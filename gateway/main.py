"""Zero-trust gateway: the Policy Enforcement Point (PEP) between the agent and its MCP tools.

Every tool call is: bound to the caller's identity -> counted -> decided by the PDP (OPA)
-> allowed / denied / parked for human approval -> audited. Deny by default, fail closed.
"""
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from gateway import dlp
from gateway.audit import AuditLog
from gateway.context import PII_SOURCES, ContextTracker
from gateway.pdp import PdpClient
from tools.paths import VAR_DIR
from tools.registry import BOUND_ARGS, McpPool, agent_visible_tools

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")


class Subject(BaseModel):
    agent_id: str
    on_behalf_of: str
    role: str


class ToolCall(BaseModel):
    session_id: str
    subject: Subject
    tool: str
    args: dict = Field(default_factory=dict)


class FinalOutput(BaseModel):
    session_id: str
    subject: Subject
    text: str


class ApprovalDecision(BaseModel):
    approve: bool
    approver: str


def bind_args(call: ToolCall) -> dict:
    """Overwrite identity-bound arguments with values from the subject (e.g. which mailbox to read)."""
    args = dict(call.args)
    for arg, field in BOUND_ARGS.get(call.tool, {}).items():
        args[arg] = getattr(call.subject, field)
    return args


def pdp_view(tool: str, args: dict) -> dict:
    """Data-minimised view of the arguments: the PDP needs the recipient, not the email body."""
    if tool == "send_email":
        return {"to": str(args.get("to", "")).strip().lower(), "body_len": len(str(args.get("body", "")))}
    if tool == "query_customer":
        return {"customer_id": args.get("customer_id")}
    return {k: v for k, v in args.items() if isinstance(v, (str, int, float, bool))}


@asynccontextmanager
async def lifespan(app: FastAPI):
    VAR_DIR.mkdir(parents=True, exist_ok=True)
    app.state.tracker = ContextTracker(VAR_DIR / "context.db")
    app.state.audit = AuditLog(VAR_DIR / "audit.jsonl")
    app.state.pdp = PdpClient(OPA_URL)
    app.state.output_pdp = PdpClient(OPA_URL, "agent/output", valid_results={"allow", "redact"},
                                     fail_result="redact")
    app.state.pending = {}
    async with McpPool() as pool:
        app.state.pool = pool
        yield
    await app.state.pdp.aclose()
    await app.state.output_pdp.aclose()


app = FastAPI(title="Zero-Trust Agent Gateway (PEP)", lifespan=lifespan)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "opa_url": OPA_URL}


@app.get("/v1/tools")
async def list_tools():
    return {"tools": agent_visible_tools(app.state.pool.tools)}


async def _execute(call: ToolCall, args: dict, decision: dict) -> dict:
    s = app.state
    result = await s.pool.call(call.tool, args)
    if call.tool in PII_SOURCES:
        s.tracker.add_fingerprints(call.session_id, dlp.fingerprints(result))
    ctx = s.tracker.record_result(call.session_id, call.tool)
    s.audit.write(event="executed", session_id=call.session_id, subject=call.subject.model_dump(),
                  tool=call.tool, args=args, context=ctx, decision="executed",
                  reason=decision["reasons"], policy_version=decision["policy_version"])
    return {"status": "ok", "result": result, "reasons": decision["reasons"]}


def _decision_input(call: ToolCall, args: dict, ctx: dict) -> dict:
    return {"subject": call.subject.model_dump(), "action": {"tool": call.tool, "args": pdp_view(call.tool, args)},
            "context": ctx}


@app.post("/v1/tools/call")
async def call_tool(call: ToolCall):
    s = app.state
    args = bind_args(call)
    ctx = s.tracker.register_call(call.session_id)
    decision = await s.pdp.decide(_decision_input(call, args, ctx))
    if decision["result"] == "allow" and not s.pool.has_tool(call.tool):
        decision = {**decision, "result": "deny", "reasons": ["R1: unknown tool"]}

    entry = s.audit.write(event="decision", session_id=call.session_id, subject=call.subject.model_dump(),
                          tool=call.tool, args=args, context=ctx, decision=decision["result"],
                          reason=decision["reasons"], policy_version=decision["policy_version"])

    if decision["result"] == "allow":
        return await _execute(call, args, decision)
    if decision["result"] == "require_approval":
        approval_id = uuid.uuid4().hex[:12]
        s.pending[approval_id] = (call, args)
        return {"status": "pending_approval", "approval_id": approval_id, "reasons": decision["reasons"],
                "audit_hash": entry["hash"]}
    return {"status": "denied", "reasons": decision["reasons"], "audit_hash": entry["hash"]}


@app.post("/v1/approvals/{approval_id}")
async def resolve_approval(approval_id: str, body: ApprovalDecision):
    s = app.state
    if approval_id not in s.pending:
        raise HTTPException(404, "unknown or already resolved approval")
    call, args = s.pending.pop(approval_id)

    # Re-check at approval time: the session may have changed while the request waited,
    # and a human approval must never override a hard deny.
    ctx = s.tracker.get(call.session_id)
    decision = await s.pdp.decide(_decision_input(call, args, ctx))
    if decision["result"] == "deny":
        verdict, reasons = "denied", decision["reasons"]
    elif body.approve:
        verdict, reasons = "approved", decision["reasons"]
    else:
        verdict, reasons = "rejected", ["rejected by approver"]

    s.audit.write(event="approval", session_id=call.session_id, subject=call.subject.model_dump(),
                  tool=call.tool, args=args, context=ctx, decision=verdict, reason=reasons,
                  policy_version=decision["policy_version"], approver=body.approver, approval_id=approval_id)

    if verdict != "approved":
        return {"status": verdict, "reasons": reasons}
    return await _execute(call, args, decision)


@app.post("/v1/output")
async def check_output(out: FinalOutput):
    """Output-side DLP (R7): the agent's final answer passes the gateway before it reaches the user.

    PII this session obtained from tools is matched by fingerprint; the PDP decides whether to redact.
    If the PDP cannot be reached, matches are redacted (fail closed).
    """
    s = app.state
    ctx = s.tracker.get(out.session_id)
    spans = dlp.scan(out.text, s.tracker.fingerprints(out.session_id))
    fields = sorted({f for _, _, f in spans})
    decision = await s.output_pdp.decide({"subject": out.subject.model_dump(), "context": ctx,
                                          "output": {"pii_fields": fields, "length": len(out.text)}})
    text = dlp.redact(out.text, spans) if decision["result"] != "allow" else out.text
    s.audit.write(event="output", session_id=out.session_id, subject=out.subject.model_dump(),
                  tool="final_output", args={"text": out.text}, context=ctx, decision=decision["result"],
                  reason=decision["reasons"], policy_version=decision["policy_version"],
                  pii_fields=fields, redactions=len(spans) if text != out.text else 0)
    return {"status": decision["result"], "text": text, "pii_fields": fields, "reasons": decision["reasons"]}

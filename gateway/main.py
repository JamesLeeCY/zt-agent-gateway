"""Zero-trust gateway: the Policy Enforcement Point (PEP) between the agent and its MCP tools.

Every tool call is: bound to the caller's identity -> counted -> decided by the PDP (OPA)
-> allowed / denied / parked for human approval -> audited. Deny by default, fail closed.
"""
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from gateway import dlp, semantic
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


class SessionStart(BaseModel):
    session_id: str
    subject: Subject
    request: str  # the user's own words; tool output never goes here


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
    app.state.output_pdp = PdpClient(OPA_URL, "agent/output", valid_results={"allow", "redact", "withhold"},
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


@app.post("/v1/sessions")
async def start_session(start: SessionStart):
    """Register the user's request before the first tool call. The addresses written in it become
    user_named_recipients (R3 sends those to approval instead of denying). Write-once."""
    s = app.state
    ctx = s.tracker.start(start.session_id, start.request)
    if ctx is None:
        raise HTTPException(409, "session already started or already has tool calls")
    s.audit.write(event="session", session_id=start.session_id, subject=start.subject.model_dump(),
                  tool="-", args={"request": start.request}, context=ctx, decision="started", reason=[],
                  policy_version="-", user_named_recipients=len(ctx["user_named_recipients"]))
    return {"status": "started", "user_named_recipients": ctx["user_named_recipients"]}


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


def _review(call: ToolCall, args: dict, ctx: dict, decision: dict) -> dict:
    """What the human approver needs to see to avoid rubber-stamping: why it was flagged, who the
    recipient really is, and whether this session's PII is in what is about to leave."""
    body = " ".join(str(args.get(k, "")) for k in ("subject", "body"))
    fields = sorted({f for _, _, f, _ in dlp.scan(body, app.state.tracker.fingerprints(call.session_id))})
    warnings = []
    if decision.get("recipient_class") in {"external", "malformed"}:
        warnings.append("收件人在行外")
    elif decision.get("recipient_class") == "internal_domain_unlisted":
        warnings.append("收件人雖在行內網域，但不在通訊錄（可能是轉寄或共用信箱）")
    if ctx.get("tainted"):
        warnings.append("這個 session 讀過外部來信，內容可能受操控")
    if fields:
        warnings.append(f"信件內容含本 session 查到的個資：{', '.join(fields)}")
    return {"tool": call.tool, "recipient": args.get("to"), "recipient_class": decision.get("recipient_class"),
            "tainted": ctx.get("tainted"), "pii_accessed": ctx.get("pii_accessed"), "body_pii_fields": fields,
            "rules": decision["reasons"], "warnings": warnings}


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
                          reason=decision["reasons"], policy_version=decision["policy_version"],
                          recipient_class=decision.get("recipient_class"))

    if decision["result"] == "allow":
        return await _execute(call, args, decision)
    if decision["result"] == "require_approval":
        approval_id = uuid.uuid4().hex[:12]
        s.pending[approval_id] = (call, args)
        return {"status": "pending_approval", "approval_id": approval_id, "reasons": decision["reasons"],
                "review": _review(call, args, ctx, decision), "audit_hash": entry["hash"]}
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


WITHHELD = ("[WITHHELD] 這份草稿經安全檢查判定可能含有客戶個資，已由安全閘道攔下。"
            "請理專直接在客戶系統中查看資料後自行撰寫回覆。")


@app.post("/v1/output")
async def check_output(out: FinalOutput):
    """Output-side DLP: the agent's final answer passes the gateway before it reaches the user.

    Layer 1 (R7, deterministic): PII this session obtained from tools is matched by fingerprint and redacted.
    Layer 2 (R8, semantic, optional): a local model decodes identifiers from the redacted text (numbers read
    out as words, other languages, digit-by-digit descriptions...) and the candidates are checked against
    the same fingerprints; a confirmed match withholds the whole draft. If the PDP cannot be reached, matches are redacted (fail closed); if the classifier
    cannot be reached for a tainted session that accessed PII, the draft is withheld (fail closed).
    """
    s = app.state
    ctx = s.tracker.get(out.session_id)
    fps = s.tracker.fingerprints(out.session_id)
    spans = dlp.scan(out.text, fps)
    fields = sorted({f for _, _, f, _ in spans})
    kinds = sorted({k for _, _, _, k in spans})
    redacted = dlp.redact(out.text, spans)

    if not semantic.enabled():
        sem = {"status": "disabled"}
    elif ctx["tainted"] and ctx["pii_accessed"]:
        sem = await semantic.check(redacted, fps)
    else:
        sem = {"status": "skipped"}  # nothing to protect, or R7/R8 would allow anyway
    sem_view = {k: sem[k] for k in ("status", "discloses", "fields", "candidates") if k in sem}  # counts, no text

    decision = await s.output_pdp.decide({"subject": out.subject.model_dump(), "context": ctx,
                                          "output": {"pii_fields": fields, "length": len(out.text),
                                                     "semantic": sem_view}})
    if decision["result"] == "withhold":
        text = WITHHELD
    elif decision["result"] == "allow":
        text = out.text
    else:
        text = redacted
    s.audit.write(event="output", session_id=out.session_id, subject=out.subject.model_dump(),
                  tool="final_output", args={"text": out.text}, context=ctx, decision=decision["result"],
                  reason=decision["reasons"], policy_version=decision["policy_version"],
                  pii_fields=fields, match_kinds=kinds, redactions=len(spans) if text == redacted != out.text else 0,
                  semantic={**sem_view, "model": sem.get("model"), "latency_ms": sem.get("latency_ms"),
                            "error": sem.get("error")})
    return {"status": decision["result"], "text": text, "pii_fields": fields, "match_kinds": kinds,
            "semantic": sem_view, "reasons": decision["reasons"]}

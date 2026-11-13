"""Replay every user task's reference solution (AgentDojo ground truth) through the gateway policy.

  bench/.venv/Scripts/python -m bench.agentdojo.replay_ground_truth [--suite banking] [--opa-url http://localhost:8182]

This takes the model out of the measurement. It shows which tasks a perfect agent could not finish
because the policy denies a call, or sends a call to approval, on the correct path. It also checks
whether the recipients the gateway stops were written in the user's own request.
"""
import argparse
import re

from agentdojo.task_suite.load_suites import get_suite

from bench.agentdojo.gateway_defense import GatewayToolsExecutor, initial_context

EGRESS = {"send_email": ["recipients", "cc", "bcc"], "share_file": ["email"],
          "create_calendar_event": ["participants"], "add_calendar_event_participants": ["participants"]}


def recipients(call) -> list[str]:
    out = []
    for arg in EGRESS.get(call.function, []):
        v = call.args.get(arg) or []
        out += [v] if isinstance(v, str) else list(v)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--opa-url", default="http://localhost:8182")
    p.add_argument("--version", default="v1.2.2")
    p.add_argument("--suite", choices=["workspace", "banking", "slack", "travel"], default="workspace")
    a = p.parse_args()
    suite = get_suite(a.version, a.suite)
    gw = GatewayToolsExecutor(a.opa_url, suite=a.suite)
    env = suite.load_and_inject_default_environment({})
    counts = {"deny": [], "require_approval": []}
    named = {"deny": 0, "require_approval": 0, "total": {"deny": 0, "require_approval": 0}}
    for tid, task in sorted(suite.user_tasks.items(), key=lambda kv: int(kv[0].rsplit("_", 1)[1])):
        ctx = initial_context(task.PROMPT)
        worst, notes = "allow", []
        for call in task.ground_truth(env.model_copy(deep=True)):
            ctx["call_count"] += 1
            d = gw.decide(call.function, dict(call.args), ctx)
            if d["result"] != "allow":
                rec = d.get("recipients") or recipients(call)
                in_prompt = bool(rec) and all(re.search(re.escape(r), task.PROMPT, re.I) for r in rec)
                named["total"][d["result"]] += 1
                named[d["result"]] += in_prompt
                notes.append(f"{call.function}{rec or ''} {d['result']} {d['reasons'][0].split(':')[0]}"
                             f"{' (named by user)' if in_prompt else ''}")
                if worst != "deny":
                    worst = d["result"]
            ctx["tainted"] |= call.function in gw.untrusted
            ctx["pii_accessed"] |= call.function in gw.pii
        if worst != "allow":
            counts[worst].append(tid)
            print(f"{tid:13} {worst:16} " + "; ".join(notes))
    n = len(suite.user_tasks)
    print(f"\n{n} tasks: {n - len(counts['deny']) - len(counts['require_approval'])} pass untouched, "
          f"{len(counts['require_approval'])} need an approval, {len(counts['deny'])} are denied")
    for k in ("deny", "require_approval"):
        print(f"{k} calls whose recipients all appear in the user's request: {named[k]}/{named['total'][k]}")


if __name__ == "__main__":
    main()

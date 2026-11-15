"""Ask the current policy again about every call a past gateway run let through. No model, no new run.

  bench/.venv/Scripts/python -m bench.agentdojo.recheck_run --run local-qwen2.5-7b-16k-gateway-approve \
      --suite slack [--attack important_instructions_no_model_name] [--opa-url http://localhost:8182]

Reads the run's AgentDojo traces (logs/<run>/<suite>/<user task>/<attack>/<injection task>.json), rebuilds
the gateway context call by call exactly as GatewayToolsExecutor does, and reports the calls that ran
then but the policy now denies (or, with --approval reject, also sends to approval).

What this can and cannot say. A newly refused call that the attack goal depends on (opening the attacker's
link, sending the phishing link) means the attack cannot succeed that way under the new policy: the model
may retry, but the same call is refused again. For the user task it is only a warning: the model would have
seen a refusal and might have found another way, or failed, so a utility number needs a new run.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

from bench.agentdojo.gateway_defense import GatewayToolsExecutor, initial_context, links_in

HERE = Path(__file__).parent


def text(content) -> str:
    return "".join(b.get("content") or "" for b in content or [] if isinstance(b, dict))


def recheck(gw: GatewayToolsExecutor, trace: dict, refuse_approval: bool) -> list[str]:
    msgs = trace["messages"]
    ctx = initial_context(text(next(m for m in msgs if m["role"] == "user")["content"]))
    refused = []
    for m in msgs:
        if m["role"] != "tool" or m.get("error") is not None:
            continue  # only calls that really ran
        call = m["tool_call"]
        ctx["call_count"] += 1
        d = gw.decide(call["function"], dict(call["args"]), ctx)
        if d["result"] == "deny" or (refuse_approval and d["result"] == "require_approval"):
            refused.append(f"{call['function']}[{','.join(sorted(r.split(':')[0] for r in d['reasons']))}]")
        ctx["tainted"] |= call["function"] in gw.untrusted
        ctx["pii_accessed"] |= call["function"] in gw.pii
        ctx["links"] = ctx["links"] + links_in(call["function"], text(m["content"]))
    return refused


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run", required=True, help="log directory name, e.g. local-qwen2.5-7b-16k-gateway-approve")
    p.add_argument("--suite", default="slack")
    p.add_argument("--attack", default="important_instructions_no_model_name")
    p.add_argument("--approval", choices=["approve", "reject"], default="approve")
    p.add_argument("--opa-url", default="http://localhost:8182")
    a = p.parse_args()
    gw = GatewayToolsExecutor(a.opa_url, suite=a.suite)
    pattern = "*/none/none.json" if a.attack == "none" else f"*/{a.attack}/injection_task_*.json"  # none: benign
    traces = sorted((HERE / "logs" / a.run / a.suite).glob(pattern))
    hit_attack, hit_utility, by_inj = Counter(), Counter(), Counter()
    for f in traces:
        t = json.loads(f.read_text(encoding="utf-8"))
        refused = recheck(gw, t, a.approval == "reject")
        iid = t["injection_task_id"]
        if t["security"] and a.attack != "none":  # benign traces carry no attack verdict worth counting
            by_inj[iid] += 1
            hit_attack[(iid, refused[0] if refused else "still allowed")] += 1
        if t["utility"] and refused:
            hit_utility[refused[0]] += 1
    print(f"{a.run} {a.suite}: {len(traces)} traces, AgentDojo attack verdict true in {sum(by_inj.values())}")
    for (iid, first), n in sorted(hit_attack.items()):
        print(f"  {iid}: {n} x, first call the current policy refuses: {first}")
    print(f"utility true and now some call refused: {sum(hit_utility.values())} "
          + ", ".join(f"{k} x{n}" for k, n in hit_utility.most_common()))


if __name__ == "__main__":
    main()

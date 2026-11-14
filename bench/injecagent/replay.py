"""Would the gateway stop InjecAgent's attacks once the model has fallen for them? Policy only, no model.

  bench/.venv/Scripts/python -m bench.injecagent.fetch_data      # once
  bench/.venv/Scripts/python -m bench.injecagent.replay [--opa-url http://localhost:8182]

Each of InjecAgent's 1,054 test cases (17 user tools x 62 attacks; base and enhanced differ only in the
injected wording, which the gateway never sees) is replayed through the gateway policy with the running
context:

  1. the user's own call (its user tool, with the arguments InjecAgent gives), which returns the
     injection: the session is tainted from here on, and PII is accessed if that tool reads private data;
  2. the hijacked agent's calls for the attack (attacks.py): one action for direct harm (dh); for data
     stealing (ds) the read of the user's data, then GmailSendEmail to the attacker.

The user's request is InjecAgent's user instruction, so a destination counts as user-named only if the
user really wrote it. An attack counts as denied if any of its calls is denied, as needing approval if
the worst is require_approval (stopped with approval=reject; up to the approver otherwise).
"""
import argparse
import json
from ast import literal_eval
from collections import Counter, defaultdict
from pathlib import Path

from bench.agentdojo.gateway_defense import GatewayToolsExecutor, initial_context
from bench.injecagent.attacks import attack_calls

DATA = Path(__file__).parent / "data"
RANK = {"allow": 0, "require_approval": 1, "deny": 2}


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (DATA / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--opa-url", default="http://localhost:8182")
    p.add_argument("--json", help="also write every case's outcome to this file")
    a = p.parse_args()
    gw = GatewayToolsExecutor(a.opa_url, suite="injecagent")
    users = load("user_cases.jsonl")
    attacks = [("dh", c) for c in load("attacker_cases_dh.jsonl")] + [("ds", c) for c in load("attacker_cases_ds.jsonl")]

    rows = []
    for u in users:
        ctx0 = initial_context(u["User Instruction"])
        d = gw.decide(u["User Tool"], literal_eval(u["Tool Parameters"]), ctx0)
        assert d["result"] == "allow", (u["User Tool"], d)  # the user's own read must go through
        ctx0["call_count"] += 1
        ctx0["tainted"] = True
        ctx0["pii_accessed"] |= u["User Tool"] in gw.pii
        for kind, case in attacks:
            c, worst, block = dict(ctx0), "allow", None
            for tool, args in attack_calls(case):
                c["call_count"] += 1
                d = gw.decide(tool, dict(args), c)
                if RANK[d["result"]] > RANK[worst]:
                    worst = d["result"]
                if d["result"] != "allow" and block is None:
                    block = f"{tool}[{','.join(sorted(r.split(':')[0] for r in d['reasons']))}]"
                c["pii_accessed"] |= tool in gw.pii
            rows.append({"type": kind, "attack": case["Attacker Tools"][0], "attack_type": case["Attack Type"],
                         "user_tool": u["User Tool"], "user_tool_pii": u["User Tool"] in gw.pii,
                         "result": worst, "first_stop": block})

    by_attack = defaultdict(Counter)
    stop = {}
    for r in rows:
        by_attack[(r["type"], r["attack"])][r["result"]] += 1
        stop.setdefault((r["type"], r["attack"]), Counter())[r["first_stop"]] += 1
    print(f"{'type':4} {'attack (first attacker tool)':48} {'deny':>4} {'appr':>4} {'allow':>5}  first call stopped")
    for (kind, att), o in by_attack.items():
        fs = ", ".join(f"{k} x{v}" for k, v in stop[(kind, att)].most_common(2) if k)
        print(f"{kind:4} {att:48} {o['deny']:4} {o['require_approval']:4} {o['allow']:5}  {fs}")

    for kind in ("dh", "ds", None):
        sub = [r for r in rows if kind is None or r["type"] == kind]
        t = Counter(r["result"] for r in sub)
        n = len(sub)
        print(f"\n{kind or 'all'}: {n} cases  denied {t['deny']} ({t['deny'] / n:.1%})  "
              f"need approval {t['require_approval']} ({t['require_approval'] / n:.1%})  "
              f"allowed {t['allow']} ({t['allow'] / n:.1%})")
        for pii in (True, False):
            s = [r for r in sub if r["user_tool_pii"] == pii]
            if s:
                print(f"   user tool {'reads' if pii else 'no'} PII ({len(s)}): denied "
                      f"{sum(r['result'] == 'deny' for r in s) / len(s):.1%}")
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()

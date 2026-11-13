"""Compare benign (no attack) utility with and without the gateway: what does the gateway cost?

  bench/.venv/Scripts/python -m bench.agentdojo.analyze_benign [--model qwen2.5-7b-16k]
  bench/.venv/Scripts/python -m bench.agentdojo.analyze_benign --provider openai --model gpt-6-luna-scaffold [--suite banking]

A task counts as a false block when the gateway blocked at least one call in it and the task passed
without the gateway but failed with it. A task that failed with the gateway but had nothing blocked is
model noise (the same prompt can go differently), not a gateway cost.
"""
import argparse
import json
from collections import Counter
from pathlib import Path

RES = Path(__file__).parent / "results"


def load(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()] if path.exists() else []


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="qwen2.5-7b-16k", help="model part of the run name, e.g. phi4-16k-scaffold")
    p.add_argument("--provider", default="local", choices=["local", "openai"], help="run-name prefix")
    p.add_argument("--suite", default="workspace", choices=["workspace", "banking", "slack", "travel"])
    a = p.parse_args()
    pre, suf = f"{a.provider}-{a.model}", ("" if a.suite == "workspace" else f"-{a.suite}") + "-benign"
    runs = {"none": f"{pre}-none{suf}", "reject": f"{pre}-gateway-reject{suf}",
            "approve": f"{pre}-gateway-approve{suf}"}
    util = {k: {r["user_task"]: r["utility"] for r in load(RES / f"{v}.jsonl") if r["error"] is None}
            for k, v in runs.items()}
    blocks = {}
    for k in ("reject", "approve"):
        b: dict[str, list[dict]] = {}
        for d in load(RES / f"{runs[k]}.decisions.jsonl"):
            if not d["executed"]:
                b.setdefault(d["task"][0], []).append(d)
        blocks[k] = b

    tasks = sorted(set().union(*util.values()), key=lambda t: int(t.rsplit("_", 1)[1]))
    print(f"{'task':14} {'none':5} {'reject':7} {'approve':8} blocked (reject run)")
    for t in tasks:
        cells = ["-" if t not in util[k] else ("Y" if util[k][t] else ".") for k in runs]
        bl = ", ".join(f"{d['tool']}[{d['reasons'][0].split(':')[0]}]" for d in blocks["reject"].get(t, []))
        print(f"{t:14} {cells[0]:5} {cells[1]:7} {cells[2]:8} {bl}")

    print()
    for k in runs:
        n = len(util[k])
        print(f"{k:8} utility {sum(util[k].values())}/{n}")
    for k in ("reject", "approve"):
        both = [t for t in util["none"] if t in util[k]]
        false_block = [t for t in both if util["none"][t] and not util[k][t] and t in blocks[k]]
        noise_loss = [t for t in both if util["none"][t] and not util[k][t] and t not in blocks[k]]
        gain = [t for t in both if not util["none"][t] and util[k][t]]
        print(f"\n{k}: tasks with a block {len(blocks[k])}/{len(util[k])}, false blocks {len(false_block)} {false_block}")
        print(f"  lost without any block (model noise) {len(noise_loss)} {noise_loss}; gained {len(gain)} {gain}")
        rules = Counter(r.split(":")[0] for ds in blocks[k].values() for d in ds for r in d["reasons"])
        tools = Counter(d["tool"] for ds in blocks[k].values() for d in ds)
        print(f"  blocked calls by rule {dict(rules)}; by tool {dict(tools)}")

    usage = Counter()  # OpenAI runs record tokens per pair (rows with errors included: they were billed too)
    for v in runs.values():
        for r in load(RES / f"{v}.jsonl"):
            usage.update(r.get("usage") or {})
    if usage:
        print(f"\ntokens over the three runs: {dict(usage)}")


if __name__ == "__main__":
    main()

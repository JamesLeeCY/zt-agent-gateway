"""Live progress bars for benchmark runs that write their output to log files.

  bench/.venv/Scripts/python -m bench.agentdojo.progress bench/agentdojo/results/luna_attack_*.log
  bench/.venv/Scripts/python -m bench.agentdojo.progress --once bench/agentdojo/results/luna_pilot_*.log

One bar per log. The run name and size come from run.py's first line ("<run>: N pairs to run (D already
done)"); the counts come from results/<run>.jsonl, so pairs finished before a resume are included.
Refreshes every few seconds and exits when every run is complete. Closing it (Ctrl+C) does not stop the
runs: they are separate processes.
"""
import argparse
import glob
import os
import json
import re
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.progress_bar import ProgressBar
from rich.table import Table

RES = Path(__file__).parent / "results"
HEADER = re.compile(r"^(\S+): (\d+) pairs to run \((\d+) already done\)", re.M)
STALE_MIN = 15


def status(log: Path) -> dict:
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    m = ([*HEADER.finditer(text)] or [None])[-1]  # a log can hold several runs one after another
    if not m:
        err = Path(f"{log}.err")
        problem = err.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-1:] if err.exists() else []
        return {"name": log.stem, "total": 0, "starting": True, "problem": problem[0] if problem else ""}
    run, todo, already = m.group(1), int(m.group(2)), int(m.group(3))
    rows = []
    res = RES / f"{run}.jsonl"
    if res.exists():
        rows = [json.loads(x) for x in res.read_text(encoding="utf-8").splitlines() if x.strip()]
    ok = [r for r in rows if r["error"] is None]
    seen = {(r["user_task"], r["injection_task"]) for r in ok}
    # seconds per pair in this session, for the time estimate
    secs = [float(s) for s in re.findall(r"^\[\d+/\d+\].* (\d+(?:\.\d+)?)s", text, re.M)]
    return {"name": run, "total": todo + already, "done": len(seen),
            "errors": sum(1 for r in rows if r["error"] is not None and (r["user_task"], r["injection_task"]) not in seen),
            "attack": sum(1 for r in ok if r.get("attack_succeeded")),
            "utility": sum(1 for r in ok if r.get("utility")),
            "has_attack": any(r.get("injection_task") for r in ok),
            "avg": sum(secs[-20:]) / len(secs[-20:]) if secs else None,
            "idle_min": (time.time() - log.stat().st_mtime) / 60}


def fmt_eta(s: dict) -> str:
    left = s["total"] - s["done"]
    if left <= 0:
        return "[green]done[/]"
    if s["idle_min"] > STALE_MIN:
        return f"[red]no output for {s['idle_min']:.0f} min[/]"
    if not s["avg"]:
        return "…"
    m = left * s["avg"] / 60
    return f"~{m / 60:.1f} h" if m >= 90 else f"~{m:.0f} min"


def render(paths: list[Path]) -> tuple[Table, bool]:
    stats = [status(p) for p in paths]
    names = [s["name"] for s in stats]
    common = os.path.commonprefix(names) if len(names) > 1 else ""
    common = common[:common.rfind("-") + 1]  # cut at a word boundary
    t = Table(title=common.rstrip("-") or None, title_justify="left", box=None, padding=(0, 1))
    for col, kw in [("run", {"overflow": "ellipsis", "max_width": 40}), ("progress", {}), ("done", {"justify": "right"}),
                    ("utility", {"justify": "right"}), ("attack ok", {"justify": "right"}),
                    ("errors", {"justify": "right"}), ("left", {"justify": "right"})]:
        t.add_column(col, **kw)
    all_done = bool(paths)
    for s in stats:
        label = s["name"][len(common):] or s["name"]
        if s.get("starting"):
            all_done = False
            t.add_row(label, "starting…", "", "", "", "", s["problem"][:40])
            continue
        n, d = s["total"], s["done"]
        all_done &= d >= n
        pct = lambda k: f"{s[k]} ({s[k] / d:.0%})" if d else "-"  # noqa: E731
        t.add_row(label, ProgressBar(total=max(n, 1), completed=d, width=24), f"{d}/{n}", pct("utility"),
                  pct("attack") if s["has_attack"] else "-",
                  f"[red]{s['errors']}[/]" if s["errors"] else "0", fmt_eta(s))
    return t, all_done


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("logs", nargs="+", help="log files or glob patterns")
    p.add_argument("--once", action="store_true", help="print the table once and exit")
    p.add_argument("--every", type=float, default=5, help="refresh interval in seconds")
    a = p.parse_args()
    pattern_paths = lambda: sorted({Path(f) for g in a.logs for f in (glob.glob(g) or [g])})  # noqa: E731
    console = Console()
    if a.once:
        console.print(render(pattern_paths())[0])
        return
    try:
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                table, done = render(pattern_paths())
                live.update(table)
                if done:
                    break
                time.sleep(a.every)
        console.print("[green]All runs complete.[/]")
    except KeyboardInterrupt:
        console.print("Progress view closed; the runs keep going in the background.")


if __name__ == "__main__":
    main()

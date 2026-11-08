"""Run the AgentDojo workspace suite with and without the zero-trust gateway.

  bench/.venv/Scripts/python -m bench.agentdojo.run --defense none --benign
  bench/.venv/Scripts/python -m bench.agentdojo.run --defense gateway --approval reject \
      --user-tasks user_task_0 user_task_1 --injection-tasks injection_task_0

Model: Ollama's OpenAI-compatible API (default qwen2.5-7b-16k = qwen2.5:7b-instruct with a 16k context).
Every (user task, injection task) pair is appended to results/<run name>.jsonl as soon as it finishes, so a
run can be stopped and resumed; finished pairs are skipped. AgentDojo's own per-task traces go to logs/.
Needs OPA serving bench/agentdojo/policy on --opa-url for --defense gateway. On Windows set PYTHONUTF8=1
(AgentDojo reads its YAML files with the locale encoding).
"""
import argparse
import json
import sys
import time
from pathlib import Path

import openai
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite

from bench.agentdojo.gateway_defense import GatewayToolsExecutor

HERE = Path(__file__).parent


def build_pipeline(model: str, defense: str, approval: str, opa_url: str, ollama_url: str, gw_log: Path,
                   no_think: bool = False):
    llm = OpenAILLM(openai.OpenAI(base_url=f"{ollama_url.rstrip('/')}/v1", api_key="ollama"), model, temperature=0.0)
    executor = (GatewayToolsExecutor(opa_url, approval, gw_log) if defense == "gateway" else ToolsExecutor())
    system = load_system_message(None) + (" /no_think" if no_think else "")  # Qwen3 soft switch: no reasoning
    pipeline = AgentPipeline([SystemMessage(system), InitQuery(), llm,
                              ToolsExecutionLoop([executor, llm])])
    # "local" in the name lets AgentDojo's attacks address the model; the suffix keeps logs apart.
    pipeline.name = f"local-{model.replace(':', '_')}{'-nothink' if no_think else ''}-{defense}" + (f"-{approval}" if defense == "gateway" else "")
    return pipeline


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--defense", choices=["none", "gateway"], required=True)
    p.add_argument("--approval", choices=["reject", "approve"], default="reject")
    p.add_argument("--benign", action="store_true", help="run user tasks without injections (utility only)")
    p.add_argument("--injection-as-user", action="store_true",
                   help="run each injection task as a plain user request (attack capability ceiling)")
    p.add_argument("--user-tasks", nargs="*")
    p.add_argument("--injection-tasks", nargs="*")
    p.add_argument("--model", default="qwen2.5-7b-16k")
    p.add_argument("--attack", default="important_instructions_no_model_name")
    p.add_argument("--no-think", action="store_true", help="append /no_think to the system prompt (Qwen3)")
    p.add_argument("--version", default="v1.2.2")
    p.add_argument("--opa-url", default="http://localhost:8182")
    p.add_argument("--ollama-url", default="http://localhost:11434")
    a = p.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    suite = get_suite(a.version, "workspace")
    run_name = None
    (HERE / "results").mkdir(exist_ok=True)
    pipeline = build_pipeline(a.model, a.defense, a.approval, a.opa_url, a.ollama_url, None, a.no_think)
    run_name = pipeline.name + ("-injection-as-user" if a.injection_as_user else "-benign" if a.benign else f"-{a.attack}")
    executor = pipeline.elements[-1].elements[0]
    if isinstance(executor, GatewayToolsExecutor):  # one decision log per run, tagged with the task pair
        executor.log_path = HERE / "results" / f"{run_name}.decisions.jsonl"
    out = HERE / "results" / f"{run_name}.jsonl"
    done = set()
    if out.exists():
        done = {(r["user_task"], r["injection_task"]) for r in map(json.loads, out.read_text().splitlines())
                if r["error"] is None}  # errored pairs are retried

    user_tasks = a.user_tasks or list(suite.user_tasks)
    if a.injection_as_user:  # can the model carry out each attack goal when the user asks for it directly?
        user_tasks, a.benign = a.user_tasks or list(suite.injection_tasks), True
    inj_tasks = [None] if a.benign else (a.injection_tasks or list(suite.injection_tasks))
    todo = [(u, i) for u in user_tasks for i in inj_tasks if (u, i) not in done]
    print(f"{run_name}: {len(todo)} pairs to run ({len(done)} already done)", flush=True)
    attack = None if a.benign else load_attack(a.attack, suite, pipeline)

    with OutputLogger(str(HERE / "logs"), live=None):
        for n, (u, i) in enumerate(todo, 1):
            t0 = time.time()
            if isinstance(executor, GatewayToolsExecutor):
                executor.task = (u, i)
            try:
                # Called per pair (not benchmark_suite_*), which would re-run every injection task as a
                # user task on each call; that check is a separate run (--injection-as-user).
                task = suite.get_injection_task_by_id(u) if u.startswith("injection_task") else                     suite.get_user_task_by_id(u)
                if i is None:
                    utility, _ = run_task_without_injection_tasks(suite, pipeline, task, HERE / "logs", True,
                                                                  a.version)
                    security = None
                else:
                    ut, sec = run_task_with_injection_tasks(suite, pipeline, task, attack, HERE / "logs", True,
                                                            [i], a.version)
                    utility, security = ut[(u, i)], sec[(u, i)]
                err = None
            except Exception as exc:  # noqa: BLE001 - one broken pair should not end the run
                utility = security = None
                err = f"{type(exc).__name__}: {exc}"[:300]
            row = {"run": run_name, "user_task": u, "injection_task": i, "utility": utility,
                   "attack_succeeded": security, "seconds": round(time.time() - t0, 1), "error": err}
            with out.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            print(f"[{n}/{len(todo)}] {u} {i or '-'} utility={utility} attack={security} "
                  f"{row['seconds']}s{' ERROR ' + err if err else ''}", flush=True)


if __name__ == "__main__":
    main()

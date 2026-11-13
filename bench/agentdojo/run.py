"""Run an AgentDojo suite (default workspace; --suite banking|slack|travel) with and without the gateway.

  bench/.venv/Scripts/python -m bench.agentdojo.run --defense none --benign
  bench/.venv/Scripts/python -m bench.agentdojo.run --defense gateway --approval reject \
      --user-tasks user_task_0 user_task_1 --injection-tasks injection_task_0

Model: Ollama's OpenAI-compatible API (default qwen2.5-7b-16k = qwen2.5:7b-instruct with a 16k context), or
the OpenAI API with --provider openai (reads OPENAI_API_KEY; --flex for Flex processing at Batch prices):
  bench/.venv/Scripts/python -m bench.agentdojo.run --provider openai --model gpt-6-luna --flex --defense none --benign
Every (user task, injection task) pair is appended to results/<run name>.jsonl as soon as it finishes, so a
run can be stopped and resumed; finished pairs are skipped. AgentDojo's own per-task traces go to logs/.
Needs OPA serving bench/agentdojo/policy on --opa-url for --defense gateway. On Windows set PYTHONUTF8=1
(AgentDojo reads its YAML files with the locale encoding).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx
import openai
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks, run_task_without_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite

from bench.agentdojo.agent_scaffold import WORK_RULES, Nudge, TolerantLocalLLM
from bench.agentdojo.gateway_defense import GatewayToolsExecutor
from bench.agentdojo.openai_flex import FlexOpenAILLM

HERE = Path(__file__).parent


def build_pipeline(model: str, defense: str, approval: str, opa_url: str, ollama_url: str, gw_log: Path,
                   no_think: bool = False, scaffold: bool = False, prompt_tools: bool = False,
                   provider: str = "ollama", flex: bool = False,
                   reasoning_effort: str | None = None, suite: str = "workspace"):
    if provider == "openai":
        # Flex requests can be slow; the SDK default timeout (10 min) is raised as OpenAI's Flex guide suggests.
        llm = FlexOpenAILLM(openai.OpenAI(timeout=900.0, max_retries=2), model, flex=flex,
                            reasoning_effort=reasoning_effort)
        MODEL_NAMES.setdefault(model, model)  # lets AgentDojo's attacks find the model in the pipeline name
    else:
        client = openai.OpenAI(base_url=f"{ollama_url.rstrip('/')}/v1", api_key="ollama")
        # prompt_tools: for models without native tool calling (e.g. phi4), the tools are described in the
        # system prompt and calls are parsed from <function=...> tags (AgentDojo's LocalLLM).
        llm = TolerantLocalLLM(client, model, temperature=0.0) if prompt_tools else OpenAILLM(client, model, temperature=0.0)
    executor = (GatewayToolsExecutor(opa_url, approval, gw_log, suite) if defense == "gateway" else ToolsExecutor())
    system = load_system_message(None) + (WORK_RULES if scaffold else "") + (" /no_think" if no_think else "")
    loop = ToolsExecutionLoop([executor, llm])
    pipeline = AgentPipeline([SystemMessage(system), InitQuery(), llm, loop, *([Nudge(llm, loop)] if scaffold else [])])
    # "local" in the name lets AgentDojo's attacks address the model; the suffix keeps logs apart.
    pipeline.name = f"{'local' if provider == 'ollama' else 'openai'}-{model.replace(':', '_')}{'-nothink' if no_think else ''}{'-scaffold' if scaffold else ''}-{defense}" + (f"-{approval}" if defense == "gateway" else "")
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
    p.add_argument("--suite", choices=["workspace", "banking", "slack", "travel"], default="workspace")
    p.add_argument("--opa-url", default="http://localhost:8182")
    p.add_argument("--ollama-url", default="http://localhost:11434")
    p.add_argument("--scaffold", action="store_true",
                   help="stricter work rules in the system prompt, and nudge the agent when it gives up early")
    p.add_argument("--prompt-tools", action="store_true",
                   help="describe tools in the prompt instead of native tool calling (models without tool support)")
    p.add_argument("--provider", choices=["ollama", "openai"], default="ollama")
    p.add_argument("--flex", action="store_true",
                   help="OpenAI Flex processing: Batch prices, slower responses (--provider openai only)")
    p.add_argument("--reasoning-effort", choices=["none", "minimal", "low", "medium", "high", "xhigh"],
                   help="OpenAI reasoning effort (default: the model's own default)")
    p.add_argument("--tag", default="", help="suffix for the results file, e.g. the policy version")
    a = p.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if a.flex and a.provider != "openai":
        sys.exit("--flex needs --provider openai")
    if a.provider == "openai" and not os.environ.get("OPENAI_API_KEY"):
        sys.exit("Set OPENAI_API_KEY in your shell first (the key is never passed on the command line)")

    if a.defense == "gateway":  # without a PDP every call is denied (fail closed): that run would be meaningless
        try:
            pkg = "workspace" if a.suite == "workspace" else "gateway"
            v = httpx.post(f"{a.opa_url.rstrip('/')}/v1/data/agentdojo/{pkg}/policy_version", json={"input": {}},
                           timeout=5).raise_for_status().json()["result"]
        except Exception as exc:  # noqa: BLE001
            sys.exit(f"OPA is not reachable at {a.opa_url} ({type(exc).__name__}); start it before a gateway run")
        print(f"policy_version {v}", flush=True)
    suite = get_suite(a.version, a.suite)
    run_name = None
    (HERE / "results").mkdir(exist_ok=True)
    pipeline = build_pipeline(a.model, a.defense, a.approval, a.opa_url, a.ollama_url, None, a.no_think, a.scaffold, a.prompt_tools,
                              a.provider, a.flex, a.reasoning_effort, a.suite)
    # workspace runs keep their original names (no suite part), so old results files still resume
    run_name = pipeline.name + ("" if a.suite == "workspace" else f"-{a.suite}") + ("-injection-as-user" if a.injection_as_user else "-benign" if a.benign else f"-{a.attack}") + (f"-{a.tag}" if a.tag else "")
    llm = pipeline.elements[2]
    executor = next(e for e in pipeline.elements if isinstance(e, ToolsExecutionLoop)).elements[0]
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
            if isinstance(llm, FlexOpenAILLM):  # tokens and billed tier per pair, for checking the cost
                row["usage"] = dict(llm.usage)
                llm.usage.clear()
            with out.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            print(f"[{n}/{len(todo)}] {u} {i or '-'} utility={utility} attack={security} "
                  f"{row['seconds']}s{' ' + str(row['usage']) if row.get('usage') else ''}"
                  f"{' ERROR ' + err if err else ''}", flush=True)


if __name__ == "__main__":
    main()

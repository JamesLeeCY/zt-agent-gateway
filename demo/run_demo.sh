#!/usr/bin/env bash
# Same malicious email, twice: agent direct to tools (left) vs through the gateway (right).
# For split-screen recording run `python -m demo.run_demo direct` and `... gateway` in two panes.
set -euo pipefail
cd "$(dirname "$0")/.."
LLM="${ZT_LLM:-ollama}"
curl -sf http://localhost:8000/healthz >/dev/null || { echo "gateway not running: docker compose up -d"; exit 1; }
python -m demo.run_demo attack --llm "$LLM"
python -m demo.run_demo control --llm "$LLM"

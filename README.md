# zt-agent-gateway — 企業 AI Agent 零信任控制框架（精簡版）

在 AI agent 與其工具（MCP server）之間放一個零信任閘道：每一次工具呼叫都經過**授權、情境評估與稽核**。用一個間接 prompt injection 攻擊 demo 證明控制有效：同一封惡意來信，無 gateway 時客戶個資被寄到外部，有 gateway 時被 R3 擋下，理專的正常任務照常完成。

規格：[企業 AI Agent 零信任控制框架 — 精簡版技術規格書.md](企業%20AI%20Agent%20零信任控制框架%20—%20精簡版技術規格書.md) · 威脅模型：[docs/threat_model.md](docs/threat_model.md) · 控制矩陣：[docs/control_matrix.md](docs/control_matrix.md)

## 架構（NIST SP 800-207 套用到 agent）

```
理專 ─▶ Agent (LLM tool calling) ─▶ Gateway = PEP ─┬─▶ OPA = PDP  (policy/*.rego, R1–R7)
                                      │             ├─▶ Context Tracker (tainted / pii_accessed / call_count)
                                      │             └─▶ Audit Log (JSONL, args 只存 hash, hash chain)
                                      ▼
                        MCP: read_inbox · query_customer · send_email
```

1. Agent 送出 tool call 到 Gateway（agent 不持有工具連線）。
2. Gateway 綁定身分參數（例如信箱 = `on_behalf_of`）、計數、組決策輸入。
3. OPA 回傳 `allow` / `deny` / `require_approval` + 理由；收不到決策就 deny（fail closed）。
4. allow → 轉發 MCP；require_approval → 推給理專確認，並附上觸發的規則、收件人類型（通訊錄內／行內未列名／行外）、信件是否含本 session 查到的個資（確認時重新評估，人工核准蓋不過 deny）；deny → 拒絕訊息回給 agent。
5. 工具結果回來後更新情境：讀信 → `tainted`，查個資 → `pii_accessed`（不可回復），並記下個資欄位的 HMAC 指紋（不存明文）。
6. Agent 的最終回覆也要經過 Gateway（`/v1/output`）：比對指紋（忽略大小寫、空白、標點），由 OPA 決定是否遮蔽（R7）；PDP 無回應時一律遮蔽。
7. 每一步寫入稽核日誌。

| 規則 | 條件 | 決策 |
| --- | --- | --- |
| R1 | 沒有規則放行／PDP 無回應 | deny |
| R2 | 角色不在工具允許清單 | deny |
| R3 | tainted 且 pii_accessed 且收件人不在行內通訊錄 | deny |
| R4 | tainted 後呼叫高風險工具 | require_approval |
| R5 | 收件人不在行內通訊錄（[policy/directory.rego](policy/directory.rego)；行內網域但未列名的轉寄／共用信箱也算） | require_approval |
| R6 | 單一 session 超過 20 次呼叫 | deny |
| R7 | tainted 後，agent 最終回覆含本 session 取得的個資 | redact（輸出端 DLP） |

## 快速開始

需求：Python 3.11+、Docker、（LLM 二擇一）[Ollama](https://ollama.com) + `qwen2.5:7b-instruct`，或 `ANTHROPIC_API_KEY`。

```bash
pip install -r requirements.txt
```

```bash
docker compose up -d --build
```

```bash
python -m demo.run_demo attack
```

`docker compose up` 會啟動 OPA（PDP）與 Gateway（PEP，Gateway 內部再啟動三個 MCP 工具）。Agent 在本機跑，預設連本機 Ollama。

### Demo 指令

| 指令 | 內容 |
| --- | --- |
| `python -m demo.run_demo attack` | 同一封惡意信：直連（外洩）→ 經 gateway（R3 擋下），最後印出稽核日誌 |
| `python -m demo.run_demo direct` / `gateway` | 只跑一半，用於左右分屏錄影 |
| `python -m demo.run_demo control` | 對照組：正常來信、寄給行內同事 → R4 理專確認後送出 |
| `python -m demo.run_demo accept --runs 5` | 驗收：統計 5 次有／無 gateway 的外洩次數 |
| `python -m demo.run_demo audit` | 印出完整稽核日誌並驗證 hash chain |
| `python -m demo.campaign run --per-variant 5` | 8 種注入手法（V7、V8 專攻輸出端 DLP）× 5 次 × 有／無 gateway，可中斷續跑；`--variants`、`--modes`、`--results` 可只跑部分；`report` 產生統計表 |

共用參數：`--llm ollama|anthropic|scripted`（`scripted` 是決定性的「天真 agent」，不需 LLM，CI 用）、`--approve ask|yes|no`。

也可以直接跑 agent：

```bash
python -m agent.run_agent --gateway --rm rm_042 "幫我看一下收件匣最新一封信，查一下這位客戶的資料，擬一封回覆草稿。"
```

環境變數：`OLLAMA_MODEL`（預設 `qwen2.5:7b-instruct`）、`ANTHROPIC_MODEL`、`ZT_LLM`、`ZT_GATEWAY_URL`、`OPA_URL`、`ZT_VAR_DIR`（outbox／稽核日誌／情境 DB 位置，預設 `var/`）。

寄信工具不會真的寄出，信件寫入 `var/outbox.jsonl`；所有客戶資料都是合成資料。

## 測試

```bash
docker run --rm -v "$PWD/policy:/policy:ro" openpolicyagent/opa:1.10.1-static test /policy -v
```

```bash
pytest -v
```

`opa test`：27 個案例，每條規則至少一個放行與一個拒絕（含多收件人走私、仿冒網域、未列名的行內信箱、未知角色、空輸入）。pytest：情境追蹤、稽核 hash chain、端到端（直連外洩、R3 阻擋、R4 核准／拒絕、R2、R6、身分綁定、fail closed、輸出端 DLP（含中文數字、全形、倒序）、送審資訊）；需要 OPA 的測試在 OPA 未啟動時自動略過。CI 見 [.github/workflows/ci.yml](.github/workflows/ci.yml)。

## 驗收結果

見 [docs/acceptance.md](docs/acceptance.md)。

## 目錄

```text
agent/run_agent.py        # --direct / --gateway；llm.py：Ollama / Anthropic / scripted 後端
gateway/main.py           # PEP：身分綁定、詢問 PDP、轉發、人工審核
gateway/context.py        # taint / pii / call_count（SQLite，flag 只能 0→1）
gateway/audit.py          # JSON Lines 稽核日誌 + hash chain
gateway/pdp.py            # OPA client，任何錯誤即 deny
tools/*_server.py         # 3 個 mock MCP server（FastMCP, stdio）
policy/authz.rego         # R1–R6；output.rego：R7；*_test.rego：opa test
gateway/dlp.py            # 輸出端 DLP：個資指紋、比對、遮蔽
data/                     # 合成客戶資料、正常／惡意信件
demo/                     # run_demo.py / run_demo.sh
docs/                     # 威脅模型、控制矩陣、驗收結果
```

## 後續擴充

紅隊測試集與攻擊成功率／誤擋率統計、欄位層級的資料來源追蹤（取代 session 層級 taint）、ML 行為異常分數接入 PDP、真實 IdP 與短效憑證、稽核日誌送 WORM 儲存。

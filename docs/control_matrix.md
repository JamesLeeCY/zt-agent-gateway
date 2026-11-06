# 治理控制矩陣

把技術控制翻譯成稽核與治理語言。每項控制都指到可驗證的程式碼或測試。

| 控制措施 | 實作位置 | 驗證證據 | 緩解威脅 | NIST AI RMF | ISO/IEC 42001 Annex A | 剩餘風險 | 建議負責單位 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1 角色工具允許清單 | PDP R2（[authz.rego](../policy/authz.rego) `role_tools`） | `opa test`：`test_r2_*`；pytest `test_role_without_permission_is_denied` | T2 | GOVERN、MANAGE | A.9.2 Processes for responsible use of AI systems、A.9.4 Intended use of the AI system | 角色設計過寬時仍有權限過大 | 資安部、業務單位 |
| C2 不可信輸入污染追蹤 | Context Tracker（[context.py](../gateway/context.py)） | pytest `test_flags_are_sticky_and_calls_counted` | T1 | MAP、MANAGE | A.7.5 Data provenance、A.6.2.6 AI system operation and monitoring | 未標記的輸入來源可繞過；新增工具時須同步標記 | AI 平台團隊 |
| C3 個資外部傳送阻擋 | PDP R3；收件人以通訊錄白名單判定（[directory.rego](../policy/directory.rego)），不是「行內網域即可信」 | `opa test`：`test_r3_*`（含多收件人、仿冒網域、未列名的行內信箱）；pytest `test_attack_blocked_by_r3_and_task_still_completes` | T1、T3 | MANAGE | A.9.2 Processes for responsible use of AI systems、A.6.2.6 AI system operation and monitoring | 轉述、摘要後的個資不易偵測；最終文字輸出由 C9 補上；通訊錄若誤列會轉寄到外部的信箱，R3 就不會觸發，通訊錄需由 IdP／HR 系統餵入並定期覆核 | 資安部、個資保護專責 |
| C4 高風險操作人工審核 | PDP R4、R5；Gateway approval 流程（核准時重新評估，人工核准無法覆蓋 deny；送審時附上規則理由、收件人類型、信件是否含本 session 個資） | `opa test`：`test_r4_*`、`test_r5_*`、`test_recipient_class`；pytest `test_control_group_requires_approval_then_sends`、`test_rejected_approval_sends_nothing`、`test_approval_review_flags_unlisted_mailbox_and_pii` | T1、T3 | GOVERN、MANAGE | A.9.2 Processes for responsible use of AI systems（人工監督）、A.9.3 Objectives for responsible use | 審核疲勞導致盲目核准（送審資訊降低但不能消除；可用稽核日誌量測核准率） | 業務單位主管 |
| C5 呼叫次數上限 | PDP R6 | `opa test`：`test_r6_*`；pytest `test_call_budget` | T2 | MANAGE | A.6.2.6 AI system operation and monitoring | 上限內的低頻攻擊 | AI 平台團隊 |
| C6 防竄改稽核日誌 | Audit Log（[audit.py](../gateway/audit.py)：只附加、參數只存 hash、hash chain） | pytest `test_chain_detects_tampering`、`test_audit_log_complete_chained_and_pii_free` | T1–T3（事後追蹤） | MEASURE、GOVERN | A.6.2.8 AI system recording of event logs | 日誌只存 hash，鑑識時需對照原始系統；hash chain 能偵測竄改但不能防止整檔替換，正式版需送 WORM 儲存或外部時間戳 | 內稽、資安部 |
| C7 攻擊情境測試 | [demo/run_demo.py](../demo/run_demo.py)、[demo/campaign.py](../demo/campaign.py)、CI | `python -m demo.campaign run`：12 種注入手法（含 6 種專攻輸出端 DLP）＋正常來信對照組，共 140 輪；R8 另有 24 份標註草稿的離線評估；GitHub Actions | T1 | MEASURE | A.6.2.4 AI system verification and validation | 只用單一模型（Qwen2.5-7B）、單一情境；30 輪只能把誤放率上界壓到約 10% | 紅隊／第三方測試 |
| C8 預設拒絕／失效即關閉 | PDP R1（`default decision`）＋ Gateway（PDP 無回應即 deny） | `opa test`：`test_r1_*`；pytest `test_fail_closed_when_pdp_unreachable` | T1–T3 | MANAGE | A.6.2.5 AI system deployment、A.6.2.6 AI system operation and monitoring | 可用性風險：OPA 停機時 agent 全部停擺（刻意的取捨） | AI 平台團隊、維運 |
| C9 輸出端 DLP | [gateway/dlp.py](../gateway/dlp.py)（個資 HMAC 指紋、正規化比對、遮蔽）＋ PDP R7（[output.rego](../policy/output.rego)） | `opa test`：`test_r7_*`；pytest `test_dlp.py`、`test_output_dlp_*` | T1、T3 | MANAGE | A.9.2 Processes for responsible use of AI systems、A.6.2.6 AI system operation and monitoring | 決定性比對涵蓋：完整值（大小寫、空白標點、全形、中文數字、英文數字詞、倒序）、拼湊（單段 ≥5 碼、合計還原 ≥60%）、base64／hex 編碼。仍比對不到的交給 C10；刻意允許末四碼這類遮罩寫法；未 tainted 的 session 不遮蔽（理專本來就要看資料）；agent 若繞過 gateway 直接把回覆交給使用者則無效，需在 UI 端強制走 `/v1/output` | 資安部、個資保護專責 |
| C10 輸出端語意檢查 | [gateway/semantic.py](../gateway/semantic.py)（本機小模型把識別碼還原成明碼，交回 C9 的指紋比對確認）＋ PDP R8（withhold） | `opa test`：`test_r8_*`；pytest `test_semantic.py`；離線評估 `python -m demo.semantic_eval`（見 [acceptance.md](acceptance.md)） | T1、T3 | MEASURE、MANAGE | A.6.2.6 AI system operation and monitoring、A.6.2.4 AI system verification and validation（離線評估） | 機率性：還原失敗就漏（例如中文地址、需要算術的描述）；草稿裡的注入內容可能干擾檢查用模型，所以採不同模型家族，且模型只負責還原、由指紋決定；每份 tainted 草稿多 3–10 秒（CPU）；模型無回應時攔下草稿（可用性取捨） | AI 平台團隊、資安部 |

> **ISO/IEC 42001 已細化到子條款（2026-11-06）**
> - **條款編號與標題**：ISO 原文需付費，這裡依兩份逐條列出 Annex A（38 項控制、A.2–A.10）的公開資料交叉比對，兩者對所有條號與標題一致：[Riskprofs](https://riskprofs.com/iso-42001-annex-a-controls-list/)、[Modulos](https://docs.modulos.ai/frameworks/iso-42001/annexes-a-d)。另一份 [Certpro](https://certpro.com/hub/iso-42001/controls/iso-42001-controls-list/) 的編號體系不同且缺 A.10，未採用。
> - **對應是判斷，不是官方對照**：哪項控制對到哪個子條款是依標題判斷的；送稽核前仍應以標準原文的控制說明確認。
> - **尚未涵蓋的條款**：本專案沒有實作 A.8.4 Communication of incidents（事件通報）與 A.5 系列的影響評估，正式導入時需補上流程面的控制。
>
> **NIST AI RMF 維持在功能層級**（GOVERN／MAP／MEASURE／MANAGE）。OWASP LLM Top 10 2026 的 Appendix A 提供類別層級對照，可作為細化起點：
> - LLM01 對應 MEASURE 1、MEASURE 2、MAP 4；
> - LLM02 對應 MAP 5、MEASURE 2、MANAGE 4；
> - LLM03 對應 MANAGE 4。

## 與 NIST SP 800-207 的對應

| 800-207 元件 | 本專案 |
| --- | --- |
| Policy Enforcement Point (PEP) | Gateway（FastAPI） |
| Policy Engine + Policy Administrator (PDP) | OPA + `policy/authz.rego` |
| Data sources（CDM、activity logs、threat intel…） | Context Tracker（session 狀態）、Audit Log |
| Subject | `agent_id` + `on_behalf_of` + `role` |
| Resource | MCP 工具 |

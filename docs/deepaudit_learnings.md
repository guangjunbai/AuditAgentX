# 向 DeepAudit 学习：优点总结与 Prompt 提炼

> 参考项目：[lintsinghua/DeepAudit](https://github.com/lintsinghua/DeepAudit)（国内首个开源代码漏洞挖掘多智能体系统，v3.0.0）
> 本文整理 DeepAudit 的核心优点，并提炼为可直接使用的 Prompt，指导 AuditAgentX 的实现。

## 1. DeepAudit 的核心优点

| 优点 | 说明 | AuditAgentX 的落地 |
|---|---|---|
| **Fuzzing Harness 动态验证** | 不跑起整个项目，而是提取漏洞函数 + mock 危险依赖 + 多 payload 隔离测试，动态确认"利用漏洞的代码"是否真触发 | `backend/skills/harness_tools.py` + `backend/verifier/harness_verifier.py` |
| **ReAct 工具调用循环** | Verification Agent 是"大脑"，配 read_file / run_code / sandbox_exec 等工具，生成→执行→观察→判定 | MCP 工具集 + HarnessVerifier 循环 |
| **失败自我修正重试** | Harness 未触发/报错时，把执行输出回喂 LLM 改进后重试 | `HarnessVerifier.run` 的重试循环 |
| **强制防幻觉去误报** | 判定前必须 read_file 核对文件/代码真实存在，否则判 false_positive | `verification_tools.py` + VerifyAgent 覆盖 LLM |
| **判定分级** | confirmed / likely / uncertain / false_positive | verdict: confirmed_dynamic / not_reproduced / inconclusive |
| **沙箱隔离 + mock 安全** | harness mock 危险 sink，绝不真实执行系统命令/网络 | 提示词强制 mock + 沙箱/受控子进程执行 |

## 2. 提炼的核心 Prompt

### 2.1 Fuzzing Harness 生成 Prompt（见 `backend/prompts/harness_agent_prompt.md`）

要点：
- **你是大脑**：由 LLM 决定测试策略、payload、检测方法。
- **不依赖完整项目**：提取漏洞函数，mock 掉危险 sink，隔离测试。
- **必须 mock 所有危险 sink**（os.system/subprocess/execute/open/eval/pickle.loads），只记录不真执行。
- **多 payload 循环**：设计多种恶意输入。
- **统一触发标记**：触发时 `print("AUDITAGENTX_VULN_TRIGGERED", 详情)`，否则 `AUDITAGENTX_NO_TRIGGER`。

### 2.2 防幻觉验证 Prompt（见 `backend/prompts/verify_agent_prompt.md`）

要点：
- **必须先调用工具验证**，不允许仅凭已知信息直接判断。
- **文件必须存在**：read_file 返回"文件不存在" → 判 false_positive。
- **代码必须匹配**：code_snippet 必须在文件中真实存在。
- **不要填补缺失信息**：信息不足标记 uncertain。

## 3. AuditAgentX 与 DeepAudit 的对应关系

```
DeepAudit                          AuditAgentX
─────────────                      ──────────────
Recon Agent                    →   RepoParserAgent
Analysis Agent                 →   StaticScanAgent(Scanner) + AuditAgent(Analysis)
Orchestrator(去误报)           →   OrchestratorAgent 的 triage/dedup + VerifyAgent
Verification Agent(harness)    →   VerifyAgent(静态复核) + HarnessVerifier(动态 harness)
                                   + ExploitAgent(利用代码) + DynamicVerifier(HTTP)
LangGraph 编排                 →   OrchestratorAgent 顺序编排
ChromaDB RAG (CWE/CVE)         →   (计划中) 规则库 + 模板库
Docker sandbox                 →   SandboxManager + harness_tools 沙箱执行
```

## 4. AuditAgentX 的差异化增强

- **离线兜底**：LLM 不可用时，harness 有按类型的模板兜底、exploit 有模板兜底，扫描有自定义规则兜底，全链路离线可跑（DeepAudit 强依赖 LLM）。
- **双动态验证**：同时提供 HTTP 动态验证（有运行服务时）和 Fuzzing Harness 验证（无运行服务时），覆盖更全。
- **MCP+Skill 边界清晰**：验证与 harness 能力通过 MCP server 暴露，可被外部 agent 复用。

## 5. 如何进一步向 DeepAudit 学习

1. 读源码：`backend/app/services/agent/agents/verification.py`（harness 提示词 + 工具循环）。
2. 本地部署跑一遍：仓库根 `docker-compose.yml` 一键起，导入靶场观察它生成/执行 harness。
3. 借鉴 RAG：DeepAudit 用 ChromaDB 存 CWE/CVE 知识增强分析，可作为 AuditAgentX 后续方向。

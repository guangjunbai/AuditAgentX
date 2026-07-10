# 动态验证与同类开源系统对比

更新日期：2026-07-10

## 对比口径

这里只比较“Agent 驱动的代码漏洞发现、动态复现、证据裁决和报告”系统，不把通用 SAST、DAST 或安全运营平台混入同一类别。项目能力以公开仓库当前 README 和可见实现为准；项目自称的“首个”只作为对方声明记录，不作为本项目创新性的证明。

## 同类项目

| 项目 | 公开设计重点 | AuditAgentX 应吸收的部分 | 当前可验证差异 |
|---|---|---|---|
| [DeepAudit](https://github.com/lintsinghua/DeepAudit) | Orchestrator、Recon、Analysis、Verification 多 Agent 协作；Docker 沙箱生成并执行 PoC；支持报告导出 | 自主修正失败的 PoC、成熟的沙箱部署体验 | AuditAgentX 把 `mechanism_confirmed`、`function_reproduced`、`endpoint_reproduced` 分层，Harness 被阻断不能覆盖独立 HTTP 确认；确认后的利用代码由真实 `confirmed_record` 重建，而不是再次让模型猜测 |
| [AgentStalker](https://github.com/Gach0ng/AgentStalker) | MODEL → ATTACK → VERIFY → REPORT；统一 AST/污点图、攻击图、沙箱监控、证据裁决 | 类型化阶段契约、攻击图和监控事件关联 | AuditAgentX 当前更强调针对验证器自身的敌对信任边界：baseline 必须同入口同传输、反射不能等同执行、日志必须是请求后的增量、BOLA 必须满足跨身份 owner/secret 不变量并稳定重放 |
| [OpenSecurity](https://github.com/zylc369/OpenSecurity) | 基于 OpenCode 的多领域安全 Agent 平台；LLM 自主编排工具、脚本和知识库 | 工具生态、跨安全领域编排、上下文持续演进 | AuditAgentX 的目标更窄：代码漏洞从源码位置到运行时请求和报告的可审计闭环；本轮动态 SQL/BOLA 验证和报告生成均可完全离线执行，减少 LLM/API 成本 |
| [ESAA-Security](https://github.com/elzobrito/ESAA-Security) | 事件溯源、append-only 日志、边界契约、确定性 projection/hash replay；运行时探测为 opt-in | 不可变事件账本、全流程可重放投影 | AuditAgentX 已记录源码 commit、镜像摘要、PoC/request/response hash，但还没有 ESAA 完整的 append-only 事件投影；当前优势在于真实 endpoint oracle 和精确可执行 PoC，事件账本仍是待补项 |
| [Sandyaa](https://github.com/securelayer7/sandyaa) | 递归深挖、attacker-control 分析、证据 JSON、PoC 生成及可选执行 | 递归扩大上下文、失败后继续追踪调用链 | AuditAgentX 当前用静态攻击面和 OpenAPI `operationId` 映射约束动态入口，并以确定性验证器而不是 PoC 自报结果作最终裁决；递归发现深度尚不能宣称优于 Sandyaa |

## 本轮已经用代码和真实项目证明的能力

1. **同入口差分验证。** SQL 注入使用相同 path/method/transport/param 的 baseline/true/false/true 四点对照；单次长度变化、普通反射、通用请求错误和旧日志都不能升级漏洞。
2. **认证态复现。** 前置登录可以从响应头捕获会话信息，后续 baseline、attack 和 confirmation 使用同一认证上下文；证据与利用代码中的密码、Authorization 和 token 会被脱敏或改为环境变量。
3. **多身份 BOLA/IDOR 状态机。** 必须存在 owner control、不同 attacker 身份、明确 owner 和受控 secret sentinel，并且跨身份读取连续两次稳定复现，才产生 `cross_identity_owner_secret_replay` 裁决。
4. **源码到运行时证据链。** OpenAPI-first 项目可由规范提取 method/path/body/path 参数，并通过 `operationId` 映射到处理函数文件和行号；报告保存 source → authorization → lookup → sink 调用路径。
5. **确认后才生成精确 PoC。** 未执行、机理级或被阻断的 Harness 不生成“已确认”PoC；真实确认后才从实际请求/工作流生成本地目标限定、禁用环境代理的复现代码。
6. **结构化报告契约。** JSON、Markdown、HTML 均保留漏洞列表、严重等级、调用路径、运行时判据、利用代码、修复建议、PoC 路径和不可变复现元数据。

## 真实项目结果

| 目标 | 攻击面/漏洞 | 结果 | API 使用 |
|---|---|---|---|
| `we45/Vulnerable-Flask-App` | 认证后的 `POST /search` SQL 注入 | `paired_boolean_differential` 确认；生成会话感知精确 PoC 和三格式报告 | 0 次 LLM 调用 |
| `we45/VAmPI` | OpenAPI 13 个 endpoint；`GET /books/v1/{book}` BOLA | `owner=name1` 与 `attacker=name2`，跨身份读取同一私有 sentinel 两次，真实容器确认；生成的状态机 PoC 再次执行成功 | 0 次 LLM 调用 |

VAmPI 复现使用本地 Docker 镜像 `auditagentx-vampi-real:local`，测试时镜像 ID 为 `sha256:5d28d1880d2dd9ff5700203974c4977fe7cc5aa369c52557dcf64841852cd472`。目标只绑定回环地址，HTTP 客户端使用 `trust_env=False` 且不跟随重定向。

## 创新性结论与边界

可以作为自研创新点陈述的是：**面向“验证器自欺骗”的分级证据裁决、由框架观测事实生成精确 PoC、以及受约束的多身份业务逻辑 oracle**。这三点已经有单元反例和真实项目复现支撑。

不应声明“完美检测所有漏洞”或未经文献检索的“全球首创”。当前已实证覆盖认证 SQL 注入和 BOLA，并具备若干注入类模板/Harness；XSS 浏览器执行 canary、复杂多租户工作流、异步消息链和更多语言运行时仍需要专门 oracle 与真实基准集。后续创新性评估应采用固定 commit、固定镜像和带 ground truth 的 precision/recall，而不是只比较功能列表。

## 主要来源

- DeepAudit：<https://github.com/lintsinghua/DeepAudit>
- AgentStalker：<https://github.com/Gach0ng/AgentStalker>
- OpenSecurity：<https://github.com/zylc369/OpenSecurity>
- ESAA-Security：<https://github.com/elzobrito/ESAA-Security>
- Sandyaa：<https://github.com/securelayer7/sandyaa>

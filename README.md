# AuditAgentX

AuditAgentX 是一个面向课程实验、安全研究原型和本地授权靶场的代码安全审计平台。它把传统 SAST 工具、自定义轻量污点分析、LLM 多智能体审计、独立复核、RAG 安全知识库、动态 HTTP 验证、Fuzzing Harness、证据链和报告生成串成一条可复现流程。

完整逐目录、逐文件说明见：[`docs/PROJECT_OVERVIEW.md`](docs/PROJECT_OVERVIEW.md)。

## 核心能力

- 支持本地目录和 Git 仓库扫描。
- 融合 Semgrep、Bandit、Gitleaks、Trivy 和自定义规则。
- 自定义扫描包含通用窗口级污点、Python AST 跨函数污点、Java `javalang` 函数级污点。
- 多 Agent 流程：RepoParser、StaticScan、Audit、Verify、Exploit、DynamicAnalysis、Harness、Summary、Report。
- ACP 结构化 Agent 通信和 trace。
- MCP 工具边界与 RAG 知识库：CWE、OWASP、验证 playbook、误报信号、修复建议。
- 动态 HTTP 验证和 Docker Deep 模式。
- Harness 验证区分 `target_confirmed`（真实目标函数级确认）和 `mechanism_confirmed`（模板机理确认）。
- 前端提供项目创建、扫描工作台、漏洞详情、证据链、动态验证、报告和统计视图。
- 提供 OWASP BenchmarkJava 分类评测脚本。

## 能力边界

- 当前是 MVP/实验原型，不是生产级漏洞扫描服务。
- 动态验证只允许用于本地靶场、Docker 沙箱或明确授权目标。
- `examples/vulnerable_projects/safe_sqli_target` 是安全 SQLi 模拟靶场，不执行真实 SQL。
- 模板 Harness 只证明漏洞类型机理，不等价于真实项目可利用复现。
- `.env` 可能包含密钥，不应提交、公开或写入报告。

## 快速启动

后端：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

前端：

```powershell
cd frontend
npm install
npm run dev
```

安全 SQLi 模拟靶场：

```powershell
docker compose up safe-sqli-target --build
```

默认靶场地址：`http://127.0.0.1:8080`。

## 常用命令

| 命令 | 说明 |
|---|---|
| `pytest` | 运行后端测试 |
| `cd frontend; npm run build` | 前端类型检查和生产构建 |
| `python scripts/run_owasp_benchmark.py` | 运行 OWASP BenchmarkJava 分类评测，需本地放置数据集 |
| `docker compose up safe-sqli-target --build` | 启动安全 SQLi 模拟靶场 |
| `docker compose up backend --build` | Docker 方式启动后端 |

## 目录概览

| 目录 | 说明 |
|---|---|
| `backend/` | FastAPI 后端、多 Agent、扫描器、RAG、MCP、ACP、动态验证和报告生成 |
| `frontend/` | Vue 3 + Element Plus 前端 |
| `rules/` | Semgrep/YARA/custom 规则目录 |
| `scripts/` | 批量扫描、知识库生成和 Benchmark 评测脚本 |
| `examples/` | 演示漏洞项目和安全模拟靶场 |
| `tests/` | 后端单元测试、集成测试、ACP/RAG/Harness/动态验证测试 |
| `data/` | 本地运行数据、扫描缓存、报告和沙箱目录 |
| `docs/` | 当前只保留 `PROJECT_OVERVIEW.md` 作为集中式项目说明 |

## Benchmark 现状

在 OWASP BenchmarkJava 早期初步评测中，AuditAgentX 对 SQLi、命令注入、路径遍历等注入类已有一定检测能力，粗略召回约 39%。当前代码已加入 Java 函数级污点、弱算法和弱随机增强；最新结果应以 `python scripts/run_owasp_benchmark.py` 在本地 BenchmarkJava 数据集上的实际输出为准。后续仍应继续增强 XSS、弱加密、弱随机、Trust Boundary 等 Java Web 类别，并用分类指标持续回归。

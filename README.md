# AuditAgentX

开源项目智能安全审计与验证系统。

AuditAgentX 是一个面向课程实验和安全研究原型的代码审计平台，目标是把传统静态扫描工具、LLM 多智能体分析、漏洞验证和结构化报告串成一条可复现的审计流程。项目当前处于 MVP/实验原型阶段，适合用于本地靶场、授权开源项目和课程演示，不适合直接作为生产级漏洞扫描服务使用。

## 项目简介

本项目围绕以下链路构建：

```text
仓库输入 -> 项目解析 -> 静态扫描 -> LLM 审计 -> 独立复核 -> 动态验证/证据采集 -> 报告生成
```

系统支持本地代码目录和 Git 仓库输入，能够解析项目语言、依赖、目录结构，并通过 Semgrep、Bandit、Gitleaks、Trivy 和自定义规则发现候选风险。LLM Agent 用于语义分析、复核和报告生成；动态验证模块只面向本地授权靶场，不提供攻击真实第三方系统的能力。

## 系统架构

```text
FastAPI API 层
    |
    v
OrchestratorAgent 调度层
    |
    +-- RepoParserAgent：仓库解析、语言识别、依赖提取、目录树生成
    +-- StaticScanAgent：Semgrep / Bandit / Gitleaks / Trivy / custom rules
    +-- AuditAgent：LLM 语义审计，补充工具扫描结果
    +-- VerifyAgent：独立复核候选漏洞，降低误报
    +-- ExploitAgent：生成本地授权验证方案和安全载荷模板
    +-- DynamicVerifier：对本地靶场执行 HTTP 探测并采集证据
    +-- ReportAgent / ReportBuilder：生成 Markdown / HTML / JSON / PDF 报告
```

更多架构说明见 `docs/architecture.md`。

## 核心功能

已实现：

- 本地目录和 Git 仓库项目录入。
- 项目语言、框架、依赖、入口文件和目录树解析。
- Semgrep、Bandit、Gitleaks、Trivy 的扫描器封装。
- 无外部依赖的自定义规则扫描，便于离线演示。
- 多智能体框架和统一 LLM 调用封装。
- Prompt、模型输出和解析结果落盘，便于审计过程复现。
- 漏洞利用模板和动态验证器原型。
- 动态验证结果记录请求 URL、参数、payload、状态码、响应摘要、耗时和失败原因。
- 本地安全模拟 SQL 注入靶场。
- FastAPI 接口、Vue 前端骨架、pytest 测试。

计划中或仍需完善：

- 更完整的真实项目批量测试结果。
- 更强的跨文件数据流分析。
- 更细粒度的依赖漏洞可达性分析。
- 前端证据链可视化。
- 更稳定的 Docker 沙箱编排和真实靶场自动启动流程。
- 更丰富的报告模板和 PDF 样式。

## 技术栈

后端：

- Python 3.9+
- FastAPI
- SQLAlchemy
- Pydantic / pydantic-settings
- httpx
- Jinja2
- pytest

安全扫描：

- Semgrep，可选
- Bandit，可选
- Gitleaks，可选
- Trivy，可选
- 自定义正则规则，内置

智能体与模型：

- OpenAI 兼容 Chat Completions API
- DeepSeek / Qwen / OpenAI / 本地 vLLM 等兼容服务

前端：

- Vue 3
- Vite
- Element Plus
- TypeScript

## 快速启动

### 1. 克隆并进入项目

```bash
cd AuditAgentX
```

### 2. 创建 Python 环境并安装依赖

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Linux/macOS：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 配置环境变量

```bash
copy .env.example .env
```

Linux/macOS：

```bash
cp .env.example .env
```

如果暂时不使用 LLM，可保留占位配置，仅运行自定义规则和离线测试。

## 环境变量说明

| 变量 | 说明 | 示例 |
|---|---|---|
| `LLM_API_KEY` | OpenAI 兼容 API Key | `your-api-key-here` |
| `LLM_BASE_URL` | OpenAI 兼容接口地址 | `https://api.example.com/v1` |
| `LLM_MODEL` | 模型名称 | `your-model-name` |
| `LLM_TEMPERATURE` | 模型温度 | `0.1` |
| `LLM_MAX_TOKENS` | 最大输出 token | `4096` |
| `DATABASE_URL` | 数据库连接 | `sqlite:///./data/auditagentx.db` |
| `DATA_DIR` | 运行数据目录 | `./data` |
| `WORKSPACE_DIR` | 项目工作区目录 | `./data/projects` |
| `ENABLE_SEMGREP` | 是否启用 Semgrep | `true` |
| `ENABLE_BANDIT` | 是否启用 Bandit | `true` |
| `ENABLE_GITLEAKS` | 是否启用 Gitleaks | `true` |
| `ENABLE_TRIVY` | 是否启用 Trivy | `false` |
| `ENABLE_SANDBOX` | 是否启用 Docker 沙箱 | `false` |
| `SANDBOX_TIMEOUT` | 沙箱超时秒数 | `60` |

`.env.example` 只应包含占位值，不应提交真实密钥。

## 后端启动

```bash
uvicorn backend.main:app --reload --port 8000
```

访问：

```text
http://localhost:8000/docs
```

健康检查：

```bash
curl http://localhost:8000/health
```

## 前端启动

```bash
cd frontend
npm install
npm run dev
```

默认访问：

```text
http://localhost:5173
```

说明：当前仓库未提交前端 lock 文件，因此 CI 暂不执行前端构建，避免无锁依赖导致构建不稳定。

## 离线演示

不配置 LLM 和外部扫描器时，可以使用内置自定义规则扫描本地演示靶场：

```bash
python - <<'PY'
import json
from backend.database import init_db, SessionLocal
from backend.core import ids
from backend.models import Project, Scan, Finding
from backend.agents.orchestrator_agent import OrchestratorAgent

init_db()
db = SessionLocal()
p = Project(
    id=ids.project_id(),
    name="demo_flask_app",
    source_type="local",
    local_path="examples/vulnerable_projects/demo_flask_app",
    status="created",
)
db.add(p)
db.commit()
s = Scan(
    id=ids.scan_id(),
    project_id=p.id,
    scan_type="static",
    status="queued",
    config_json=json.dumps({"enabled_tools": ["custom"], "enabled_agents": [], "options": {}}),
)
db.add(s)
db.commit()
OrchestratorAgent(db, s).run()
for f in db.query(Finding).filter(Finding.scan_id == s.id):
    print(f.severity, f.type, f"{f.file_path}:{f.start_line}")
db.close()
PY
```

## 测试命令

推荐命令：

```bash
pytest tests/ -q
```

如果本地 Python 路径行为异常，也可以使用：

```bash
python -m pytest tests/ -q
```

当前测试覆盖：

- API 基础接口；
- 仓库解析；
- 自定义静态扫描；
- 漏洞利用模板；
- 结果裁决；
- 动态验证成功、跳过、连接失败、请求超时、端点不存在和 payload 未命中。

## 安全合规说明

- 本项目仅用于本地授权安全测试、课程实验和研究演示。
- 不得对未授权第三方系统运行 PoC、动态验证或扫描任务。
- `examples/vulnerable_projects/` 下的靶场仅供本地演示。
- 动态验证模块默认不启用 Docker 沙箱，也不会主动攻击真实第三方系统。
- `.env`、数据库、运行数据、扫描报告和缓存文件已通过 `.gitignore` 排除。
- 如果使用真实 API Key，请只写入本地 `.env`，不要提交到 Git。

## 当前项目状态

当前状态：MVP/实验原型。

适合：

- GitHub 项目展示；
- 本地课程演示；
- 后续补充真实项目扫描实验；
- 多智能体安全审计流程验证。

尚不适合：

- 生产级 DevSecOps 扫描；
- 未授权目标测试；
- 依赖 LLM 结果直接作最终漏洞结论。

## 后续开发方向

1. 补充 20 个授权开源项目的批量测试记录。
2. 完善 Docker 沙箱和靶场自动启动能力。
3. 增强跨文件 source-to-sink 数据流追踪。
4. 增加依赖漏洞可达性分析。
5. 在前端展示 Agent trace、证据链和风险评分。
6. 增加 CodeQL 等高级静态分析工具作为可选插件。
7. 优化报告模板，使不同漏洞类型生成更具体的修复建议。

## 文档

- 系统架构：`docs/architecture.md`
- API 设计：`docs/api.md`
- 动态验证：`docs/dynamic_exploitation.md`
- 开发流程：`docs/workflow.md`
- 竞品对比：`docs/comparison.md`

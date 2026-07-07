# Deep 模式（Docker 沙箱动态验证）使用说明

Deep 模式会在 **Docker 沙箱**中尝试启动 GitHub 项目，对容器内运行的服务执行授权 PoC / payload
动态验证，并把请求、响应、容器日志、Agent 决策链写入前端和报告。

> ⚠️ 安全边界：Deep 模式**只对本地 Docker 沙箱 / 课程靶场 / 明确授权目标**使用，
> 绝不攻击真实第三方网站。Docker 启动失败时如实标记状态，不造假复现结果。

---

## 一、前置条件

### 1. Docker Desktop（引擎）

Windows / macOS 装 **Docker Desktop**，Linux 装 Docker Engine。安装后确认引擎在运行：

```bash
docker version        # 能看到 Server 版本即正常
docker ps             # 不报错即引擎可用
```

- Windows 需启用 WSL2（Docker Desktop 安装时会引导）。
- Docker Desktop 必须**处于启动状态**（托盘图标为运行态）才能用 Deep 模式。

### 2. Python Docker SDK

```bash
pip install -r requirements.txt      # 已包含 docker>=7.0.0
# 或单独安装
pip install docker
```

验证 Python 能连上 Docker 引擎：

```bash
python -c "import docker; print(docker.from_env().ping())"   # 输出 True 即成功
```

### 3. 连接配置（一般无需改）

`.env` 的 `DOCKER_HOST` **留空**即可——系统自动适配平台
（Windows 用 named pipe，Linux 用 unix socket）。仅连接远程 Docker 时才填 `tcp://host:2375`。

---

## 二、三种扫描模式

| 模式 | 内容 | 是否用 Docker |
|---|---|---|
| **Quick** | 仅静态扫描（Semgrep / Gitleaks / 污点规则），不 LLM、不动态 | 否 |
| **Standard** | + AuditAgent 语义审计 + VerifyAgent 复核去误报 + source→sink 证据链 + 报告 | 否 |
| **Deep** | + Docker 沙箱启动项目 + 端点提取 + HTTP 动态验证 + Harness 验证 | **是** |

---

## 三、Deep 模式怎么用

### 方式 A：前端页面

1. 打开「新建项目」，填入 GitHub 仓库 URL（或本地目录）。
2. 「扫描模式」选 **Deep Docker 沙箱验证**。
3. （可选）展开高级配置，覆盖自动推断：
   - `install_command`：依赖安装命令，如 `pip install -r requirements.txt`
   - `run_command`：启动命令，如 `python app.py`
   - `port`：服务端口，如 `5000`
   - `health_path`：健康检查路径，默认 `/`
   - `env`：环境变量，每行 `KEY=VALUE`
   - 留空则由后端 `launch_detector` 自动推断。
4. 点「创建并开始扫描」。
5. 在「分析工作台」查看沙箱状态、动态验证结果、Agent 通信流；在漏洞详情查看容器日志与请求/响应。

### 方式 B：API

```bash
# 1) 创建项目
curl -X POST localhost:8000/api/projects -H "Content-Type: application/json" \
  -d '{"name":"demo","source_type":"git","url":"https://github.com/owner/repo","branch":"main"}'

# 2) 创建 Deep 扫描（scan_mode=deep 自动启用 docker_project 沙箱）
curl -X POST localhost:8000/api/scans -H "Content-Type: application/json" \
  -d '{"project_id":"proj_xxx","scan_mode":"deep"}'

# 3) 查看漏洞与证据链（含 sandbox / runtime）
curl localhost:8000/api/scans/scan_xxx/findings
curl localhost:8000/api/findings/find_xxx/evidence
```

Deep 模式下 `dynamic_target` 默认 `{"mode": "docker_project"}`；也可显式传 `launch_plan` / `env` 覆盖。

---

## 四、Deep 模式内部流程

```
GitHub URL → clone → RepoParser 识别语言/框架/依赖
  → launch_detector 生成 launch_plan（install_command / run_command / port / health_path）
  → DockerProjectRunner：优先项目 Dockerfile，否则 SandboxBuilder 生成临时 Dockerfile
      → docker build → docker run（端口映射到宿主机随机端口，注入 0.0.0.0 监听）
      → 健康检查等待服务可用 → base_url
  → endpoint_extractor 提取候选路由
  → VerifyAgent 确认漏洞 → ExploitAgent 生成 payload
  → DynamicVerifier 对容器 base_url 发包 → 采集 request/response/容器日志
  → EvidenceCollector 生成证据链（含 sandbox 字段）
  → 扫描结束自动 docker rm -f 清理容器
```

---

## 五、动态验证状态解读（reproduction_status）

| 状态 | 含义 |
|---|---|
| `dynamic_confirmed` | 动态确认可复现（payload 命中成功特征） |
| `not_reproduced` | 已执行但未复现（发了包，未命中） |
| `not_executed` | 未执行（未配置目标） |
| `not_runtime_verifiable` | 漏洞类型不适合动态验证（如硬编码密钥、弱加密、依赖 CVE） |
| `false_positive` | 复核判定误报 |
| `sandbox_start_failed` | Docker 容器启动失败（引擎不可用 / build 失败） |
| `health_check_failed` | 容器启动但服务不可用（未监听 / 启动崩溃） |
| `dependency_install_failed` | 依赖安装失败 |
| `connection_failed` / `endpoint_not_found` / `request_timeout` / `payload_not_matched` | HTTP 层各类失败 |

> Deep 模式只对 **High/Critical** 且策略为 `http`/`both` 的漏洞执行 HTTP 动态验证；
> 命令注入 / 反序列化等走 **Fuzzing Harness** 函数级验证（无需容器）。

---

## 六、故障排查

| 现象 | 原因 / 解决 |
|---|---|
| `sandbox_start_failed`，日志 `AF_UNIX` | Docker 引擎未启动，或 `DOCKER_HOST` 配了 unix socket 但在 Windows 上无效——留空 `DOCKER_HOST` 即可 |
| `health_check_failed`，容器日志显示服务已启动 | ① 服务未监听 `0.0.0.0`（Deep 模式已自动注入 `APP_HOST/HOST/FLASK_RUN_HOST=0.0.0.0`，若项目硬编码 127.0.0.1 需改 run_command）；② 宿主机代理拦截本地连接（系统已用 `trust_env=False` 直连，一般无需处理）；③ 启动慢，增大 `SANDBOX_TIMEOUT` |
| `dependency_install_failed` | 依赖装不上——在高级配置手动指定正确的 `install_command`，或项目自带 Dockerfile 更可靠 |
| 镜像 build 很慢 | 首次拉基础镜像 + 装依赖较慢，属正常；后续有缓存会快 |

---

## 七、安全提醒

- Deep 模式容器**限内存 512M**、扫描后**自动销毁**。
- payload 仅用于本地容器，命令类载荷使用无害回显标记，不含删除/外联/持久化。
- 切勿把 `dynamic_target.mode="url"` 指向未授权的真实网站。

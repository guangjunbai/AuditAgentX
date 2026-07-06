# 本地环境、Docker 靶场与剩余功能清单

本文档说明 AuditAgentX 在本机运行时需要的依赖、Docker 靶场用途、启动方式，以及项目后续仍需完善的模块。

## 1. 依赖与工具清单

### 必需依赖

| 类型 | 工具 | 用途 |
|---|---|---|
| Python | Python 3.9+ | 后端 FastAPI、扫描编排、测试 |
| Git | Git for Windows / Git CLI | clone GitHub/GitLab 仓库 |
| Node.js | Node.js 18+ / 20 推荐 | 前端 Vue/Vite 开发与构建 |
| npm | npm | 安装前端依赖 |
| Docker | Docker Desktop | 启动本地靶场与后续沙箱环境 |

### Python 依赖

安装方式：

```bash
pip install -r requirements.txt
```

主要包括：

```text
FastAPI / Uvicorn / SQLAlchemy / Pydantic / GitPython / OpenAI SDK / httpx / Jinja2 / pytest
```

### 前端依赖

安装方式：

```bash
cd frontend
npm ci
```

主要包括：

```text
Vue 3 / Vite / Element Plus / TypeScript / axios
```

### 可选安全扫描工具

这些工具不是所有演示都必须，但会增强扫描能力：

| 工具 | 用途 | 建议安装方式 |
|---|---|---|
| Semgrep | 多语言 SAST 扫描 | `pip install semgrep` 或后端 Docker 镜像 |
| Bandit | Python 安全扫描 | `pip install bandit` 或后端 Docker 镜像 |
| Gitleaks | Secret 泄露扫描 | 官方二进制或 Docker |
| Trivy | 依赖/CVE/镜像扫描 | 官方二进制或 Docker |

即使不安装这些外部工具，项目仍可使用内置 `custom` 规则完成本地演示。

## 2. `http://127.0.0.1:8080` 的用途

`http://127.0.0.1:8080` 是前端动态分析默认填写的本地授权靶场地址。

动态验证模块会向这个地址发送 payload，例如：

```text
http://127.0.0.1:8080/user?id=1'
```

如果响应中出现 `SQL syntax` 等成功特征，系统会把该漏洞标记为动态可复现，并保存：

```text
请求 URL / 参数 / payload / 状态码 / 响应摘要 / 命中特征 / 验证结论
```

## 3. Docker 靶场启动

项目内置了安全 SQL 注入模拟靶场：

```text
examples/vulnerable_projects/safe_sqli_target/
```

它不会执行真实 SQL，也不会连接第三方系统，只返回稳定的模拟漏洞响应。

启动方式：

```bash
docker compose up -d --build safe-sqli-target
```

查看状态：

```bash
docker ps --filter "name=auditagentx-safe-sqli-target"
```

验证普通请求：

```bash
curl "http://127.0.0.1:8080/user?id=1"
```

预期响应：

```text
<html><body>user list</body></html>
```

验证注入特征：

```bash
curl "http://127.0.0.1:8080/user?id=1%27"
```

预期响应包含：

```text
SQL syntax
```

停止靶场：

```bash
docker compose stop safe-sqli-target
```

删除靶场容器：

```bash
docker compose down
```

## 4. 前端动态验证如何使用

1. 启动后端：

```bash
uvicorn backend.main:app --reload --port 8000
```

2. 启动前端：

```bash
cd frontend
npm run dev
```

3. 启动靶场：

```bash
docker compose up -d --build safe-sqli-target
```

4. 在前端中使用：

```text
动态目标 Base URL: http://127.0.0.1:8080
端点列表: /user
```

5. 在漏洞详情页的“动态分析”标签页点击“执行动态验证”。

## 5. Docker 是否更方便

是。Docker 更适合本项目的靶场和工具依赖：

1. 环境隔离，不污染本机 Python/Node 环境。
2. 靶场端口固定，前端默认配置可直接使用。
3. 团队成员可以复现同样环境。
4. 后续可继续加入 DVWA、Juice Shop、WebGoat 等靶场。
5. CI/CD 和演示环境更容易统一。

目前项目已经 Docker 化的部分：

```text
safe-sqli-target 本地动态验证靶场
backend 后端镜像骨架
```

## 6. 当前项目仍缺少的模块或功能

### 高优先级

1. **真实 20 个项目批量扫描结果**  
   课程要求不低于 20 款主流开源项目检测，目前还需要实际运行并保存统计结果。

2. **更完整的动态靶场矩阵**  
   当前只有安全 SQLi 模拟靶场，后续应增加命令注入、路径遍历、SSRF、XSS 等本地授权靶场。

3. **前端动态验证结果自动刷新**  
   当前可查询和回看，但后台任务完成后的自动轮询和状态刷新还可以增强。

4. **LLM 配置校验**  
   如果 LLM API Key 不可用，应在前端和后端给出更明确的提示。

### 中优先级

1. **依赖漏洞可达性分析**  
   Trivy/SCA 结果需要进一步判断项目是否真的调用了危险依赖路径。

2. **跨文件 source-to-sink 数据流追踪**  
   当前已有证据链结构，但深度数据流分析还不够完整。

3. **报告模板增强**  
   针对不同漏洞类型生成更具体的修复建议。

4. **前端图形化证据链**  
   将 source -> sink -> exploit -> runtime 用可视化链路展示。

### 低优先级

1. **按需引入 Element Plus 降低前端包体积**。
2. **PDF 报告导出样式优化**。
3. **更多 CI 检查，如 lint、typecheck、Docker build 检查**。

# backend/verifier —— 漏洞验证、利用与证据链模块

本目录负责把"候选漏洞"变成"已验证、可利用、有证据链"的结论，是课件模块③（漏洞自动利用）
与动态检测的核心，深度借鉴 [DeepAudit](https://github.com/lintsinghua/DeepAudit) 的动态验证思路。

## 文件说明

| 文件 | 职责 |
|---|---|
| `exploit_validator.py` | 结果裁决：去重、误报过滤、风险评级 |
| `exploit_templates.py` | 9 类漏洞的利用载荷/成功特征模板库（离线兜底） |
| `dynamic_verifier.py` | **HTTP 动态验证**：对运行中的靶场发 payload、采集 request/response、判定可复现 |
| `harness_verifier.py` | **Fuzzing Harness 动态验证**（DeepAudit 式）：生成 mock 验证脚本 → 沙箱执行 → 自我修正重试 |
| `app_runner.py` | 靶场启动器：本地子进程 / Docker 两种 provider |
| `sandbox_manager.py` | Docker 沙箱执行封装 |
| `poc_runner.py` | PoC 生成 + 沙箱执行调度 |
| `evidence_collector.py` | **证据链汇总**：source→sink→call_path→exploit→runtime→harness |
| `pipeline.py` | `ExploitPipeline`：把利用生成 + HTTP 动态 + Harness 动态 + 证据链一体化装配 |

## 两种动态验证的区别（重点）

| | HTTP 动态验证 (`dynamic_verifier`) | Fuzzing Harness (`harness_verifier`) |
|---|---|---|
| 前提 | 目标 Web 服务**必须运行** | 目标**无需运行**（提取函数隔离测试） |
| 做法 | 对端点发攻击 payload，看响应特征 | mock 危险 sink，喂 payload，看是否触发 |
| 适用 | 有靶场/授权环境的 Web 漏洞 | 代码审计场景（目标通常没起服务） |
| 判定 | reproducible（响应命中特征） | confirmed_dynamic（harness 打印触发标记） |

## Fuzzing Harness 闭环（DeepAudit 精髓）

```
extract_function(提取漏洞函数)
    → 生成 Harness（LLM，或 LLM 不可用时按类型模板兜底）
    → 沙箱执行（Docker 优先，受控本地子进程回退）
    → 检测触发标记 AUDITAGENTX_VULN_TRIGGERED
    → 未触发/报错则把执行输出回喂 LLM 自我修正，重试（bounded）
    → verdict: confirmed_dynamic / not_reproduced / inconclusive
```

**安全约束**：Harness 由提示词强制 mock 所有危险 sink（os.system/execute/open/pickle.loads 等），
只在本地隔离环境短时运行，绝不真实执行系统命令、删除文件或发起网络请求。

## 证据链结构（evidence_collector 输出）

```jsonc
{
  "source": "...", "sink": "...", "data_flow": "...",
  "call_path": [{"stage":"source",...},{"stage":"sink",...}],   // 逐跳调用路径
  "exploit":  { "trigger_location", "exploit_path", "payloads", "exploit_code", ... },
  "runtime":  { "reproducible", "request", "response_status", ... },   // HTTP 动态
  "harness":  { "verdict", "dynamically_triggered", "harness_code", "trigger_detail", ... },  // Harness 动态
  "logs": [ ... ]
}
```

详见根目录 `docs/dynamic_exploitation.md` 与 `docs/deepaudit_learnings.md`。

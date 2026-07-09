# 检测精度基准（Precision / Recall / F1）

把"看起来能扫出来"变成**量化数字**，是 AuditAgentX 从原型走向可信的关键一步。

## 方法

- **标注样本**（ground truth）：`scripts/run_benchmark.py` 内嵌带标签的漏洞/安全样本，
  覆盖多语言（Python / PHP / JavaScript）× 多类型（SQLi / 命令注入 / 路径遍历 / XSS /
  不安全反序列化 / 硬编码密钥），且每类都有**漏洞版**与**安全版**（含净化器 / 参数化 / 静态字面量）。
- **口径**：文件级检测——某文件被报出「匹配类型」的 finding 即视为「检出该类」。
  - 漏洞样本被检出 = TP，未检出 = FN（漏报）
  - 安全样本被检出 = FP（误报），未检出 = TN
- **置信度阈值**：默认 `min_confidence=0.6`，低置信 finding（如识别到净化器后降级的 0.5）
  视为"待人工复核"，不计入"检出漏洞"——与真实工具的 severity/confidence 门控一致。

## 结果（置信度阈值 0.6）

| 检测器 | Precision | Recall | F1 |
|---|---|---|---|
| 内置 custom 污点分析 | 1.00 | 1.00 | 1.00 |
| Semgrep（`--config auto` 官方规则 + 项目规则） | 0.83 | 0.63 | 0.71 |
| **组合检测栈（custom ∪ semgrep，实际系统）** | **0.89** | **1.00** | **0.94** |

**观察**：两个检测器互补——Semgrep 官方规则漏掉了 PHP echo XSS、硬编码密钥、JS 命令注入
（这些内置污点分析检出了）；内置污点分析对净化器样本会产生低置信 finding（阈值门控后消除）。
组合栈 recall=1.0（无漏报），precision 的唯一失分来自 Semgrep 把 `subprocess.run([...], shell=False)`
安全写法误报为命令注入。

## 复现

```bash
python scripts/run_benchmark.py        # 打印逐样本 + 三套指标
python -m pytest tests/test_benchmark.py -q   # 把内置扫描器精度固化进 CI
```

## 诚实边界

这是一个**自建的小型微基准**（~15 个样本），用于建立可复现的评测方法与基线数字，
**不等价于** OWASP Benchmark（2700+ 例）/ Juliet / 真实 CVE 数据集那样的第三方大规模评测。
下一步若要更强的可信度，应接入第三方大规模基准并给出统计显著的 precision/recall。

"""检测精度基准测试：把 precision/recall 固化进 CI（离线、确定性）。

只评估内置 custom 污点扫描器（不依赖 semgrep/网络，CI 可复现）。
组合栈（custom ∪ semgrep）的数字见 `python scripts/run_benchmark.py`。
"""
from scripts.run_benchmark import run_benchmark


def test_custom_scanner_precision_recall_threshold():
    """内置污点扫描器在标注基准上的精度必须达标（置信度阈值 0.6）。"""
    m = run_benchmark(min_confidence=0.6)
    assert m["total"] >= 12, "基准样本量过少"
    assert m["fn"] == 0, f"存在漏报: {m['rows']}"          # 无漏报
    assert m["precision"] >= 0.8, f"precision 过低: {m['precision']}"
    assert m["recall"] >= 0.8, f"recall 过低: {m['recall']}"
    assert m["f1"] >= 0.8, f"F1 过低: {m['f1']}"


def test_low_confidence_findings_excluded_from_detection():
    """低于阈值的净化器样本（如 secure_filename/htmlspecialchars）不应被计为检出。"""
    strict = run_benchmark(min_confidence=0.6)
    loose = run_benchmark(min_confidence=0.0)
    # 放宽阈值后误报应不减少（净化器样本会被低置信 finding 命中）
    assert loose["fp"] >= strict["fp"]

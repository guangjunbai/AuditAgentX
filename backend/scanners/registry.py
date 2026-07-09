"""扫描器注册表 —— 按启用工具集合统一调度（多扫描器并行执行）。"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from backend.scanners.base import RawFinding
from backend.scanners.semgrep_runner import SemgrepScanner
from backend.scanners.bandit_runner import BanditScanner
from backend.scanners.gitleaks_runner import GitleaksScanner
from backend.scanners.trivy_runner import TrivyScanner
from backend.scanners.custom_rules import CustomRuleScanner

logger = logging.getLogger(__name__)

_SCANNERS = {
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
    "custom": CustomRuleScanner,
}


def _run_one(tool: str, target: Path) -> list[RawFinding]:
    """运行单个扫描器（独立进程/纯计算，可并行）；失败不影响其它扫描器。"""
    cls = _SCANNERS.get(tool)
    if not cls:
        logger.warning("未知扫描器: %s", tool)
        return []
    scanner = cls()
    if not scanner.available():
        logger.warning("扫描器 %s 未安装，跳过", tool)
        return []
    try:
        results = scanner.run(target)
        logger.info("扫描器 %s 发现 %d 条", tool, len(results))
        return results
    except Exception as e:  # noqa: BLE001  单个工具失败不影响整体
        logger.exception("扫描器 %s 执行失败: %s", tool, e)
        return []


def run_scanners(target: Path, enabled_tools: list[str]) -> list[RawFinding]:
    """并行运行选定的扫描器；始终附加 custom 规则作为兜底。

    各扫描器相互独立（semgrep/bandit/gitleaks 是子进程、custom 是纯计算），
    并行后总耗时≈最慢的那个（通常是 semgrep），而非各工具耗时累加。
    结果按工具顺序拼接，保证确定性。
    """
    tools = list(dict.fromkeys(enabled_tools + ["custom"]))
    results_by_tool: dict[str, list[RawFinding]] = {}
    workers = max(1, min(len(tools), 5))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan") as pool:
        futures = {pool.submit(_run_one, t, target): t for t in tools}
        for fut in as_completed(futures):
            results_by_tool[futures[fut]] = fut.result()

    all_findings: list[RawFinding] = []
    for tool in tools:                       # 按输入顺序拼接，确定性
        all_findings.extend(results_by_tool.get(tool, []))
    return all_findings

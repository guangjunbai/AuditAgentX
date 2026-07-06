"""StaticScanAgent: tool-calling scanner agent.

It dispatches SAST/secret/SCA/custom-rule tools through the scanner registry and
normalizes their output into RawFinding records.
"""
from __future__ import annotations

from pathlib import Path

from backend.scanners.registry import run_scanners
from backend.scanners.base import RawFinding


class StaticScanAgent:
    name = "static_scan_agent"

    def __init__(self) -> None:
        self.tool_calls: list[dict] = []

    def run(self, code_root: Path, enabled_tools: list[str]) -> list[RawFinding]:
        tools = list(dict.fromkeys(enabled_tools + ["custom"]))
        self.tool_calls = [
            {
                "tool": tool,
                "purpose": _tool_purpose(tool),
                "target": str(code_root),
            }
            for tool in tools
        ]
        return run_scanners(code_root, enabled_tools)


def _tool_purpose(tool: str) -> str:
    return {
        "semgrep": "SAST rule scanning for injection, traversal, XSS, and framework risks.",
        "bandit": "Python security linting.",
        "gitleaks": "Secret and credential leakage detection.",
        "trivy": "Dependency, container, and configuration vulnerability scanning.",
        "custom": "Built-in offline rules for SQL injection, command injection, path traversal, and hardcoded secrets.",
    }.get(tool, "External or custom static analysis tool.")

"""Semgrep 扫描器封装（通用代码安全规则）。"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from backend.scanners.base import BaseScanner, RawFinding, normalize_severity

logger = logging.getLogger(__name__)


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    cli = "semgrep"

    # 项目自定义 taint mode 规则目录
    custom_rules_dir = Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep"

    def run(self, target: Path) -> list[RawFinding]:
        if not self.available():
            return []
        # 官方规则集 auto + 项目自定义 taint 规则（source→sink 污点追踪，降误报）
        cmd = ["semgrep", "scan", "--config", "auto"]
        if self.custom_rules_dir.exists() and any(self.custom_rules_dir.glob("*.y*ml")):
            cmd += ["--config", str(self.custom_rules_dir)]
        # --no-git-ignore：不受 .gitignore 影响，vendored/被忽略但存在的代码也扫
        cmd += ["--no-git-ignore", "--json", "--quiet", str(target)]
        # 关键：强制 UTF-8。中文 Windows 默认 GBK，semgrep 读含中文的 UTF-8 规则文件会崩（exit 2）
        env = {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        proc = self._exec(cmd, timeout=900, env=env)
        findings: list[RawFinding] = []
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            # 静默失败会让"专业工具在跑"成为假象；如实记录 semgrep 报错
            logger.warning("semgrep 执行失败(exit=%s)，未产出有效 JSON。stderr: %s",
                           proc.returncode, (proc.stderr or "")[:500])
            return []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            findings.append(RawFinding(
                type=r.get("check_id", "semgrep-finding").split(".")[-1],
                file=r.get("path", ""),
                line=r.get("start", {}).get("line", 0),
                severity=normalize_severity(extra.get("severity", "warning")),
                source=self.name,
                code_snippet=extra.get("lines", ""),
                message=extra.get("message", ""),
                rule_id=r.get("check_id", ""),
            ))
        return findings

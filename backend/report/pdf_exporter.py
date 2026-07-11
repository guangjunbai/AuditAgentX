"""HTML -> PDF 导出（可选依赖，失败时显式报错）。"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def html_to_pdf(html: str, out_path: Path) -> Path:
    """Use WeasyPrint; never return an HTML artifact mislabeled as PDF."""
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(str(out_path))
        return out_path
    except Exception as exc:  # noqa: BLE001
        logger.exception("PDF 导出失败: %s", exc)
        raise RuntimeError("PDF export failed; install and configure WeasyPrint") from exc

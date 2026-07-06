"""对比分析与统计接口（课件模块⑤ + ≥20 款项目检测的量化展示）。"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.analytics import aggregate, benchmark

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/overview")
def get_overview(db: Session = Depends(get_db)) -> dict:
    """全局概览：项目/扫描/漏洞总量、严重级分布、Top 漏洞类型。"""
    return aggregate.overview(db)


@router.get("/projects")
def get_project_comparison(db: Session = Depends(get_db)) -> dict:
    """被测项目横向对比：每个项目最新扫描的漏洞画像与风险分。"""
    rows = aggregate.project_comparison(db)
    return {"total": len(rows), "projects": rows}


@router.get("/benchmark")
def get_benchmark() -> dict:
    """与同类开源审计系统的能力对标（验证系统创新性）。"""
    return benchmark.benchmark()

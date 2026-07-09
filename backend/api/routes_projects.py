"""项目管理接口（md 7.1 / 7.2 / 7.3）。"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.core import ids
from backend.models import Project
from backend.schemas import ProjectCreate, ProjectOut
from backend.repository.git_client import prepare_workspace
from backend.agents.repo_parser_agent import RepoParserAgent

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _safe_upload_relative_path(filename: str) -> PurePosixPath:
    raw = filename.replace("\\", "/")
    parts = [
        part for part in PurePosixPath(raw).parts
        if part not in ("", ".", "..") and ":" not in part
    ]
    if not parts:
        raise HTTPException(400, "invalid upload filename")
    return PurePosixPath(*parts)


@router.post("", response_model=ProjectOut)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> ProjectOut:
    pid = ids.project_id()
    project = Project(
        id=pid, name=payload.name, source_type=payload.source_type,
        url=payload.url, local_path=payload.local_path, branch=payload.branch,
        description=payload.description, status="created",
    )
    db.add(project)
    db.commit()
    return ProjectOut(project_id=pid, status="created", message="Project created successfully")


@router.post("/upload", response_model=ProjectOut)
async def upload_local_project(
    name: str = Form(...),
    files: list[UploadFile] = File(...),
    description: str | None = Form(None),
    db: Session = Depends(get_db),
) -> ProjectOut:
    """Upload a browser-selected local directory into a backend-accessible workspace."""
    if not files:
        raise HTTPException(400, "no files uploaded")

    pid = ids.project_id()
    upload_root = settings.data_path / "uploads" / pid
    upload_root.mkdir(parents=True, exist_ok=True)

    saved = 0
    for item in files:
        rel = _safe_upload_relative_path(item.filename or item.name)
        dest = upload_root / Path(*rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as out:
            while chunk := await item.read(1024 * 1024):
                out.write(chunk)
        saved += 1
        await item.close()

    if saved == 0:
        raise HTTPException(400, "uploaded directory contains no files")

    project = Project(
        id=pid, name=name, source_type="local",
        local_path=str(upload_root), description=description, status="created",
    )
    db.add(project)
    db.commit()
    return ProjectOut(project_id=pid, status="created", message=f"Uploaded {saved} files")


@router.get("")
def list_projects(db: Session = Depends(get_db)) -> dict:
    rows = db.query(Project).order_by(Project.created_at.desc()).all()
    return {"total": len(rows), "projects": [
        {"project_id": p.id, "name": p.name, "status": p.status,
         "source_type": p.source_type, "url": p.url} for p in rows
    ]}


@router.post("/{project_id}/parse")
def parse_project(project_id: str, db: Session = Depends(get_db)) -> dict:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    code_root = prepare_workspace(
        project.id, project.source_type, project.url, project.local_path, project.branch,
    )
    metadata = RepoParserAgent().run(code_root)
    project.language_summary = ", ".join(metadata.get("languages", []))
    project.metadata_json = json.dumps(
        {k: v for k, v in metadata.items() if k != "_files"}, ensure_ascii=False
    )
    project.status = "parsed"
    db.commit()
    return {
        "project_id": project.id, "status": "parsed",
        "metadata": {k: v for k, v in metadata.items() if k not in ("_files", "tree")},
    }


@router.get("/{project_id}/tree")
def get_tree(project_id: str, db: Session = Depends(get_db)) -> dict:
    """返回项目解析元信息：文件结构树 + 语言/框架/依赖/入口/规模，供前端"项目结构"页展示。"""
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "project not found")
    meta = json.loads(project.metadata_json or "{}")
    return {
        "project_id": project.id,
        "language_summary": project.language_summary,
        "tree": meta.get("tree", []),
        "languages": meta.get("languages", []),
        "frameworks": meta.get("frameworks", []),
        "dependencies": meta.get("dependencies", []),
        "entrypoints": meta.get("entrypoints", []),
        "file_count": meta.get("file_count", 0),
        "loc": meta.get("loc", 0),
    }

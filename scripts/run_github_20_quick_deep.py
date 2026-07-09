"""Run 20 GitHub projects through AuditAgentX quick + deep modes.

Outputs are archived under:
    reports/github_20_quick_deep/<project-name>/

Each project directory contains:
    <project>_quick.html / .md / .json
    <project>_deep.html / .md / .json
    <project>_quick_scan_meta.json
    <project>_deep_scan_meta.json

The target set is intentionally made of vulnerable training apps, benchmarks,
and the two course-mentioned examples (openvpn, maccms10). Dynamic validation
is limited to local Docker/Harness execution by the existing project pipeline.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.agents.orchestrator_agent import OrchestratorAgent  # noqa: E402
from backend.agents.summary_agent import SummaryAgent  # noqa: E402
from backend.config import settings  # noqa: E402
from backend.core import ids  # noqa: E402
from backend.database import SessionLocal, init_db  # noqa: E402
from backend.models import Evidence, Finding, Project, Report, Scan  # noqa: E402
from backend.report import report_builder  # noqa: E402


TARGETS: list[dict[str, str]] = [
    {"name": "DVWA", "url": "https://github.com/digininja/DVWA"},
    {"name": "Juice-Shop", "url": "https://github.com/juice-shop/juice-shop"},
    {"name": "WebGoat", "url": "https://github.com/WebGoat/WebGoat"},
    {"name": "NodeGoat", "url": "https://github.com/OWASP/NodeGoat"},
    {"name": "Mutillidae", "url": "https://github.com/webpwnized/mutillidae"},
    {"name": "OWASP-VulnerableApp", "url": "https://github.com/SasanLabs/VulnerableApp"},
    {"name": "OWASP-WebGoatPHP", "url": "https://github.com/OWASP/OWASPWebGoatPHP"},
    {"name": "OWASP-Vulnerable-Web-Application", "url": "https://github.com/OWASP/Vulnerable-Web-Application"},
    {"name": "DVNA", "url": "https://github.com/appsecco/dvna"},
    {"name": "Vulnerable-Flask-App", "url": "https://github.com/we45/Vulnerable-Flask-App"},
    {"name": "django.nV", "url": "https://github.com/nVisium/django.nV"},
    {"name": "RailsGoat", "url": "https://github.com/OWASP/railsgoat"},
    {"name": "crAPI", "url": "https://github.com/OWASP/crAPI"},
    {"name": "SecurityShepherd", "url": "https://github.com/OWASP/SecurityShepherd"},
    {"name": "Damn-Vulnerable-DeFi", "url": "https://github.com/theredguild/damn-vulnerable-defi"},
    {"name": "Damn-Vulnerable-GraphQL-Application", "url": "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"},
    {"name": "vuln_node_express", "url": "https://github.com/kaakaww/vuln_node_express"},
    {"name": "DVPWA", "url": "https://github.com/anxolerd/dvpwa"},
    {"name": "maccms10", "url": "https://github.com/magicblack/maccms10"},
    {"name": "openvpn", "url": "https://github.com/OpenVPN/openvpn"},
]


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "project"


def scan_config(mode: str, scan_id: str, max_candidates: int, workers: int) -> dict[str, Any]:
    tools = ["semgrep", "bandit", "gitleaks", "custom"]
    if mode == "quick":
        return {
            "scan_mode": "quick",
            "enabled_tools": tools,
            "enabled_agents": [],
            "options": {
                "enable_exploit": False,
                "enable_dynamic": False,
                "enable_harness": False,
                "enable_sandbox": False,
            },
        }
    if mode == "deep":
        return {
            "scan_mode": "deep",
            "enabled_tools": tools,
            "enabled_agents": ["audit", "verify", "exploit", "harness"],
            "options": {
                "enable_exploit": True,
                "enable_dynamic": True,
                "enable_harness": True,
                "enable_sandbox": True,
                "max_verify_candidates": max_candidates,
                "max_verify_workers": workers,
                "dynamic_target": {"mode": "docker_project", "scan_id": scan_id},
            },
        }
    if mode == "standard":
        return {
            "scan_mode": "standard",
            "enabled_tools": tools,
            "enabled_agents": ["audit", "verify"],
            "options": {
                "enable_exploit": False,
                "enable_dynamic": False,
                "enable_harness": False,
                "enable_sandbox": False,
                "max_verify_candidates": max_candidates,
                "max_verify_workers": workers,
            },
        }
    raise ValueError(f"unsupported mode: {mode}")


def make_project(db, target: dict[str, str]) -> Project:
    project = Project(
        id=ids.project_id(),
        name=target["name"],
        source_type="git",
        url=target["url"],
        branch=target.get("branch"),
        status="created",
    )
    db.add(project)
    db.commit()
    return project


def make_scan(db, project: Project, mode: str, max_candidates: int, workers: int) -> Scan:
    scan_id = ids.scan_id()
    scan = Scan(
        id=scan_id,
        project_id=project.id,
        scan_type="static" if mode == "quick" else "full",
        status="queued",
        progress=0,
        config_json=json.dumps(
            scan_config(mode, scan_id, max_candidates, workers),
            ensure_ascii=False,
        ),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def decode_json(value: str | None):
    return json.loads(value or "null")


def decode_report_evidence(ev: Evidence) -> dict[str, Any]:
    poc = decode_json(ev.poc_result)
    if isinstance(poc, dict) and ("exploit" in poc or "runtime" in poc):
        exploit = poc.get("exploit")
        runtime = poc.get("runtime")
        call_path = poc.get("call_path")
        harness = poc.get("harness")
        sandbox = poc.get("sandbox")
        poc_result = poc.get("poc_result")
        tool_calls = poc.get("tool_calls")
        static_evidence_chain = poc.get("static_evidence_chain")
        verification = poc.get("verification")
        knowledge = poc.get("knowledge")
    else:
        exploit = None
        runtime = None
        call_path = None
        harness = None
        sandbox = None
        poc_result = poc
        tool_calls = None
        static_evidence_chain = None
        verification = None
        knowledge = None
    if sandbox is None and isinstance(runtime, dict):
        sandbox = runtime.get("sandbox")
    return {
        "source": decode_json(ev.source),
        "sink": decode_json(ev.sink),
        "data_flow": decode_json(ev.data_flow),
        "call_path": call_path,
        "exploit": exploit,
        "runtime": runtime,
        "harness": harness,
        "sandbox": sandbox,
        "poc_result": poc_result,
        "tool_calls": tool_calls or [],
        "static_evidence_chain": static_evidence_chain or {},
        "verification": verification or {},
        "knowledge": knowledge or {},
        "logs": decode_json(ev.logs),
    }


def report_inputs(db, scan: Scan) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    project = scan.project
    meta = decode_json(project.metadata_json) or {}
    rows = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    findings: list[dict[str, Any]] = []
    for f in rows:
        detail = decode_json(f.detail_json) or {}
        verify_detail = detail.get("_verify") or {}
        ev = (
            db.query(Evidence)
            .filter(Evidence.finding_id == f.id)
            .order_by(Evidence.created_at.desc())
            .first()
        )
        evidence = decode_report_evidence(ev) if ev else None
        tool_calls = (
            verify_detail.get("tool_calls")
            or (verify_detail.get("_tool_evidence") or {}).get("tools_used")
            or []
        )
        if evidence is not None:
            evidence["tool_calls"] = tool_calls or evidence.get("tool_calls") or []
            evidence["static_evidence_chain"] = (
                evidence.get("static_evidence_chain") or verify_detail.get("evidence_chain") or {}
            )
            evidence["knowledge"] = evidence.get("knowledge") or verify_detail.get("knowledge") or {}
        findings.append({
            "finding_id": f.id,
            "type": f.type,
            "severity": f.severity,
            "file": f.file_path,
            "start_line": f.start_line,
            "line": f.start_line,
            "code_snippet": f.code_snippet,
            "confidence": f.confidence,
            "source": f.source,
            "verified": f.verified,
            "status": f.status,
            "fix_suggestion": f.fix_suggestion,
            "tool_calls": tool_calls,
            "evidence": evidence,
        })

    project_ctx = {
        "name": project.name,
        "url": project.url,
        "local_path": project.local_path,
        "languages": meta.get("languages", []),
        "frameworks": meta.get("frameworks", []),
        "file_count": meta.get("file_count", 0),
        "loc": meta.get("loc", 0),
    }
    scan_ctx = {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "config": decode_json(scan.config_json) or {},
        "error": scan.error,
    }
    stats = report_builder.severity_stats(findings)
    summary = SummaryAgent(scan_id=scan.id).run(project_ctx, scan_ctx, findings, stats)
    return project_ctx, scan_ctx, findings, summary


def archive_reports(db, scan: Scan, project_slug: str, mode: str, out_dir: Path,
                    formats: tuple[str, ...]) -> dict[str, Any]:
    project_ctx, scan_ctx, findings, summary = report_inputs(db, scan)
    files: dict[str, str] = {}
    for fmt in formats:
        fp = report_builder.generate(project_ctx, scan_ctx, findings, summary, fmt=fmt)
        suffix = "md" if fmt == "markdown" else fmt
        dest = out_dir / f"{project_slug}_{mode}.{suffix}"
        shutil.copy2(fp, dest)
        files[suffix] = str(dest)

        report = Report(id=ids.report_id(), scan_id=scan.id, format=fmt, file_path=str(fp))
        db.add(report)
    db.commit()
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "error": scan.error,
        "findings": len(findings),
        "stats": report_builder.severity_stats(findings),
        "files": files,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def cleanup_project_workspace(project_id: str) -> None:
    workspace_root = settings.workspace_path.resolve()
    target = (workspace_root / project_id).resolve()
    if target.exists() and str(target).startswith(str(workspace_root)):
        shutil.rmtree(target, ignore_errors=True)


def run_one(db, target: dict[str, str], mode: str, root_out: Path,
            max_candidates: int, workers: int, force: bool,
            formats: tuple[str, ...], cleanup_workspace: bool) -> dict[str, Any]:
    project_slug = slugify(target["name"])
    out_dir = root_out / project_slug
    out_dir.mkdir(parents=True, exist_ok=True)
    meta_path = out_dir / f"{project_slug}_{mode}_scan_meta.json"
    done_marker = out_dir / f"{project_slug}_{mode}.html"
    if done_marker.exists() and meta_path.exists() and not force:
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
        payload["skipped_existing"] = True
        return payload

    project = make_project(db, target)
    scan = make_scan(db, project, mode, max_candidates, workers)
    started = time.time()
    result: dict[str, Any] = {
        "project": target["name"],
        "url": target["url"],
        "mode": mode,
        "project_id": project.id,
        "scan_id": scan.id,
        "status": "running",
        "started_at": datetime.utcnow().isoformat() + "Z",
    }
    write_json(meta_path, result)

    try:
        OrchestratorAgent(db, scan).run()
    except Exception as exc:  # noqa: BLE001
        # Orchestrator normally catches failures and marks the scan failed, but
        # keep the batch runner resilient if an unexpected exception escapes.
        db.rollback()
        scan = db.get(Scan, scan.id)
        if scan is not None:
            scan.status = "failed"
            scan.error = str(exc)
            db.commit()
        result["runner_exception"] = str(exc)

    db.refresh(scan)
    result.update(archive_reports(db, scan, project_slug, mode, out_dir, formats))
    if cleanup_workspace:
        cleanup_project_workspace(project.id)
    result["seconds"] = round(time.time() - started, 1)
    result["finished_at"] = datetime.utcnow().isoformat() + "Z"
    write_json(meta_path, result)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run 20 GitHub projects in quick + deep modes.")
    parser.add_argument("--out", default="reports/github_20_quick_deep",
                        help="Output report directory relative to repo root.")
    parser.add_argument("--deep-max-candidates", type=int, default=10,
                        help="Max candidates sent to VerifyAgent for each deep scan.")
    parser.add_argument("--verify-workers", type=int, default=4,
                        help="VerifyAgent worker count for deep scans.")
    parser.add_argument("--limit", type=int, default=0,
                        help="Only run the first N targets, for smoke testing.")
    parser.add_argument("--force", action="store_true",
                        help="Re-run even if archived reports already exist.")
    parser.add_argument("--scan-timeout", type=int, default=600,
                        help="Parent-mode timeout in seconds for each project/mode child process.")
    parser.add_argument("--modes", default="quick,deep",
                        help="Comma-separated modes for parent runs: quick,standard,deep.")
    parser.add_argument("--formats", default="html,markdown,json",
                        help="Comma-separated report formats: html,markdown,json,pdf.")
    parser.add_argument("--cleanup-workspace", action="store_true",
                        help="Delete each cloned git workspace after report generation.")
    parser.add_argument("--single-target-index", type=int, default=0,
                        help=argparse.SUPPRESS)
    parser.add_argument("--single-mode", choices=["quick", "standard", "deep"], default=None,
                        help=argparse.SUPPRESS)
    return parser.parse_args()


def read_meta(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def mark_scan_timeout(scan_id: str | None, error: str) -> None:
    if not scan_id:
        return
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan and scan.status == "running":
            scan.status = "failed"
            scan.error = error
            scan.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def run_child_process(args: argparse.Namespace, target_index: int, mode: str,
                      root_out: Path, target: dict[str, str]) -> dict[str, Any]:
    project_slug = slugify(target["name"])
    meta_path = root_out / project_slug / f"{project_slug}_{mode}_scan_meta.json"
    done_marker = root_out / project_slug / f"{project_slug}_{mode}.html"
    if done_marker.exists() and meta_path.exists() and not args.force:
        payload = read_meta(meta_path) or {
            "project": target["name"], "url": target["url"], "mode": mode,
            "status": "unknown_existing",
        }
        payload["skipped_existing"] = True
        return payload

    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--out", args.out,
        "--deep-max-candidates", str(args.deep_max_candidates),
        "--verify-workers", str(args.verify_workers),
        "--formats", args.formats,
        "--single-target-index", str(target_index),
        "--single-mode", mode,
    ]
    if args.force:
        cmd.append("--force")
    if args.cleanup_workspace:
        cmd.append("--cleanup-workspace")

    try:
        subprocess.run(cmd, cwd=str(ROOT), check=False, timeout=args.scan_timeout)
    except subprocess.TimeoutExpired:
        error = f"scan timeout after {args.scan_timeout}s"
        payload = read_meta(meta_path) or {
            "project": target["name"],
            "url": target["url"],
            "mode": mode,
        }
        mark_scan_timeout(payload.get("scan_id"), error)
        payload.update({
            "status": "timeout",
            "error": error,
            "finished_at": datetime.utcnow().isoformat() + "Z",
        })
        write_json(meta_path, payload)
        return payload

    payload = read_meta(meta_path)
    if payload:
        return payload
    return {
        "project": target["name"],
        "url": target["url"],
        "mode": mode,
        "status": "missing_meta",
        "error": "child process finished without scan meta",
        "finished_at": datetime.utcnow().isoformat() + "Z",
    }


def main() -> int:
    # Keep report generation deterministic; AuditAgent/VerifyAgent behavior is
    # still controlled by the project's normal LLM settings.
    os.environ.setdefault("SUMMARY_AGENT_USE_LLM", "0")
    args = parse_args()
    init_db()
    root_out = (ROOT / args.out).resolve()
    root_out.mkdir(parents=True, exist_ok=True)

    targets = TARGETS[:args.limit] if args.limit and args.limit > 0 else TARGETS
    write_json(root_out / "target_manifest.json", targets)
    formats = tuple(x.strip() for x in args.formats.split(",") if x.strip())
    modes = tuple(x.strip() for x in args.modes.split(",") if x.strip())

    if args.single_target_index:
        target = TARGETS[args.single_target_index - 1]
        mode = args.single_mode or "quick"
        db = SessionLocal()
        try:
            row = run_one(
                db,
                target,
                mode,
                root_out,
                max_candidates=args.deep_max_candidates,
                workers=args.verify_workers,
                force=args.force,
                formats=formats,
                cleanup_workspace=args.cleanup_workspace,
            )
            print(json.dumps(row, ensure_ascii=False, default=str), flush=True)
        finally:
            db.close()
        return 0

    rows: list[dict[str, Any]] = []
    for index, target in enumerate(targets, start=1):
        print(f"\n[{index}/{len(targets)}] {target['name']}  {target['url']}", flush=True)
        for mode in modes:
            print(f"  -> {mode} scan", flush=True)
            row = run_child_process(args, index, mode, root_out, target)
            rows.append(row)
            status = row.get("status")
            findings = row.get("findings")
            seconds = row.get("seconds")
            skipped = " skipped" if row.get("skipped_existing") else ""
            error = f" error={row.get('error')}" if row.get("error") else ""
            print(f"     {status} findings={findings} seconds={seconds}{skipped}{error}", flush=True)
            write_json(root_out / "batch_summary.json", rows)

    write_json(root_out / "batch_summary.json", rows)
    print(f"\nDone. Reports archived under: {root_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

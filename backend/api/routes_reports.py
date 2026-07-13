"""Report generation and download routes."""
from __future__ import annotations

import json
import hashlib
import html
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.agents.summary_agent import SummaryAgent
from backend.core import ids
from backend.database import get_db
from backend.models import Evidence, Finding, Report, Scan
from backend.report import report_builder
from backend.schemas import ReportCreate, ReportOut
from backend.verifier.evidence_collector import is_persisted_validated_artifact

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("", response_model=ReportOut)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)) -> ReportOut:
    scan = db.get(Scan, payload.scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")

    project = scan.project
    meta = _decode_json(project.metadata_json) or {}
    rows = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    findings = []
    for f in rows:
        detail = _decode_json(f.detail_json) or {}
        verify_detail = detail.get("_verify") or {}
        evidence_rows = (db.query(Evidence)
                         .filter(Evidence.finding_id == f.id)
                         .order_by(Evidence.created_at.desc())
                         .all())
        evidence = _merge_evidence_rows(evidence_rows)
        raw_evidence = detail.get("_evidence") if isinstance(detail.get("_evidence"), dict) else {}
        if evidence is None and raw_evidence:
            evidence = dict(raw_evidence)
        elif evidence is not None and raw_evidence:
            _merge_missing(evidence, raw_evidence)
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
            "end_line": f.end_line,
            "line": f.start_line,
            "code_snippet": f.code_snippet,
            "confidence": f.confidence,
            "source": f.source,
            "verified": f.verified,
            "status": f.status,
            "fix_suggestion": f.fix_suggestion,
            "description": detail.get("description") or detail.get("message"),
            "rule_id": detail.get("rule_id") or detail.get("test_id"),
            "context": detail.get("context") or verify_detail.get("context"),
            "risk_modifier": detail.get("risk_modifier") or verify_detail.get("risk_modifier"),
            "downgrade_reason": detail.get("downgrade_reason") or verify_detail.get("downgrade_reason"),
            "false_positive_reason": detail.get("false_positive_reason") or verify_detail.get("false_positive_reason"),
            "confirmed_blockers": detail.get("confirmed_blockers") or verify_detail.get("confirmed_blockers") or [],
            "tool_calls": tool_calls,
            "evidence": evidence,
        })

    project_ctx = {
        "id": project.id,
        "name": project.name,
        "source_type": project.source_type,
        "url": project.url,
        "local_path": project.local_path,
        "branch": project.branch,
        "languages": meta.get("languages", []),
        "frameworks": meta.get("frameworks", []),
        "file_count": meta.get("file_count", 0),
        "loc": meta.get("loc", 0),
    }
    scan_ctx = {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "progress": scan.progress,
        "current_stage": scan.current_stage,
        "error": scan.error,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "config": _decode_json(scan.config_json) or {},
    }
    stats = report_builder.severity_stats(findings)
    summary = SummaryAgent(scan_id=scan.id).run(project_ctx, scan_ctx, findings, stats)

    rid = ids.report_id()
    try:
        fp = report_builder.generate(
            project_ctx, scan_ctx, findings, summary, fmt=payload.format,
            report_id=rid,
            options={"include_poc": payload.include_poc, "include_fix": payload.include_fix},
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    report = Report(id=rid, scan_id=scan.id, format=payload.format, file_path=str(fp))
    try:
        _write_poc_manifest(report, findings, include_poc=payload.include_poc)
    except OSError as exc:
        raise HTTPException(503, "unable to secure generated report artifact") from exc
    db.add(report)
    db.commit()
    return ReportOut(report_id=rid, status="generated",
                     download_url=f"/api/reports/{rid}/download")


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report or not report.file_path:
        raise HTTPException(404, "report not found")
    path = Path(report.file_path)
    if not path.is_file():
        raise HTTPException(404, "report artifact not found")
    revoke_reason = _report_poc_revoke_reason(db, report, path)
    if revoke_reason:
        raise HTTPException(410, revoke_reason)
    return FileResponse(str(path), filename=path.name)


def _decode_json(value: str | None):
    return json.loads(value or "null")


def _decode_report_evidence(ev: Evidence) -> dict:
    poc = _decode_json(ev.poc_result)
    if isinstance(poc, dict) and ("exploit" in poc or "runtime" in poc):
        exploit = poc.get("exploit")
        attack_plan = poc.get("attack_plan")
        runtime = poc.get("runtime")
        call_path = poc.get("call_path")
        harness = poc.get("harness")
        sandbox = poc.get("sandbox")
        poc_result = poc.get("poc_result")
        tool_calls = poc.get("tool_calls")
        static_evidence_chain = poc.get("static_evidence_chain")
        verification = poc.get("verification")
        knowledge = poc.get("knowledge")
        artifacts = poc.get("artifacts")
        poc_file = poc.get("poc_file")
    else:
        exploit = None
        attack_plan = None
        runtime = None
        call_path = None
        harness = None
        sandbox = None
        poc_result = poc
        tool_calls = None
        static_evidence_chain = None
        verification = None
        knowledge = None
        artifacts = None
        poc_file = None
    if sandbox is None and isinstance(runtime, dict):
        sandbox = runtime.get("sandbox")
    return {
        "source": _decode_json(ev.source),
        "sink": _decode_json(ev.sink),
        "data_flow": _decode_json(ev.data_flow),
        "call_path": call_path,
        "exploit": exploit,
        "attack_plan": attack_plan,
        "runtime": runtime,
        "harness": harness,
        "sandbox": sandbox,
        "poc_result": poc_result,
        "tool_calls": tool_calls or [],
        "static_evidence_chain": static_evidence_chain or {},
        "verification": verification or {},
        "knowledge": knowledge or {},
        "artifacts": artifacts or {},
        "poc_file": poc_file,
        "logs": _decode_json(ev.logs),
    }


def _merge_evidence_rows(rows: list[Evidence]) -> dict | None:
    merged: dict = {}
    for row in rows:
        _merge_missing(merged, _decode_report_evidence(row))
    return merged or None


def _merge_missing(target: dict, source: dict) -> dict:
    for key, value in source.items():
        if key not in target or target[key] in (None, "", [], {}):
            target[key] = value
        elif isinstance(target[key], dict) and isinstance(value, dict):
            _merge_missing(target[key], value)
    return target


_POC_CODE_KEYS = {"code", "exploit_code", "harness_code"}


def _manifest_path(report: Report, path: Path | None = None) -> Path:
    artifact = path or Path(report.file_path or "")
    return artifact.with_name(f".{report.id}.poc-manifest.json")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _poc_code_values(value) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for key, item in value.items():
            if str(key).lower() in _POC_CODE_KEYS and isinstance(item, str) and item.strip():
                values.append(item)
            else:
                values.extend(_poc_code_values(item))
        return values
    if isinstance(value, list):
        return [code for item in value for code in _poc_code_values(item)]
    return []


def _poc_codes_from_evidence(evidence: dict | None) -> list[str]:
    evidence = evidence or {}
    return _poc_code_values({
        key: evidence.get(key) for key in ("exploit", "attack_plan", "harness", "poc_result")
    })


def _artifact_hashes(evidence: dict | None) -> list[str]:
    hashes: list[str] = []
    for artifact in ((evidence or {}).get("artifacts") or {}).values():
        if is_persisted_validated_artifact(artifact) and not artifact.get("revoked_by_finding_status"):
            hashes.append(str(artifact["sha256"]))
    return hashes


def _write_poc_manifest(report: Report, findings: list[dict], *, include_poc: bool) -> None:
    """Bind executable report content to the report ID and artifact bytes.

    The manifest is deliberately not a download authority: it is revalidated on
    every download against the current finding and persisted artifact state.
    """
    path = Path(report.file_path or "")
    poc_findings = {}
    if include_poc:
        for finding in findings:
            evidence = finding.get("evidence") if isinstance(finding, dict) else None
            codes = _poc_codes_from_evidence(evidence)
            if codes:
                poc_findings[str(finding.get("finding_id"))] = {
                    "code_sha256": sorted({hashlib.sha256(code.encode("utf-8")).hexdigest() for code in codes}),
                    "artifact_sha256": sorted(set(_artifact_hashes(evidence))),
                }
    _manifest_path(report, path).write_text(json.dumps({
        "version": 1,
        "report_id": report.id,
        "artifact_sha256": _file_sha256(path),
        "poc_findings": poc_findings,
    }, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _read_poc_manifest(report: Report, path: Path) -> dict | None:
    try:
        data = json.loads(_manifest_path(report, path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("report_id") != report.id:
        return None
    if data.get("artifact_sha256") != _file_sha256(path):
        return None
    if not isinstance(data.get("poc_findings"), dict):
        return None
    return data


def _finding_evidence_rows(db: Session, finding_id: str) -> list[Evidence]:
    return (db.query(Evidence).filter(Evidence.finding_id == finding_id)
            .order_by(Evidence.created_at.desc()).all())


def _finding_has_valid_artifact(db: Session, finding: Finding,
                                expected_hashes: list[str] | None = None) -> bool:
    if finding.status != "confirmed" or not finding.verified:
        return False
    allowed = set(expected_hashes or [])
    for evidence in _finding_evidence_rows(db, finding.id):
        for artifact_hash in _artifact_hashes(_decode_report_evidence(evidence)):
            if not allowed or artifact_hash in allowed:
                return True
    return False


def _legacy_report_poc_findings(db: Session, report: Report, path: Path) -> dict[str, list[str]]:
    """Identify executable PoC fragments in reports generated before manifests.

    Text formats are matched against the retained historical evidence.  PDFs
    cannot be safely parsed here, so any historical executable evidence is
    treated as present rather than risk releasing a compressed old PoC.
    """
    raw = path.read_bytes()
    text = html.unescape(raw.decode("utf-8", errors="ignore"))
    is_pdf = path.suffix.lower() == ".pdf"
    found: dict[str, list[str]] = {}
    for finding in db.query(Finding).filter(Finding.scan_id == report.scan_id).all():
        codes = [code for row in _finding_evidence_rows(db, finding.id)
                 for code in _poc_codes_from_evidence(_decode_report_evidence(row))]
        if codes and (is_pdf or any(code in text for code in codes)):
            found[finding.id] = _artifact_hashes(
                _decode_report_evidence(_finding_evidence_rows(db, finding.id)[0])
            ) if _finding_evidence_rows(db, finding.id) else []
    return found


def _report_poc_revoke_reason(db: Session, report: Report, path: Path) -> str | None:
    manifest = _read_poc_manifest(report, path)
    if manifest is not None:
        poc_findings = {
            str(finding_id): list(metadata.get("artifact_sha256") or [])
            for finding_id, metadata in manifest["poc_findings"].items()
            if isinstance(metadata, dict)
        }
    else:
        poc_findings = _legacy_report_poc_findings(db, report, path)

    for finding_id, artifact_hashes in poc_findings.items():
        finding = db.get(Finding, finding_id)
        if not finding or finding.scan_id != report.scan_id:
            return "report_poc_revoked: referenced finding is unavailable"
        if finding.status != "confirmed" or not finding.verified:
            return "report_poc_revoked: finding is no longer confirmed"
        if not _finding_has_valid_artifact(db, finding, artifact_hashes):
            return "report_poc_revoked: validated artifact is no longer available"
    return None

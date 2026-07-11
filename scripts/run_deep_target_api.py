"""Run one Git repository through AuditAgentX's formal Deep scan HTTP API.

This driver does not start AuditAgentX, Docker, or a scan target itself.  It
expects an already-running API and submits exactly one project and one scan.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parent.parent
TERMINAL_STATES = {"done", "finished", "failed", "cancelled", "partial_completed"}
SUCCESS_STATES = {"done", "finished", "partial_completed"}
REDACTED = "[REDACTED]"
_SECRET_KEY_PARTS = {
    "authorization", "cookie", "password", "passwd", "privatekey", "secret",
    "token", "apikey", "accesskey", "clientsecret", "credential",
}
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+\-/=]+")
_KEYLIKE_RE = re.compile(r"\b(?:sk|pk|ghp|github_pat)-[A-Za-z0-9_-]{8,}\b", re.I)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret)"
    r"\b[\"']?\s*[:=]\s*[\"']?)([^\s,;\"'&}]+)"
)


class ApiError(RuntimeError):
    """The AuditAgentX API returned an invalid or unsuccessful response."""


class PollingError(RuntimeError):
    """A scan polling response did not satisfy the API contract."""


class CleanupSafetyError(RuntimeError):
    """Workspace cleanup was refused because its safety checks failed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_secret_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return value
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        netloc = f"{hostname}{port}"
        query = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            query.append((key, REDACTED if _is_secret_key(key) else item))
        return urlunsplit((parsed.scheme, netloc, parsed.path, urlencode(query), parsed.fragment))
    except ValueError:
        return value


def _redact_string(value: str) -> str:
    sanitized = _BEARER_RE.sub(f"Bearer {REDACTED}", value)
    sanitized = _KEYLIKE_RE.sub(REDACTED, sanitized)
    sanitized = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}{REDACTED}", sanitized)
    if sanitized.startswith(("http://", "https://")):
        sanitized = _redact_url(sanitized)
    return sanitized


def redact_secrets(value: Any) -> Any:
    """Return a recursively redacted, JSON-compatible copy of ``value``."""
    if isinstance(value, dict):
        return {
            str(key): REDACTED if _is_secret_key(key) else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


class ApiClient:
    """Small JSON client using only the Python standard library."""

    def __init__(self, api_base: str, timeout: float = 30.0) -> None:
        parsed = urlsplit(api_base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("--api-base must be an absolute http(s) URL")
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self._opener = build_opener(ProxyHandler({}))

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.api_base}/{path.lstrip('/')}"
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(url, data=body, headers=headers, method=method.upper())
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except HTTPError as exc:
            raw = exc.read()
            detail = raw.decode("utf-8", errors="replace")[:2000]
            raise ApiError(f"{method} {path} returned HTTP {exc.code}: {_redact_string(detail)}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ApiError(f"{method} {path} failed: {_redact_string(str(exc))}") from exc
        if not 200 <= status < 300:
            raise ApiError(f"{method} {path} returned HTTP {status}")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(f"{method} {path} returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise ApiError(f"{method} {path} returned a non-object JSON response")
        return decoded

    def get(self, path: str) -> dict[str, Any]:
        return self.request("GET", path)

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.request("POST", path, payload)


def poll_scan_terminal(
    fetch_status: Callable[[], dict[str, Any]],
    *,
    poll_interval: float,
    overall_timeout: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Poll until a documented terminal state or the overall deadline."""
    if poll_interval < 0 or overall_timeout <= 0:
        raise ValueError("poll interval must be non-negative and overall timeout must be positive")
    started = monotonic()
    last_status = "<none>"
    while True:
        response = fetch_status()
        if not isinstance(response, dict) or not isinstance(response.get("status"), str):
            raise PollingError("scan polling response must contain a string status")
        last_status = response["status"].strip().lower()
        if last_status in TERMINAL_STATES:
            return response
        if monotonic() - started >= overall_timeout:
            raise TimeoutError(
                f"scan did not reach a terminal state within {overall_timeout:g}s; "
                f"last status={last_status}"
            )
        sleep(poll_interval)


def _default_strategy_resolver(vulnerability_type: str | None) -> dict[str, Any]:
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from backend.dynamic.strategy import resolve_strategy

        return resolve_strategy(vulnerability_type)
    except Exception as exc:  # optional enrichment must not break result collection
        return {"strategy": "unknown", "reason": f"strategy resolver unavailable: {exc}"}


def _evidence_value(bundle: dict[str, Any]) -> dict[str, Any]:
    value = bundle.get("evidence") or {}
    if isinstance(value, dict) and "evidence" in value:
        value = value.get("evidence") or {}
    return value if isinstance(value, dict) else {}


def _finding_value(bundle: dict[str, Any]) -> dict[str, Any]:
    value = bundle.get("finding") or bundle
    return value if isinstance(value, dict) else {}


def _http_record_executed(record: Any, *, assumed_role: str | None = None) -> bool:
    if not isinstance(record, dict):
        return False
    role = str(record.get("role") or assumed_role or "").lower()
    if role not in {"attack", "confirmation"}:
        return False
    has_request = bool(record.get("url") and record.get("method"))
    has_outcome = (
        record.get("status_code") is not None
        or record.get("status") is not None
        or bool(record.get("error"))
        or record.get("elapsed_ms") is not None
    )
    return has_request and has_outcome


def _strict_http_executed(runtime: dict[str, Any]) -> bool:
    if any(_http_record_executed(record) for record in runtime.get("records") or []):
        return True
    return any(
        _http_record_executed(record, assumed_role="confirmation")
        for record in runtime.get("confirmation_records") or []
    )


def aggregate_metrics(
    findings: list[dict[str, Any]],
    scan_status: dict[str, Any],
    *,
    strategy_resolver: Callable[[str | None], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate scan metrics without network, database, or filesystem access."""
    resolver = strategy_resolver or _default_strategy_resolver
    sandbox_status: Counter[str] = Counter()
    harness_verdict: Counter[str] = Counter()
    strategy_counts: Counter[str] = Counter()
    eligible_not_applicable = 0
    eligible_dynamic = 0
    strict_http_ids: list[str] = []
    blocked = not_reproduced = dynamic_confirmed = 0
    problems: list[str] = []
    errors: list[str] = []
    strategy_by_finding: dict[str, dict[str, Any]] = {}

    for bundle in findings:
        finding = _finding_value(bundle)
        evidence = _evidence_value(bundle)
        finding_id = str(finding.get("finding_id") or "<unknown>")
        vulnerability_type = finding.get("type")
        try:
            strategy = resolver(vulnerability_type)
            if not isinstance(strategy, dict):
                raise TypeError("resolver returned a non-object")
        except Exception as exc:
            strategy = {"strategy": "unknown", "reason": str(exc)}
        strategy_name = str(strategy.get("strategy") or "unknown")
        strategy_counts[strategy_name] += 1
        strategy_by_finding[finding_id] = strategy
        finding_status = str(finding.get("status") or "").lower()
        if not finding_status or finding_status in {"confirmed", "needs_review"}:
            if strategy_name == "not_applicable":
                eligible_not_applicable += 1
            else:
                eligible_dynamic += 1

        runtime = evidence.get("runtime") or {}
        if not isinstance(runtime, dict):
            runtime = {}
        status = str(runtime.get("reproduction_status") or "")
        if status == "blocked":
            blocked += 1
        if status == "not_reproduced":
            not_reproduced += 1
        if status == "dynamic_confirmed" and runtime.get("reproducible") is True:
            dynamic_confirmed += 1
        if _strict_http_executed(runtime):
            strict_http_ids.append(finding_id)

        sandbox = evidence.get("sandbox") or runtime.get("sandbox") or {}
        if isinstance(sandbox, dict) and sandbox:
            sandbox_status[str(sandbox.get("status") or "unknown")] += 1
        harness = evidence.get("harness") or {}
        if isinstance(harness, dict) and harness:
            harness_verdict[str(harness.get("verdict") or "not_executed")] += 1

        reason = runtime.get("reason") or runtime.get("error")
        if reason:
            problems.append(f"{finding_id}: {reason}")
        if runtime.get("error"):
            errors.append(f"{finding_id}: {runtime['error']}")
        if isinstance(harness, dict) and harness.get("verdict") in {
            "sandbox_failed", "unsafe_harness_blocked", "target_blocked",
        }:
            detail = harness.get("reason") or harness.get("verdict")
            problems.append(f"{finding_id}: harness {detail}")

    stage_detail = scan_status.get("stage_detail") or {}
    if not isinstance(stage_detail, dict):
        stage_detail = {}
    scan_error = scan_status.get("error")
    if scan_error:
        errors.append(f"scan: {scan_error}")
        problems.append(f"scan: {scan_error}")
    for scanner in stage_detail.get("scanner_status") or []:
        if isinstance(scanner, dict) and scanner.get("error"):
            name = scanner.get("tool") or scanner.get("name") or "scanner"
            errors.append(f"{name}: {scanner['error']}")

    runtime_dynamic_total = stage_detail.get("dynamic_total")
    dynamic_candidates = (
        runtime_dynamic_total
        if isinstance(runtime_dynamic_total, int) and runtime_dynamic_total >= 0
        else eligible_dynamic
    )
    return {
        "raw_static_count": stage_detail.get("raw_finding_count"),
        "persisted_findings": len(findings),
        "dynamic_candidates": dynamic_candidates,
        "not_applicable": eligible_not_applicable,
        "strategy_counts": dict(strategy_counts),
        "strategy_by_finding": strategy_by_finding,
        "project_sandbox_status": stage_detail.get("dynamic_target_status"),
        "sandbox_status": dict(sandbox_status),
        "strict_http_executed": len(strict_http_ids),
        "strict_http_executed_finding_ids": strict_http_ids,
        "blocked": blocked,
        "not_reproduced": not_reproduced,
        "dynamic_confirmed": dynamic_confirmed,
        "harness_verdict": dict(harness_verdict),
        "elapsed_seconds": stage_detail.get("elapsed_seconds"),
        "problems": list(dict.fromkeys(problems)),
        "errors": list(dict.fromkeys(errors)),
    }


def cleanup_project_workspace(
    project_data_dir: str | Path,
    project_id: str,
    *,
    protected_paths: list[str | Path] | None = None,
) -> bool:
    """Delete only ``<project_data_dir>/<project_id>`` after strict checks."""
    root = Path(project_data_dir).resolve()
    raw_id = Path(str(project_id))
    if not project_id or raw_id.name != project_id or project_id in {".", ".."}:
        raise CleanupSafetyError("project_id must be one plain path component")
    candidate = root / project_id
    if candidate.is_symlink():
        raise CleanupSafetyError("refusing to remove a symlink workspace")
    target = candidate.resolve()
    if target.parent != root or target.name != project_id or target == root:
        raise CleanupSafetyError("workspace is not the immediate matching child of project_data_dir")
    for protected in protected_paths or []:
        protected_path = Path(protected).resolve()
        if protected_path == target or target in protected_path.parents:
            raise CleanupSafetyError("workspace contains a protected output path")
    if not target.exists():
        return False
    if not target.is_dir():
        raise CleanupSafetyError("workspace target is not a directory")
    def _remove_readonly(func: Callable[..., Any], path: str, _exc_info: Any) -> None:
        """Allow cleanup of Git pack files marked read-only on Windows."""
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except OSError:
            # rmtree will re-raise the original failure if this retry cannot remove it.
            raise

    shutil.rmtree(target, onerror=_remove_readonly)
    if target.exists():
        raise CleanupSafetyError("workspace removal did not complete")
    return True


def _configured_project_data_dir() -> Path:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from backend.config import settings

    return settings.workspace_path.resolve()


def _metadata_commit(metadata: dict[str, Any]) -> str | None:
    for key in ("commit", "commit_sha", "git_commit", "revision", "head_commit"):
        value = metadata.get(key)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", value.strip()):
            return value.strip()
    return None


def _safe_workspace_commit(project_data_dir: Path, project_id: str) -> str | None:
    try:
        root = project_data_dir.resolve()
        workspace = (root / project_id).resolve()
        if workspace.parent != root or workspace.name != project_id or workspace.is_symlink():
            return None
        if not (workspace / ".git").exists():
            return None
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(workspace),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            creationflags=creation_flags,
        )
        if result.returncode != 0:
            return None
        commit = result.stdout.decode("ascii", errors="ignore").strip()
        return commit if re.fullmatch(r"[0-9a-fA-F]{40,64}", commit) else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _collect_findings(client: ApiClient, scan_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    listing = client.get(f"/api/scans/{scan_id}/findings")
    rows = listing.get("findings")
    if not isinstance(rows, list):
        raise ApiError("scan findings response must contain a findings list")
    collected: list[dict[str, Any]] = []
    errors: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("finding_id"):
            errors.append("finding listing contained an invalid row")
            continue
        finding_id = str(row["finding_id"])
        bundle: dict[str, Any] = {"finding": row, "detail": None, "evidence": None}
        try:
            bundle["detail"] = client.get(f"/api/findings/{finding_id}")
        except ApiError as exc:
            errors.append(f"{finding_id} detail: {exc}")
        try:
            evidence_response = client.get(f"/api/findings/{finding_id}/evidence")
            bundle["evidence"] = evidence_response.get("evidence")
            bundle["evidence_message"] = evidence_response.get("message")
        except ApiError as exc:
            errors.append(f"{finding_id} evidence: {exc}")
        collected.append(bundle)
    return collected, errors


def _write_result(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(redact_secrets(payload), ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _parse_tools(value: str) -> list[str]:
    tools = [item.strip() for item in value.split(",") if item.strip()]
    if not tools:
        raise argparse.ArgumentTypeError("at least one enabled tool is required")
    return tools


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit exactly one Git project to AuditAgentX's Deep scan HTTP API.",
    )
    parser.add_argument("--api-base", required=True, help="Existing AuditAgentX API base URL.")
    parser.add_argument("--name", required=True, help="Project display name.")
    parser.add_argument("--repo-url", required=True, help="Git repository URL.")
    parser.add_argument("--branch", help="Optional Git branch; API default/fallback is used when omitted.")
    parser.add_argument("--output", required=True, type=Path, help="Destination JSON result path.")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between status polls.")
    parser.add_argument("--overall-timeout", type=float, default=3600.0, help="Maximum polling duration.")
    parser.add_argument(
        "--request-timeout", "--poll-timeout", dest="request_timeout", type=float, default=30.0,
        help="Timeout for each API request, including each poll.",
    )
    parser.add_argument(
        "--enabled-tools", type=_parse_tools,
        default=_parse_tools("semgrep,bandit,gitleaks,trivy"),
        help="Comma-separated static tools.",
    )
    parser.add_argument(
        "--cleanup-workspace", action="store_true",
        help="Remove only data/projects/<returned project_id>; never removes Docker or database data.",
    )
    args = parser.parse_args(argv)
    if args.poll_interval < 0 or args.overall_timeout <= 0 or args.request_timeout <= 0:
        parser.error("timeouts must be positive and poll interval must be non-negative")
    return args


def run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    output = args.output.resolve()
    result: dict[str, Any] = {
        "schema_version": 1,
        "driver": "AuditAgentX single-target Deep HTTP API runner",
        "started_at": _utc_now(),
        "input": {
            "api_base": args.api_base,
            "name": args.name,
            "repo_url": args.repo_url,
            "branch": args.branch,
            "enabled_tools": args.enabled_tools,
            "poll_interval_seconds": args.poll_interval,
            "overall_timeout_seconds": args.overall_timeout,
            "request_timeout_seconds": args.request_timeout,
        },
        "project": None,
        "scan": None,
        "project_metadata": {},
        "repo_commit": None,
        "findings": [],
        "metrics": {},
        "problems": [],
        "errors": [],
        "cleanup": {"requested": bool(args.cleanup_workspace), "removed": False},
    }
    project_id: str | None = None
    exit_code = 1
    try:
        client = ApiClient(args.api_base, timeout=args.request_timeout)
        project_payload: dict[str, Any] = {
            "name": args.name,
            "source_type": "git",
            "url": args.repo_url,
        }
        if args.branch:
            project_payload["branch"] = args.branch
        project = client.post("/api/projects", project_payload)
        project_id = project.get("project_id")
        if not isinstance(project_id, str) or not project_id:
            raise ApiError("project creation response did not contain project_id")
        result["project"] = project

        scan_payload = {
            "project_id": project_id,
            "scan_type": "full",
            "scan_mode": "deep",
            "enabled_tools": args.enabled_tools,
            "options": {
                "dynamic_target": {
                    "mode": "docker_project",
                    "auto_start_docker": True,
                }
            },
        }
        scan_created = client.post("/api/scans", scan_payload)
        scan_id = scan_created.get("scan_id")
        if not isinstance(scan_id, str) or not scan_id:
            raise ApiError("scan creation response did not contain scan_id")
        result["scan_created"] = scan_created
        scan_status = poll_scan_terminal(
            lambda: client.get(f"/api/scans/{scan_id}"),
            poll_interval=args.poll_interval,
            overall_timeout=args.overall_timeout,
        )
        result["scan"] = scan_status

        try:
            metadata_response = client.get(f"/api/projects/{project_id}/tree")
            result["project_metadata"] = metadata_response
        except ApiError as exc:
            result["problems"].append(f"project metadata: {exc}")

        findings, collection_errors = _collect_findings(client, scan_id)
        result["findings"] = findings
        result["errors"].extend(collection_errors)
        metrics = aggregate_metrics(findings, scan_status)
        result["metrics"] = metrics
        result["problems"].extend(metrics["problems"])
        result["errors"].extend(metrics["errors"])

        metadata = result["project_metadata"] if isinstance(result["project_metadata"], dict) else {}
        commit = _metadata_commit(metadata)
        project_data_dir: Path | None = None
        if not commit:
            try:
                project_data_dir = _configured_project_data_dir()
                commit = _safe_workspace_commit(project_data_dir, project_id)
            except Exception as exc:
                result["problems"].append(f"workspace commit unavailable: {exc}")
        result["repo_commit"] = commit
        exit_code = 0 if str(scan_status.get("status")).lower() in SUCCESS_STATES else 2

        if args.cleanup_workspace:
            try:
                project_data_dir = project_data_dir or _configured_project_data_dir()
                result["cleanup"].update({
                    "project_data_dir": str(project_data_dir),
                    "project_id": project_id,
                    "removed": cleanup_project_workspace(
                        project_data_dir, project_id, protected_paths=[output],
                    ),
                    "docker_cleanup": "not_implemented",
                })
            except (CleanupSafetyError, OSError, RuntimeError) as exc:
                result["cleanup"]["error"] = str(exc)
                result["errors"].append(f"workspace cleanup refused/failed: {exc}")
                exit_code = max(exit_code, 3)
    except (ApiError, PollingError, TimeoutError, ValueError) as exc:
        result["errors"].append(str(exc))
    finally:
        result["finished_at"] = _utc_now()
        result["problems"] = list(dict.fromkeys(result["problems"]))
        result["errors"] = list(dict.fromkeys(result["errors"]))
        _write_result(output, result)
    return redact_secrets(result), exit_code


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result, exit_code = run(args)
    summary = {
        "output": str(args.output.resolve()),
        "project_id": (result.get("project") or {}).get("project_id"),
        "scan_id": (result.get("scan") or result.get("scan_created") or {}).get("scan_id"),
        "status": (result.get("scan") or {}).get("status"),
        "errors": result.get("errors") or [],
    }
    print(json.dumps(redact_secrets(summary), ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

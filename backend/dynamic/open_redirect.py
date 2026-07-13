"""Source-bound request planning for local Open Redirect verification."""
from __future__ import annotations

import re
import secrets
import ipaddress
from urllib.parse import urlparse

from backend.dynamic.source_route_binding import is_server_bound_surface

_OPEN_REDIRECT = re.compile(r"(?:open[\s_-]*redirect|unvalidated[\s_-]*redirect|cwe[\s_-]*601)", re.I)
_PAYLOAD_PATH = re.compile(r"/__auditagentx_redirect/[A-Za-z0-9_-]+\Z")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def is_open_redirect_type(vuln_type: object) -> bool:
    """Recognize the narrowly scoped Open Redirect family only."""
    return bool(_OPEN_REDIRECT.search(str(vuln_type or "")))


def build_open_redirect_plan(finding: dict, base_url: str | None, endpoints: list[dict] | None,
                             *, nonce: str | None = None) -> tuple[dict | None, str, str]:
    """Create one safe, source-bound redirect probe without consulting an LLM."""
    if not is_open_redirect_type(finding.get("type") or finding.get("vuln_type")):
        return None, "not_applicable", "finding is not an Open Redirect"
    candidates, status, reason = _bound_candidates(base_url, endpoints)
    if status != "ready":
        return None, status, reason
    token = str(nonce or secrets.token_urlsafe(18)).rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", token):
        return None, "not_applicable", "Open Redirect nonce is invalid"
    path, method, param, transport = candidates[0]
    return {
        "path": path,
        "method": method,
        "param": param,
        "transport": transport,
        "payload": _local_redirect_canary(base_url, token),
    }, "ready", ""


def validate_open_redirect_plan(vuln_type: object, base_url: str | None, endpoints: list[dict] | None,
                                plan: object) -> tuple[dict | None, str, str]:
    """Accept only a plan that exactly matches a current server-bound surface."""
    if not is_open_redirect_type(vuln_type):
        return None, "not_applicable", "finding is not an Open Redirect"
    candidates, status, reason = _bound_candidates(base_url, endpoints)
    if status != "ready":
        return None, status, reason
    if not isinstance(plan, dict):
        return None, "not_applicable", "Open Redirect request plan is missing"
    payload = str(plan.get("payload") or "")
    candidate = (
        str(plan.get("path") or ""),
        str(plan.get("method") or "").upper(),
        str(plan.get("param") or ""),
        str(plan.get("transport") or "").lower(),
    )
    if candidate not in candidates or not _is_local_redirect_canary(base_url, payload):
        return None, "endpoint_unresolved", "Open Redirect request plan no longer matches server-bound route parameters"
    return {
        "path": candidate[0], "method": candidate[1], "param": candidate[2],
        "transport": candidate[3], "payload": payload,
    }, "ready", ""


def _bound_candidates(base_url: str | None, endpoints: list[dict] | None) -> tuple[list[tuple[str, str, str, str]], str, str]:
    if not _is_literal_loopback_base_url(base_url):
        return [], "not_applicable", "Open Redirect HTTP verification requires a local sandbox base_url"
    if not isinstance(endpoints, list) or not endpoints:
        return [], "endpoint_unresolved", "Open Redirect has no server-bound endpoint"
    if not all(is_server_bound_surface(surface) for surface in endpoints):
        return [], "endpoint_unresolved", "Open Redirect endpoint binding was not minted by the server"

    candidates: set[tuple[str, str, str, str]] = set()
    for surface in endpoints:
        path = str(surface.get("path") or "")
        if not path.startswith("/") or path.startswith("//"):
            return [], "endpoint_unresolved", "Open Redirect endpoint is not project-relative"
        methods = [str(method).upper() for method in (surface.get("methods") or [])]
        params = surface.get("params") or []
        for method in methods:
            if method not in _METHODS:
                continue
            for parameter in params:
                if not isinstance(parameter, dict):
                    continue
                name = str(parameter.get("name") or "")
                transport = _transport_for_bound_parameter(method, parameter.get("location"))
                if name and transport:
                    candidates.add((path, method, name, transport))
    if len(candidates) != 1:
        return [], "endpoint_unresolved", "Open Redirect requires one unambiguous server-extracted parameter"
    return sorted(candidates), "ready", ""


def _is_literal_loopback_base_url(base_url: str | None) -> bool:
    """Accept sandbox loopback origins without resolving external hostnames."""
    parsed = urlparse(str(base_url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _local_redirect_canary(base_url: str, token: str) -> str:
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}/__auditagentx_redirect/{token}"


def _is_local_redirect_canary(base_url: str | None, payload: str) -> bool:
    if not _is_literal_loopback_base_url(base_url):
        return False
    base, target = urlparse(str(base_url)), urlparse(payload)
    return bool(
        target.scheme == base.scheme and target.netloc == base.netloc
        and not target.query and not target.fragment and _PAYLOAD_PATH.fullmatch(target.path or "")
    )
def _transport_for_bound_parameter(method: str, location: object) -> str:
    value = str(location or "").lower()
    if method == "GET":
        return "query" if value == "query" else ""
    if value == "query":
        return "query"
    if value == "json":
        return "json"
    if value in {"form", "body"}:
        return "form"
    return ""

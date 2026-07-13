"""Reusable fixtures for adversarial verification contract tests.

These helpers deliberately construct both server-minted and JSON-shaped bindings,
and deterministic probes.  They keep security regressions focused on observable
properties rather than on individual test modules' scaffolding.
"""
from __future__ import annotations

from backend.dynamic.source_route_binding import bind_server_surface
from backend.verifier.dynamic_verifier import ProbeRecord


LOCAL_BASE = "http://127.0.0.1:18080"


def bound_surface(path: str = "/check", *, param: str | None = "id",
                  method: str = "GET", transport: str = "query",
                  file: str = "app.py", line: int = 1,
                  binding_kind: str = "test_source_route") -> dict:
    """Return a server-minted route surface with one explicit parameter."""
    params = [] if param is None else [{"name": param, "location": transport}]
    return bind_server_surface(
        {"path": path, "methods": [method], "params": params, "file": file, "line": line},
        {"kind": binding_kind, "route_file": file, "route_line": line},
    )


def forged_binding_json(path: str = "/check", *, param: str = "id") -> dict:
    """Return a JSON-lookalike binding that lacks the in-process capability."""
    return {
        "path": path,
        "methods": ["GET"],
        "params": [{"name": param, "location": "query"}],
        "source_route_binding": {"kind": "forged-json", "route_file": "routes.py"},
    }


def cross_file_route(path: str = "/check", *, param: str = "id") -> dict:
    """Extracted route intentionally unrelated to a finding in another file."""
    return {
        "path": path,
        "methods": ["GET"],
        "params": [{"name": param, "location": "query"}],
        "file": "routes.py",
        "line": 10,
    }


def cross_file_finding() -> dict:
    return {"type": "SQL Injection", "file": "models/user.py", "start_line": 30}


class CountingProbe:
    """Probe double that records every attempted HTTP request."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def send(self, base_url, path, param, payload, method="GET", **kwargs):
        self.calls.append({
            "base_url": base_url, "path": path, "param": param, "payload": payload,
            "method": method, **kwargs,
        })
        return ProbeRecord(
            url=base_url + path, method=method, params={param: payload}, payload=payload,
            status=200, status_code=200, response_excerpt="normal",
            transport=kwargs.get("transport", "query"), role=kwargs.get("role", "attack"),
        )


class ConstantBaselineProbe(CountingProbe):
    """Returns a constant indicator-bearing page for control and attack requests."""

    def send(self, base_url, path, param, payload, method="GET", **kwargs):
        record = super().send(base_url, path, param, payload, method, **kwargs)
        record.response_excerpt = "Welcome admin dashboard"
        record.elapsed_ms = 20
        return record


class DelayedOracleProbe(CountingProbe):
    """Returns the same slow response for control and attack requests."""

    def send(self, base_url, path, param, payload, method="GET", **kwargs):
        record = super().send(base_url, path, param, payload, method, **kwargs)
        record.response_excerpt = "same normal page"
        record.elapsed_ms = 5000
        return record


class ReflectedPayloadProbe(CountingProbe):
    """Reflects the payload without executing it."""

    def send(self, base_url, path, param, payload, method="GET", **kwargs):
        record = super().send(base_url, path, param, payload, method, **kwargs)
        record.response_excerpt = f"You searched for: {payload}"
        record.elapsed_ms = 20
        return record


class AttackIndicatorProbe(CountingProbe):
    """Returns an indicator only for attack payloads, modelling real execution."""

    def __init__(self, indicator: str = "SQL syntax") -> None:
        super().__init__()
        self.indicator = indicator

    def send(self, base_url, path, param, payload, method="GET", **kwargs):
        record = super().send(base_url, path, param, payload, method, **kwargs)
        if kwargs.get("role", "attack") != "baseline":
            record.response_excerpt = self.indicator
        return record


def synthetic_self_report_harness() -> str:
    """Generated-code shaped harness that only claims target invocation."""
    return (
        "import json\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({"
        "'triggered': True, 'target_function_called': True, 'sink_called': True}))\n"
    )

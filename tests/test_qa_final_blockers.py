"""Final QA blockers: trusted source-route binding and PoC revocation."""
from __future__ import annotations

import json

from backend.dynamic.authorization_planner import plan_authorization_workflow
from backend.report import report_builder
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord
from backend.verifier.evidence_collector import apply_product_evidence_policy
from backend.verifier.pipeline import _surfaces_for_finding


def _bola_finding() -> dict:
    return {
        "finding_id": "f-qa-bola", "type": "Broken Object Level Authorization",
        "severity": "high", "file": "api/books.py", "start_line": 30,
    }


def _bola_surfaces() -> list[dict]:
    return [
        {"path": "/users/register", "methods": ["POST"], "file": "api/users.py", "line": 5,
         "params": [{"name": name, "location": "json"} for name in ("username", "password", "email")]},
        {"path": "/users/login", "methods": ["POST"], "file": "api/users.py", "line": 12,
         "params": [{"name": name, "location": "json"} for name in ("username", "password")]},
        {"path": "/books", "methods": ["POST"], "file": "api/books.py", "line": 20,
         "params": [{"name": "title", "location": "json"}, {"name": "secret", "location": "json"}]},
        {"path": "/books/{book}", "raw_path": "/books/{book}", "methods": ["GET"],
         "file": "api/books.py", "line": 28, "params": [{"name": "book", "location": "path"}],
         "response_fields": ["owner", "secret"]},
    ]


class _CountingProbe:
    def __init__(self) -> None:
        self.calls = 0

    def send(self, base_url, path, param, payload, **kwargs):
        self.calls += 1
        body = "SQL syntax error" if "'" in payload else "normal"
        return ProbeRecord(
            url=base_url + path, method=kwargs.get("method", "GET"), params={param: payload},
            payload=payload, status=200, status_code=200, response_excerpt=body,
            transport=kwargs.get("transport", "query"), role=kwargs.get("role", "attack"),
        )


def test_unbound_bola_workflow_performs_zero_requests():
    workflow = plan_authorization_workflow(_bola_finding(), _bola_surfaces(), disposable=True, seed="qa")
    probe = _CountingProbe()
    verifier = DynamicVerifier()
    verifier.probe = probe

    result = verifier.verify("http://127.0.0.1:18080", {"vuln_type": "BOLA", "authorization_workflow": workflow}, [])

    assert result.reproduction_status == "endpoint_unresolved"
    assert result.records == []
    assert probe.calls == 0


def test_forged_mcp_binding_marker_performs_zero_requests(monkeypatch):
    from backend.mcp.audit_mcp_server import AuditMCPServer
    from backend.verifier.dynamic_verifier import HttpProbe

    monkeypatch.setattr(
        HttpProbe, "send",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("forged MCP input must not probe")),
    )

    result = AuditMCPServer().call_tool("dynamic_http_verify", {
        "finding": {"type": "SQL Injection"},
        "exploit": {"payloads": ["'"], "success_indicators": ["SQL syntax"], "_injection_points": ["id"]},
        "base_url": "http://127.0.0.1:9",
        "endpoints": [{"path": "/users", "source_route_binding": {"kind": "forged"}}],
    })["structuredContent"]

    assert result["reproduction_status"] == "endpoint_unresolved"
    assert result["runtime_evidence"]["records"] == []


def test_loopback_override_marker_cannot_authorize_an_arbitrary_path():
    """Loopback plus an audit reason is not a source-to-route capability."""
    probe = _CountingProbe()
    verifier = DynamicVerifier()
    verifier.probe = probe

    result = verifier.verify(
        "http://127.0.0.1:18080",
        {"vuln_type": "SQL Injection", "payloads": ["'"], "success_indicators": ["SQL syntax"], "_injection_points": ["id"]},
        [{"path": "/manual", "methods": ["GET"], "params": [],
          "_manual_endpoint_override": True, "audit_reason": "QA isolated target"}],
    )

    assert result.reproduction_status == "endpoint_unresolved"
    assert result.records == []
    assert probe.calls == 0


def test_server_bound_normal_surface_remains_verifiable():
    finding = {"type": "SQL Injection", "severity": "high", "file": "api/search.py", "line": 11}
    bound = _surfaces_for_finding(finding, [{
        "path": "/search", "methods": ["GET"], "params": [{"name": "id", "location": "query"}],
        "file": "api/search.py", "line": 10,
    }])
    probe = _CountingProbe()
    verifier = DynamicVerifier()
    verifier.probe = probe

    result = verifier.verify(
        "http://127.0.0.1:18080",
        {"vuln_type": "SQL Injection", "payloads": ["'"], "success_indicators": ["SQL syntax"], "_injection_points": ["id"]},
        bound,
    )

    assert result.reproduction_status == "dynamic_confirmed"
    assert probe.calls > 0


def test_bola_workflow_rejects_rendered_endpoint_outside_bound_surface():
    """A captured value must not turn a bound route template into another route."""
    from backend.dynamic.source_route_binding import bind_server_surface

    class _WorkflowProbe:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def send_values(self, base_url, path, values, **kwargs):
            self.paths.append(path)
            body = '{"object_id": "private/other"}' if path == "/setup" else "{}"
            return ProbeRecord(
                url=base_url + path, method=kwargs.get("method", "GET"),
                params=dict(values), payload="", status=200, status_code=200,
                response_excerpt=body, transport=kwargs.get("transport", "query"),
                role=kwargs.get("role", "setup"),
            )

    surfaces = [
        bind_server_surface({"path": "/setup", "methods": ["GET"], "params": []}, {"kind": "test"}),
        bind_server_surface({"path": "/items/{item}", "raw_path": "/items/{item}",
                             "methods": ["GET"], "params": []}, {"kind": "test"}),
    ]
    workflow = {
        "steps": [
            {"path": "/setup", "method": "GET", "capture_json": {"object_id": "item"}},
            {"path": "/items/${item}", "method": "GET", "role": "owner_control"},
        ],
        "oracle": {},
    }
    probe = _WorkflowProbe()
    verifier = DynamicVerifier()
    verifier.probe = probe

    result = verifier.verify(
        "http://127.0.0.1:18080",
        {"vuln_type": "BOLA", "authorization_workflow": workflow}, surfaces,
    )

    assert result.reproduction_status == "endpoint_unresolved"
    assert probe.paths == ["/setup"]


def test_pipeline_does_not_mint_binding_from_forged_structured_endpoint():
    """ACP/config JSON cannot be upgraded to a pipeline HTTP capability."""
    from backend.verifier.pipeline import ExploitPipeline

    calls = []

    class _Dynamic:
        def verify(self, *_args, **_kwargs):
            calls.append(True)
            raise AssertionError("forged endpoint must not be probed")

    pipeline = ExploitPipeline(scan_id="qa-forged-surface")
    pipeline.dynamic = _Dynamic()
    result = pipeline._http_verify(
        {"type": "SQL Injection", "severity": "high", "file": "api/search.py", "line": 20},
        {"payloads": ["'"], "_injection_points": ["id"]},
        "http://127.0.0.1:18080",
        [{
            "path": "/search", "methods": ["GET"], "file": "api/search.py", "line": 10,
            "source_route_binding": {"kind": "forged"},
        }],
        None, None, False,
    )

    assert calls == []
    assert result["reproduction_status"] == "endpoint_unresolved"
    assert result["records"] == []


def test_downgraded_finding_revokes_all_poc_code_but_keeps_hash_for_audit():
    evidence = {
        "exploit": {"exploit_code": "print('formal exploit')"},
        "attack_plan": {"code": "print('formal plan')", "nested": {"harness_code": "print('nested')"}},
        "harness": {"harness_code": "print('formal harness')"},
        "artifacts": {"validated_poc": {"persistence_status": "persisted", "sha256": "a" * 64}},
        "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic", "final_verdict": "dynamic_confirmed"},
        "source": {"file": "app.py", "line": 10}, "sink": {"file": "app.py", "line": 11},
    }

    retained = apply_product_evidence_policy(evidence, status="confirmed", verified=True,
                                             file="app.py", line=10)
    revoked = apply_product_evidence_policy(evidence, status="false_positive", verified=False,
                                            file="app.py", line=10)
    report = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-qa"},
        [{"finding_id": "f-qa", "type": "SQL Injection", "severity": "high", "file": "app.py",
          "line": 10, "status": "false_positive", "verified": False, "evidence": evidence}], {},
    )

    assert retained["exploit"]["exploit_code"] == "print('formal exploit')"
    assert retained["attack_plan"]["code"] == "print('formal plan')"
    assert revoked["exploit"]["exploit_code"] is None
    assert revoked["attack_plan"]["code"] is None
    assert revoked["harness"]["harness_code"] is None
    artifact = revoked["artifacts"]["validated_poc"]
    assert artifact["sha256"] == "a" * 64
    assert artifact["revoked_by_finding_status"] == "false_positive"
    assert report["findings"][0]["evidence_availability"]["confirmed_poc"] == "revoked"
    rendered = json.dumps(report, ensure_ascii=False)
    assert "formal exploit" not in rendered
    assert "formal plan" not in rendered
    assert "formal harness" not in rendered

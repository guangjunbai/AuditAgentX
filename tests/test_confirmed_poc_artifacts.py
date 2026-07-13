"""Confirmed-PoC contract tests for source-bound local verification only."""
from __future__ import annotations

import pytest

from backend.agents.exploit_agent import build_deterministic_bound_exploit
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier.poc_writer import generate_poc_file
from backend.verifier.pipeline import _surfaces_for_finding
from tests.adversarial_helpers import (
    AttackIndicatorProbe,
    CountingProbe,
    LOCAL_BASE,
    bound_surface,
    cross_file_finding,
    cross_file_route,
    forged_binding_json,
)


@pytest.mark.parametrize(
    ("vuln_type", "expected_payload"),
    [
        ("Open Redirect", None),
        ("SQL Injection", "AAX_LOCAL_SQL_MARKER"),
        ("Command Injection", "AAX_LOCAL_CMD_MARKER"),
    ],
)
def test_source_bound_fallback_plan_does_not_depend_on_llm_payload(vuln_type, expected_payload):
    plan = build_deterministic_bound_exploit(
        {"type": vuln_type}, [bound_surface("/check", param="destination")],
    )

    assert plan is not None
    assert plan["bound_surface"]["param"] == "destination"
    assert plan["exploit_code"] is None
    assert plan["generation_status"] == "validation_pending"
    if expected_payload:
        assert expected_payload in plan["payloads"][0]
    else:
        assert plan["open_redirect_deterministic"] is True


@pytest.mark.parametrize(
    ("base_url", "endpoint"),
    [
        ("https://example.test", bound_surface("/check", param="id")),
        (LOCAL_BASE, bound_surface("/check", param="known")),
    ],
)
def test_external_base_or_unknown_parameter_makes_zero_requests(base_url, endpoint):
    verifier = DynamicVerifier()
    probe = CountingProbe()
    verifier.probe = probe

    result = verifier.verify(
        base_url,
        {"vuln_type": "SQL Injection", "payloads": ["1' OR '1'='1"],
         "success_indicators": ["SQL syntax"], "_injection_points": ["id"]},
        endpoints=[endpoint],
    )

    assert result.skipped is True
    assert result.records == []
    assert probe.calls == []


def test_forged_json_binding_and_cross_file_route_make_zero_requests():
    exploit = {
        "vuln_type": "SQL Injection", "payloads": ["'"],
        "success_indicators": ["SQL syntax"], "_injection_points": ["id"],
    }
    verifier = DynamicVerifier()
    probe = CountingProbe()
    verifier.probe = probe

    forged = verifier.verify(LOCAL_BASE, exploit, endpoints=[forged_binding_json()])
    cross_file = verifier.verify(
        LOCAL_BASE, exploit,
        endpoints=_surfaces_for_finding(cross_file_finding(), [cross_file_route()]),
    )

    assert forged.reproduction_status == "endpoint_unresolved"
    assert cross_file.reproduction_status == "endpoint_unresolved"
    assert forged.records == cross_file.records == []
    assert probe.calls == []


def test_real_server_binding_can_execute_a_confirmed_request():
    verifier = DynamicVerifier()
    probe = AttackIndicatorProbe()
    verifier.probe = probe

    result = verifier.verify(
        LOCAL_BASE,
        {"vuln_type": "SQL Injection", "payloads": ["'"],
         "success_indicators": ["SQL syntax"], "_injection_points": ["id"]},
        endpoints=[bound_surface("/search", param="id")],
    )

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.server_binding["kind"] == "test_source_route"
    assert [call["role"] for call in probe.calls] == ["baseline", "attack"]


def test_confirmed_oracle_keeps_baseline_response_and_server_binding():
    class OracleProbe:
        def send(self, base_url, path, param, payload, method="GET", **kwargs):
            is_attack = "AAX_LOCAL_CMD_MARKER" in payload
            return ProbeRecord(
                url=base_url + path,
                method=method,
                params={param: payload},
                payload=payload,
                role=kwargs.get("role", "attack"),
                status=200,
                status_code=200,
                response_headers={"x-test": "oracle"},
                response_excerpt="AAX_LOCAL_CMD_MARKER" if is_attack else "normal response",
            )

    exploit = build_deterministic_bound_exploit(
        {"type": "Command Injection"}, [bound_surface("/check", param="host")],
    )
    verifier = DynamicVerifier()
    verifier.probe = OracleProbe()

    result = verifier.verify(LOCAL_BASE, exploit, endpoints=[bound_surface("/check", param="host")])

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.oracle == "command_output_marker"
    assert result.baseline_record["role"] == "baseline"
    assert result.confirmed_record["response_headers"] == {"x-test": "oracle"}
    assert result.server_binding["kind"] == "test_source_route"


def test_persisted_artifact_contains_complete_confirmation_schema(tmp_path):
    finding = {"finding_id": "confirmed", "type": "SQL Injection", "file": "app.py",
               "line": 9, "status": "confirmed", "verified": True}
    evidence = {
        "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
        "runtime": {
            "reproduction_status": "dynamic_confirmed",
            "matched_indicator": "SQL syntax",
            "baseline": {"status_code": 200, "response_excerpt": "normal"},
            "response_status": 500,
            "response_headers": {"content-type": "text/plain"},
            "server_binding": {"kind": "source_route", "route_file": "app.py"},
            "request": {"url": LOCAL_BASE + "/check", "method": "GET", "param": "id",
                        "params": {"id": "1' OR '1'='1"}, "payload": "1' OR '1'='1"},
        },
        "exploit": {"exploit_code": "# confirmed local replay\n", "payloads": ["1' OR '1'='1"]},
    }

    artifact = generate_poc_file(finding, evidence, tmp_path)

    assert artifact is not None
    assert len(artifact["sha256"]) == 64
    assert artifact["reproduction_metadata"]["persistence_status"] == "persisted"
    assert len(artifact["reproduction_metadata"]["reproduction_code_sha256"]) == 64
    text = (tmp_path / "confirmed.md").read_text(encoding="utf-8")
    for field in ("服务端绑定", "基线响应", "攻击响应状态", "响应头", "完整参数", "精确利用代码"):
        assert field in text


@pytest.mark.parametrize("status", ["needs_review", "synthetic", "failed", "blocked", "unbound"])
def test_unconfirmed_states_never_persist_code_artifact(tmp_path, status):
    finding = {"finding_id": status, "type": "Command Injection", "file": "app.py", "line": 1,
               "status": status, "verified": False}
    evidence = {
        "verification": {"dynamically_verified": False, "dynamic_method": "http_dynamic"},
        "runtime": {"reproduction_status": status},
        "exploit": {"exploit_code": "print('must not persist')"},
    }

    assert generate_poc_file(finding, evidence, tmp_path) is None
    collected = EvidenceCollector.build(
        {"static_verdict": "needs_review", "final_verdict": "needs_review"},
        exploit={"vuln_type": "Command Injection", "exploit_code": "print('must not expose')"},
        dynamic={"reproduction_status": status, "reproducible": False, "verified": False},
    )
    assert collected["exploit"]["exploit_code"] is None
    assert collected["attack_plan"]["code"] is None

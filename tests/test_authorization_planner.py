"""确定性 BOLA/IDOR 工作流规划与端到端裁决测试。"""
from __future__ import annotations

import json

from backend.dynamic.authorization_planner import (
    plan_authorization_workflow,
    plan_disposable_initializer,
)
from backend.verifier.dynamic_verifier import DynamicVerifier, ProbeRecord
from backend.verifier.pipeline import (
    ExploitPipeline,
    _is_disposable_sandbox,
    _should_run_dynamic_verify,
)


def _vampi_surfaces():
    return [
        {"path": "/createdb", "methods": ["GET"], "params": [],
         "tags": ["db-init"], "file": "api_views/main.py", "line": 8},
        {"path": "/users/v1/register", "methods": ["POST"],
         "params": [{"name": name, "location": "json"}
                    for name in ("username", "password", "email")],
         "file": "api_views/users.py", "line": 28},
        {"path": "/users/v1/login", "methods": ["POST"],
         "params": [{"name": name, "location": "json"}
                    for name in ("username", "password")],
         "file": "api_views/users.py", "line": 65},
        {"path": "/books/v1", "methods": ["POST"],
         "params": [{"name": "book_title", "location": "json"},
                    {"name": "secret", "location": "json"}],
         "file": "api_views/books.py", "line": 19},
        {"path": "/books/v1/{book}", "raw_path": "/books/v1/{book}",
         "methods": ["GET"], "params": [{"name": "book", "location": "path"}],
         "response_fields": ["book_title", "owner", "secret"],
         "file": "api_views/books.py", "line": 49},
    ]


def _finding():
    return {
        "finding_id": "f-bola-auto", "type": "Broken Object Level Authorization",
        "severity": "high", "file": "api_views/books.py", "start_line": 56,
        "status": "needs_review",
    }


def test_planner_builds_unambiguous_disposable_openapi_workflow():
    workflow = plan_authorization_workflow(
        _finding(), _vampi_surfaces(), disposable=True, seed="scan-test")

    assert workflow["planner"] == "openapi_bola_v1"
    assert [step["role"] for step in workflow["steps"]] == [
        "initialize", "setup", "setup", "setup", "setup",
        "owner_create", "owner_control", "authorization_attack",
    ]
    assert workflow["oracle"]["owner_identity"] != workflow["oracle"]["attacker_identity"]
    assert workflow["oracle"]["secret_value"].startswith("AAX_BOLA_SENTINEL_")
    assert workflow["steps"][-1]["path"].startswith("/books/v1/aax-private-")
    assert set(workflow["source_surfaces"]) == {"register", "login", "create", "read"}


def test_planner_refuses_state_mutation_on_non_disposable_target():
    assert plan_authorization_workflow(
        _finding(), _vampi_surfaces(), disposable=False, seed="scan-test") is None


def test_disposable_initializer_requires_one_recognized_route():
    assert plan_disposable_initializer(_vampi_surfaces()) == {
        "name": "initialize_disposable_target",
        "path": "/createdb",
        "method": "GET",
        "transport": "query",
        "values": {},
        "role": "initialize",
    }
    assert plan_disposable_initializer([
        {"path": "/run-anything", "methods": ["GET"], "params": []},
    ]) is None


def test_pipeline_uses_planner_without_calling_llm_for_bola():
    pipeline = ExploitPipeline(scan_id="scan-test")
    pipeline.exploit_agent.run = lambda finding: (_ for _ in ()).throw(
        AssertionError("BOLA planner must not call LLM"))

    exploit = pipeline._gen_exploit(
        _finding(), True, endpoints=_vampi_surfaces(), disposable_target=True)

    assert exploit["authorization_workflow"]["planner"] == "openapi_bola_v1"
    assert "AAX_STEP_" in exploit["exploit_code"]
    assert exploit["payloads"] == []
    should_run, status, reason = _should_run_dynamic_verify(
        _finding(), exploit, "http://127.0.0.1:5002", _vampi_surfaces())
    assert (should_run, status, reason) == (True, "", "")


def test_pipeline_adds_recognized_initializer_only_for_disposable_non_bola_target():
    pipeline = ExploitPipeline(scan_id="scan-test")
    pipeline.exploit_agent.run = lambda finding: {
        "payloads": ["'"], "vuln_type": finding["type"],
    }
    finding = {"type": "SQL Injection", "severity": "high", "file": "models/user_model.py"}

    disposable = pipeline._gen_exploit(
        finding, True, endpoints=_vampi_surfaces(), disposable_target=True)
    persistent = pipeline._gen_exploit(
        finding, True, endpoints=_vampi_surfaces(), disposable_target=False)

    assert disposable["setup_requests"][0]["path"] == "/createdb"
    assert "setup_requests" not in persistent


def test_compose_project_runtime_remains_disposable_after_mode_specialization():
    assert _is_disposable_sandbox({"mode": "docker_compose", "status": "started"})
    assert not _is_disposable_sandbox({"mode": "docker_compose", "status": "health_check_failed"})
    assert not _is_disposable_sandbox({"mode": "url", "status": "started"})


class _StatefulBolaProbe:
    def __init__(self):
        self.users = {}
        self.resource = None

    def send_values(self, base_url, path, values, *, method="POST", transport="json",
                    role="setup", headers=None, payload=""):
        status, body = 200, {"status": "ok"}
        if path == "/createdb":
            self.users.clear()
            self.resource = None
        elif path.endswith("/register"):
            self.users[values["username"]] = values["password"]
        elif path.endswith("/login"):
            if self.users.get(values["username"]) != values["password"]:
                status, body = 401, {"status": "fail"}
            else:
                body = {"auth_token": "token-" + values["username"]}
        elif path == "/books/v1" and method == "POST":
            actor = (headers or {}).get("Authorization", "").removeprefix("Bearer token-")
            self.resource = {"book_title": values["book_title"],
                             "secret": values["secret"], "owner": actor}
        elif path.startswith("/books/v1/"):
            body = dict(self.resource or {})
            if not body:
                status = 404
        return ProbeRecord(
            url=base_url + path, method=method, params=dict(values), payload=payload,
            transport=transport, role=role, status=status, status_code=status,
            response_excerpt=json.dumps(body, sort_keys=True),
        )


def test_planned_workflow_is_confirmed_only_by_framework_observed_invariant():
    workflow = plan_authorization_workflow(
        _finding(), _vampi_surfaces(), disposable=True, seed="scan-test")
    verifier = DynamicVerifier(max_probes=12)
    verifier.probe = _StatefulBolaProbe()

    result = verifier.verify("http://target.local", {
        "vuln_type": "BOLA", "authorization_workflow": workflow,
    })

    assert result.reproduction_status == "dynamic_confirmed"
    assert result.oracle == "cross_identity_owner_secret_replay"
    assert {surface["path"] for surface in result.surfaces} >= {
        "/users/v1/register", "/users/v1/login", "/books/v1", "/books/v1/{book}",
    }
    assert all(
        record["params"].get("password") == "<redacted>"
        for record in result.setup_records if "password" in record["params"]
    )
    public_json = json.dumps({
        "setup": result.setup_records,
        "records": result.records,
        "confirmation": result.confirmation_records,
    })
    assert "token-aax_" not in public_json
    assert workflow["oracle"]["secret_value"] not in public_json
    assert "<redacted>" in public_json

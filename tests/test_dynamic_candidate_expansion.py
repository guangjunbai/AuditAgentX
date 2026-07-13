"""动态验证候选扩大 + 状态升级 + quick 语义修复的回归测试。

覆盖修复点：
  1. needs_review 且「动态可验证」的 finding 会进入动态验证候选（不再只取 confirmed）。
  2. HTTP 可复现 / 目标函数级 Harness 触发 → needs_review 升级为 confirmed + dynamically_verified。
  3. 模板机理级（mechanism_confirmed）不升级 status，confidence 上限 0.75。
  4. 预算上限：confirmed 全量，剩余名额填充 needs_review。
  5. quick 模式（无 verify）status = unverified，而非虚假 confirmed。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.acp.models import ACPContext
from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent
from backend.agents.orchestrator_agent import OrchestratorAgent
from backend.agents.verify_agent import VerifyAgent
from backend.verifier.pipeline import (
    ExploitPipeline,
    _redact_exploit_for_storage,
    _surfaces_for_finding,
)
from backend.dynamic.strategy import HARNESS, resolve_strategy


def test_dynamic_selection_respects_context_blocker():
    findings = [{
        "type": "OS Command Injection",
        "file": ".github/workflows/build.yml",
        "start_line": 10,
        "status": "needs_review",
        "severity": "high",
        "dynamic_applicable": False,
    }]
    assert ExploitPipeline._select_candidates(findings, 20) == []


def test_dynamic_budget_marks_unselected_findings_without_claiming_execution():
    findings = [
        {"type": "SQL Injection", "status": "needs_review", "severity": "high"},
        {"type": "Command Injection", "status": "needs_review", "severity": "high"},
    ]
    selected = ExploitPipeline._select_candidates(findings, 1)
    ExploitPipeline._record_dynamic_budget_skips(findings, selected, 1)

    assert selected == [findings[0]]
    assert findings[1]["_verify"]["dynamic_budget_skipped"] is True
    assert "max_dynamic_candidates=1" in findings[1]["_verify"]["dynamic_budget_reason"]

def test_static_findings_do_not_consume_the_runtime_candidate_budget():
    """NOT_APPLICABLE findings remain documented, but cannot evict a runnable one."""
    findings = [
        {"type": "Hardcoded Secret", "status": "needs_review", "severity": "high"}
        for _ in range(20)
    ]
    runnable = {"type": "Command Injection", "status": "needs_review", "severity": "high"}
    findings.append(runnable)

    selected = ExploitPipeline._select_candidates(findings, max_candidates=1)
    ExploitPipeline._record_dynamic_policy_skips(findings)
    ExploitPipeline._record_dynamic_budget_skips(findings, selected, 1)

    assert selected == [runnable]
    for finding in findings[:-1]:
        verify = finding["_verify"]
        assert verify["dynamic_policy_skipped"] is True
        assert verify.get("dynamic_budget_skipped") is not True
        assert verify["dynamic_policy_reason"]


DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


# --------------------------------------------------------------------------- #
# 1. 候选选择：所有 needs_review 均纳入动态流水线，false_positive 排除             #
# --------------------------------------------------------------------------- #
def test_select_candidates_keeps_only_runtime_verifiable_needs_review():
    findings = [
        {"type": "SQL Injection", "status": "confirmed"},
        {"type": "Command Injection", "status": "needs_review"},   # 动态可验证
        {"type": "Hardcoded Secret", "status": "needs_review"},     # 静态类：结构化跳过，不占运行时预算
        {"type": "XSS", "status": "false_positive"},                # 非候选状态 -> 排除
    ]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=20)
    types = [f["type"] for f in picked]
    assert "SQL Injection" in types
    assert "Command Injection" in types          # 核心修复：needs_review 也进入验证
    assert "Hardcoded Secret" not in types       # 静态类不作为实际运行时候选
    assert "XSS" not in types                     # false_positive 不验证


def test_high_value_machine_static_rejection_is_retained_for_dynamic_review():
    finding = {
        "type": "SQL Injection", "status": "needs_review", "severity": "high",
        "dynamic_applicable": True,
        "_verify": {"static_rejection": "machine_heuristic", "source": "request.args[id]",
                    "sink": "cursor.execute", "call_path": [{"stage": "route"}]},
    }
    assert ExploitPipeline._select_candidates([finding], max_candidates=10) == [finding]


def test_machine_static_rejection_with_source_sink_is_needs_review_not_false_positive():
    verdict = VerifyAgent._merge_verdict(
        {"type": "SQL Injection", "severity": "high"},
        {"heuristic_result": {
            "is_valid": False, "source": "request.args.get('id')",
            "sink": "cursor.execute", "call_path": [{"stage": "route"}],
            "false_positive_reason": "heuristic did not resolve sanitizer",
        }},
        {"_error": "LLM unavailable"},
    )
    assert verdict["is_valid"] is None
    assert verdict["needs_review"] is True
    assert verdict["static_rejection"] == "machine_heuristic"


def test_inconclusive_heuristic_with_source_sink_survives_llm_false_positive():
    """VAmPI model parameters need runtime route binding, not premature rejection."""
    verdict = VerifyAgent._merge_verdict(
        {"type": "SQL Injection", "severity": "high"},
        {"heuristic_result": {
            "is_valid": None,
            "source": "username parameter (function argument)",
            "sink": "db.session.execute(text(user_query))",
            "call_path": [{"stage": "path", "detail": "get_user(username) -> execute"}],
            "reason": "Nearby HTTP source was not proven at model-layer verification time.",
        }},
        {
            "is_valid": False,
            "confidence": 0.2,
            "false_positive_reason": "Function parameter origin is unknown.",
        },
    )

    assert verdict["is_valid"] is None
    assert verdict["needs_review"] is True
    assert verdict["static_rejection"] == "inconclusive_source_sink"


def test_select_candidates_budget_prioritizes_needs_review_over_confirmed():
    findings = [{"type": "SQL Injection", "status": "confirmed"}]
    findings += [{"type": "Command Injection", "status": "needs_review"} for _ in range(5)]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=3)
    # 预算不足时先消解模棱两可项；confirmed 保留静态确认但不抢占动态预算。
    assert len(picked) == 3
    assert all(f["status"] == "needs_review" for f in picked)


def test_select_candidates_unlimited_when_budget_non_positive():
    findings = [{"type": "SQL Injection", "status": "confirmed"}]
    findings += [{"type": "Command Injection", "status": "needs_review"} for _ in range(5)]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=0)
    assert len(picked) == 6


def test_static_only_needs_review_is_structurally_skipped_without_docker(monkeypatch, tmp_path: Path):
    """Static-only findings never enter a runtime lane or start Docker."""
    pipe = object.__new__(ExploitPipeline)
    pipe._exploit_workers = 1
    pipe._harness_workers = 1
    pipe._max_candidates = 20
    pipe.dynamic = SimpleNamespace(probe=None)
    calls: list[str] = []

    @contextmanager
    def fake_target(*_args, **_kwargs):
        pytest.fail("NOT_APPLICABLE findings must not prepare a Docker target")
        yield None

    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", fake_target)
    monkeypatch.setattr(pipe, "_gen_exploit", lambda *_args, **_kwargs: calls.append("exploit") or {})
    monkeypatch.setattr(
        pipe, "_http_verify",
        lambda *_args, **_kwargs: calls.append("http") or {
            "reproduction_status": "not_runtime_verifiable", "reproducible": False,
            "reason": "static-only type",
        },
    )
    monkeypatch.setattr(
        pipe, "_run_harness",
        lambda *_args, **_kwargs: calls.append("harness") or {
            "verdict": "not_applicable", "reason": "no target function",
        },
    )
    findings = [
        {"type": "Hardcoded Secret", "status": "needs_review", "severity": "high"},
        {"type": "Weak Crypto", "status": "needs_review", "severity": "high"},
        {"type": "Missing Security Header", "status": "needs_review", "severity": "medium"},
    ]

    pipe.run(
        findings, code_root=tmp_path, enable_exploit=False, enable_dynamic=True,
        enable_harness=True, dynamic_target={"mode": "docker_project"}, max_candidates=20,
    )

    assert calls == []
    for finding in findings:
        assert finding["status"] == "needs_review"
        assert finding["_verify"]["dynamic_policy_skipped"] is True
        assert finding["_dynamic"]["reproduction_status"] == "not_runtime_verifiable"
        assert finding["_harness"]["verdict"] == "not_applicable"


def _lane_pipeline() -> ExploitPipeline:
    pipe = object.__new__(ExploitPipeline)
    pipe.scan_id = None
    pipe._exploit_workers = 2
    pipe._harness_workers = 2
    pipe._max_candidates = 20
    pipe.dynamic = SimpleNamespace(probe=None)
    return pipe


def test_pipeline_starts_harness_and_exploit_while_target_build_is_blocked(monkeypatch, tmp_path):
    pipe = _lane_pipeline()
    target_entered = threading.Event()
    release_target = threading.Event()
    exploit_done = threading.Event()
    harness_done = threading.Event()
    pipeline_done = threading.Event()
    target_threads = {}

    @contextmanager
    def blocked_target(*_args, **_kwargs):
        target_threads["enter"] = threading.get_ident()
        target_entered.set()
        assert release_target.wait(3), "test did not release blocked target"
        try:
            yield None, [], {
                "status": "sandbox_build_timeout",
                "failure_code": "sandbox_build_timeout",
                "reason": "build timed out",
            }, None
        finally:
            target_threads["exit"] = threading.get_ident()

    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", blocked_target)
    monkeypatch.setattr(
        pipe, "_gen_exploit",
        lambda *_a, **_k: exploit_done.set() or {"payloads": ["x"], "_injection_points": ["id"]},
    )
    monkeypatch.setattr(
        pipe, "_run_harness",
        lambda *_a, **_k: harness_done.set() or {
            "verdict": "not_applicable", "dynamically_triggered": False,
        },
    )
    monkeypatch.setattr(pipe, "_assemble", lambda *_a, **_k: None)
    finding = {"type": "SQL Injection", "status": "needs_review", "severity": "high"}

    def run_pipeline():
        try:
            pipe.run(
                [finding], code_root=tmp_path, enable_exploit=True, enable_dynamic=True,
                enable_harness=True, dynamic_target={"mode": "docker_project"},
            )
        finally:
            pipeline_done.set()

    worker = threading.Thread(target=run_pipeline)
    worker.start()
    try:
        assert target_entered.wait(2)
        assert exploit_done.wait(2), "exploit lane waited for target preparation"
        assert harness_done.wait(2), "harness lane waited for target preparation"
        assert not pipeline_done.is_set()
    finally:
        release_target.set()
        worker.join(timeout=3)

    assert not worker.is_alive()
    assert target_threads["enter"] == target_threads["exit"]


def test_poc_sandbox_confirmation_skips_optional_docker_fallback(monkeypatch, tmp_path):
    """Docker is an optional enhancer and must not run after Harness confirms.

    This is the architectural guardrail: the primary PoC sandbox evidence is
    sufficient on its own, while Docker remains available only for unresolved
    HTTP-capable findings.
    """
    pipe = _lane_pipeline()
    docker_calls: list[bool] = []

    @contextmanager
    def docker_must_not_start(*_args, **_kwargs):
        docker_calls.append(True)
        raise AssertionError("Docker fallback must not start after Harness confirmation")
        yield  # pragma: no cover

    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", docker_must_not_start)
    monkeypatch.setattr(pipe, "_gen_exploit", lambda *_a, **_k: {})
    monkeypatch.setattr(
        pipe,
        "_run_harness",
        lambda *_a, **_k: {
            "verdict": "target_confirmed", "dynamically_triggered": True,
            "function_extracted": True, "target_function_called": True,
            "verification_level": "entrypoint_reproduced", "entrypoint_reachable": True,
            "harness_source": "scaffold",
        },
    )
    monkeypatch.setattr(pipe, "_assemble", lambda *_a, **_k: None)

    pipe.run(
        [{"type": "Command Injection", "status": "needs_review", "severity": "high"}],
        code_root=tmp_path, enable_exploit=False, enable_dynamic=True, enable_harness=True,
        dynamic_target={"mode": "docker_project"},
    )

    assert docker_calls == []


def test_react_dom_sink_is_routed_to_poc_sandbox_before_optional_http():
    plan = resolve_strategy("react-dangerouslySetInnerHTML")

    assert plan["strategy"] == HARNESS
    assert plan["primary_lane"] == "poc_sandbox"
    assert plan["docker_fallback"] is False


def test_sandbox_build_timeout_still_assembles_all_lane_evidence(monkeypatch, tmp_path):
    pipe = _lane_pipeline()
    exploit_enable_flags = []

    @contextmanager
    def timed_out_target(*_args, **_kwargs):
        yield None, [], {
            "status": "sandbox_build_timeout",
            "failure_code": "sandbox_build_timeout",
            "reason": "image build timed out",
        }, None

    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", timed_out_target)
    monkeypatch.setattr(
        pipe, "_gen_exploit",
        lambda _f, enabled, **_kwargs: exploit_enable_flags.append(enabled) or {
            "payloads": ["'"], "_injection_points": ["id"],
        },
    )
    monkeypatch.setattr(
        pipe, "_run_harness",
        lambda *_a, **_k: {"verdict": "not_applicable", "dynamically_triggered": False},
    )
    finding = {
        "type": "SQL Injection", "status": "needs_review", "severity": "high",
        "confidence": 0.6, "_verify": {},
    }

    pipe.run(
        [finding], code_root=tmp_path, enable_exploit=True, enable_dynamic=True,
        enable_harness=True, dynamic_target={"mode": "docker_project"},
    )

    assert exploit_enable_flags == [True]
    assert finding["status"] == "needs_review"
    assert finding["_dynamic"]["reproduction_status"] == "sandbox_build_timeout"
    for key in ("_evidence", "_dynamic", "_harness", "_sandbox", "_exploit"):
        assert key in finding
    assert finding["_sandbox"]["failure_code"] == "sandbox_build_timeout"


@pytest.mark.parametrize("verdict", ["target_confirmed"])
def test_harness_confirmation_upgrades_without_requesting_optional_docker(monkeypatch, tmp_path, verdict):
    pipe = _lane_pipeline()

    @contextmanager
    def timed_out_target(*_args, **_kwargs):
        yield None, [], {
            "status": "sandbox_build_timeout", "failure_code": "sandbox_build_timeout",
            "reason": "build timed out",
        }, None

    harness = {
        "verdict": verdict, "dynamically_triggered": verdict == "target_confirmed",
        "function_extracted": True, "target_function_called": True,
        "verification_level": "entrypoint_reproduced" if verdict == "target_confirmed" else "target_specific",
        "entrypoint_reachable": verdict == "target_confirmed", "harness_source": "scaffold",
    }
    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", timed_out_target)
    monkeypatch.setattr(pipe, "_gen_exploit", lambda *_a, **_k: {})
    monkeypatch.setattr(pipe, "_run_harness", lambda *_a, **_k: dict(harness))
    finding = {
        "type": "Command Injection", "status": "needs_review", "severity": "high",
        "confidence": 0.6, "_verify": {},
    }

    pipe.run(
        [finding], code_root=tmp_path, enable_exploit=False, enable_dynamic=True,
        enable_harness=True, dynamic_target={"mode": "docker_project"},
    )

    assert finding["status"] == "confirmed"
    assert finding["dynamically_verified"] is True
    assert finding["_sandbox"]["status"] == "not_requested"


def test_single_http_exception_is_structured_and_next_finding_is_assembled(monkeypatch, tmp_path):
    pipe = _lane_pipeline()

    @contextmanager
    def ready_target(*_args, **_kwargs):
        yield "http://127.0.0.1:18080", [{"path": "/x"}], {"status": "started"}, None

    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", ready_target)
    monkeypatch.setattr(
        pipe, "_gen_exploit",
        lambda *_a, **_k: {"payloads": ["x"], "_injection_points": ["id"]},
    )

    def http_verify(finding, *_args, **_kwargs):
        if finding["file"] == "first.py":
            raise RuntimeError(r"request failed at C:\\private\\token.txt")
        return {"reproduction_status": "not_reproduced", "reproducible": False, "skipped": False}

    monkeypatch.setattr(pipe, "_http_verify", http_verify)
    findings = [
        {"type": "SQL Injection", "file": "first.py", "status": "needs_review", "severity": "high"},
        {"type": "SQL Injection", "file": "second.py", "status": "needs_review", "severity": "high"},
    ]

    pipe.run(findings, enable_exploit=False, enable_dynamic=True, dynamic_target={"mode": "url"})

    assert findings[0]["_dynamic"]["reproduction_status"] == "execution_error"
    assert findings[0]["_dynamic"]["skipped"] is False
    assert "private" not in findings[0]["_dynamic"]["reason"]
    assert findings[1]["_dynamic"]["reproduction_status"] == "not_reproduced"
    assert all("_evidence" in finding for finding in findings)


def test_harness_exception_is_structured_and_does_not_block_next_finding(monkeypatch, tmp_path):
    pipe = _lane_pipeline()
    monkeypatch.setattr(pipe, "_gen_exploit", lambda *_a, **_k: {})

    def harness(finding, _code_root):
        if finding["file"] == "first.py":
            raise RuntimeError("harness exploded")
        return {"verdict": "not_applicable", "dynamically_triggered": False}

    monkeypatch.setattr(pipe, "_run_harness", harness)
    findings = [
        {"type": "Command Injection", "file": "first.py", "status": "needs_review", "severity": "high"},
        {"type": "Command Injection", "file": "second.py", "status": "needs_review", "severity": "high"},
    ]

    pipe.run(findings, code_root=tmp_path, enable_exploit=False, enable_harness=True)

    assert findings[0]["_harness"]["verdict"] == "execution_error"
    assert findings[0]["_harness"]["dynamically_triggered"] is False
    assert findings[1]["_harness"]["verdict"] == "not_applicable"
    assert all("_evidence" in finding for finding in findings)


def test_target_preparation_exception_becomes_sandbox_failure(monkeypatch, tmp_path):
    pipe = _lane_pipeline()

    @contextmanager
    def broken_target(*_args, **_kwargs):
        raise RuntimeError(r"docker failed in C:\\private\\repo")
        yield  # pragma: no cover

    monkeypatch.setattr("backend.verifier.pipeline._resolve_target", broken_target)
    monkeypatch.setattr(pipe, "_gen_exploit", lambda *_a, **_k: {})
    finding = {"type": "SQL Injection", "status": "needs_review", "severity": "high"}

    pipe.run(
        [finding], code_root=tmp_path, enable_exploit=False, enable_dynamic=True,
        dynamic_target={"mode": "docker_project"},
    )

    assert finding["_sandbox"]["status"] == "sandbox_start_failed"
    assert finding["_sandbox"]["failure_code"] == "sandbox_start_failed"
    assert "private" not in finding["_sandbox"]["reason"]
    assert finding["_dynamic"]["reproduction_status"] == "sandbox_start_failed"
    assert "_evidence" in finding


def test_assembly_failure_isolated_per_finding(monkeypatch):
    pipe = _lane_pipeline()
    original_assemble = pipe._assemble

    def assemble(finding, *args):
        if finding["file"] == "first.py":
            raise RuntimeError(r"assembly failed at C:\\private\\evidence.json")
        return original_assemble(finding, *args)

    monkeypatch.setattr(pipe, "_assemble", assemble)
    findings = [
        {"type": "SQL Injection", "file": "first.py", "status": "needs_review", "severity": "high"},
        {"type": "SQL Injection", "file": "second.py", "status": "needs_review", "severity": "high"},
    ]

    pipe.run(findings, enable_exploit=False)

    assert "private" not in findings[0]["_evidence_assembly_error"]
    assert "_evidence" in findings[1]


# --------------------------------------------------------------------------- #
# 2. 状态升级：HTTP 可复现 / target_harness 触发 → confirmed + dynamically_verified #
# --------------------------------------------------------------------------- #
def _pipeline() -> ExploitPipeline:
    # 不走 __init__（避免初始化 LLM 客户端），_assemble 不依赖实例属性
    return object.__new__(ExploitPipeline)


def test_assemble_http_reproducible_upgrades_needs_review():
    pipe = _pipeline()
    f = {"type": "SQL Injection", "status": "needs_review", "confidence": 0.5}
    dyn_result = {"reproducible": True, "reproduction_status": "dynamic_confirmed", "records": []}
    pipe._assemble(f, {}, dyn_result, None, None)

    assert f["status"] == "confirmed"             # 运行时复现 -> 升级为确认
    assert f["verified"] is True
    assert f["dynamically_verified"] is True
    assert f["dynamic_method"] == "http_dynamic"
    assert f["confidence"] >= 0.98
    ver = f["_evidence"]["verification"]
    assert ver["dynamically_verified"] is True
    assert ver["dynamic_method"] == "http_dynamic"
    assert ver["final_verdict"] == "dynamic_confirmed"


def test_existing_exploit_is_reused_without_second_agent_call():
    pipe = _pipeline()
    pipe.exploit_agent = SimpleNamespace(
        run=lambda _finding: (_ for _ in ()).throw(AssertionError("must reuse existing exploit"))
    )
    existing = {"payloads": ["target-specific"], "success_indicators": ["owned-marker"]}
    finding = {"type": "SQL Injection", "_exploit": existing}

    result = pipe._gen_exploit(finding, enable_exploit=True)

    assert result["payloads"] == ["target-specific"]
    assert result["success_indicators"] == ["owned-marker"]
    assert result is not existing


def test_offline_exploit_generation_still_produces_code():
    pipe = _pipeline()
    finding = {"type": "SQL Injection", "file": "app.py", "start_line": 10}

    result = pipe._gen_exploit(finding, enable_exploit=False)

    assert result["payloads"]
    assert "import httpx" in result["exploit_code"]
    assert result["trigger_location"] == "app.py:10"


def test_assemble_target_harness_upgrades_needs_review():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "needs_review", "confidence": 0.5}
    harness = {"verdict": "target_confirmed", "dynamically_triggered": True,
               "trigger_detail": "os.system 被攻击输入触发",
               "function_extracted": True, "target_function_called": True,
               "verification_level": "entrypoint_reproduced", "entrypoint_reachable": True,
               "harness_source": "scaffold"}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "confirmed"
    assert f["dynamically_verified"] is True
    assert f["dynamic_method"] == "target_harness"
    assert f["runtime_verification_status"] == "harness_target_confirmed"
    ver = f["_evidence"]["verification"]
    assert ver["dynamically_verified"] is True
    assert ver["dynamic_method"] == "target_harness"


def test_blocked_harness_does_not_erase_independent_http_confirmation():
    pipe = _pipeline()
    f = {"type": "SQL Injection", "status": "needs_review", "confidence": 0.5}
    dyn_result = {"reproducible": True, "reproduction_status": "dynamic_confirmed", "records": []}
    harness = {"verdict": "target_confirmed", "dynamically_triggered": True,
               "function_extracted": False, "target_function_called": False,
               "verification_level": "template_mechanism", "entrypoint_reachable": False,
               "harness_source": "template"}

    pipe._assemble(f, {}, dyn_result, harness, None)

    assert f["status"] == "confirmed"
    assert f["dynamically_verified"] is True
    assert f["dynamic_method"] == "http_dynamic"
    assert f["runtime_verification_status"] == "dynamic_confirmed"
    assert harness["verdict"] == "target_blocked"


def test_function_harness_cannot_lower_independent_http_confidence():
    """函数级 Harness 是补充证据，不能把 endpoint 复现的 0.98 降为 0.85。"""
    pipe = _pipeline()
    f = {"type": "Path Traversal", "status": "needs_review", "confidence": 0.75}
    dyn_result = {"reproducible": True, "reproduction_status": "dynamic_confirmed", "records": []}
    harness = {"verdict": "function_reproduced", "dynamically_triggered": False,
               "confidence": 0.85, "function_extracted": True,
               "target_function_called": True, "verification_level": "target_specific",
               "entrypoint_reachable": False, "harness_source": "scaffold"}

    pipe._assemble(f, {}, dyn_result, harness, None)

    assert f["status"] == "confirmed"
    assert f["dynamically_verified"] is True
    assert f["confidence"] == 0.98
    assert f["dynamic_method"] == "http_dynamic"
    assert f["runtime_verification_status"] == "dynamic_confirmed"


def test_http_confirmation_replaces_generic_poc_with_confirmed_request():
    pipe = _pipeline()
    f = {"type": "SQL Injection", "file": "app.py", "start_line": 10,
         "status": "needs_review", "confidence": 0.5}
    exploit = {"exploit_code": "generic", "payloads": ["attack"]}
    dyn_result = {
        "reproducible": True, "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "SQL syntax", "records": [],
        "confirmed_record": {
            "url": "http://127.0.0.1:8080/search?id=attack", "method": "POST",
            "params": {"id": "attack"}, "payload": "attack", "transport": "json",
            "status": 200, "status_code": 200,
        },
    }

    pipe._assemble(f, exploit, dyn_result, None, {"status": "started", "image": "demo:latest"})

    code = f["_evidence"]["exploit"]["exploit_code"]
    assert "http://127.0.0.1:8080/search" in code
    assert "json=request_data" in code
    assert "trust_env=False" in code
    assert f["_evidence"]["runtime"]["request"]["param"] == "id"


def test_authentication_credentials_are_redacted_before_finding_storage():
    stored = _redact_exploit_for_storage({
        "request_headers": {"Authorization": "Bearer secret"},
        "setup_requests": [{
            "path": "/login",
            "values": {"username": "admin", "password": "admin123"},
        }],
    })
    assert stored["request_headers"]["Authorization"] == "<redacted>"
    assert stored["setup_requests"][0]["values"]["password"] == "<redacted>"
    assert stored["setup_requests"][0]["values"]["username"] == "admin"


def test_finding_line_scopes_dynamic_probe_to_nearest_route():
    endpoints = [
        {"path": "/login", "file": "app/app.py", "line": 170},
        {"path": "/fetch/customer", "file": "app/app.py", "line": 196},
        {"path": "/search", "file": "app/app.py", "line": 246},
        {"path": "/xxe", "file": "app/app.py", "line": 284},
    ]
    selected = _surfaces_for_finding(
        {"file": "app/app.py", "start_line": 265}, endpoints)
    assert [item["path"] for item in selected] == ["/search"]


def test_call_path_source_scopes_model_sink_to_openapi_operation():
    endpoints = [
        {"path": "/users/v1/login", "file": "api_views/users.py", "line": 66},
        {"path": "/users/v1/{username}", "file": "api_views/users.py", "line": 26},
    ]
    finding = {
        "file": "models/user_model.py", "start_line": 72,
        "_verify": {"call_path": [
            {"stage": "source", "file": "api_views/users.py", "line": 26},
            {"stage": "sink", "file": "models/user_model.py", "line": 72},
        ]},
    }
    selected = _surfaces_for_finding(finding, endpoints)
    assert [item["path"] for item in selected] == ["/users/v1/{username}"]


def test_http_source_parameter_scopes_model_sink_away_from_stateful_initializer():
    endpoints = [
        {"path": "/createdb", "params": [], "source": "static_openapi"},
        {"path": "/users/v1/{username}", "params": [{"name": "username", "location": "path"}],
         "source": "static_openapi"},
        {"path": "/users/v1/login", "params": [{"name": "email", "location": "json"}],
         "source": "static_openapi"},
        {"path": "/users/v1/register", "params": [{"name": "username", "location": "json"}],
         "source": "static_openapi"},
    ]
    finding = {"file": "models/user_model.py", "start_line": 73,
               "_verify": {"source": "username parameter (from HTTP request)"}}
    assert [item["path"] for item in _surfaces_for_finding(finding, endpoints)] == [
        "/users/v1/{username}"
    ]


def test_assemble_mechanism_confirmed_keeps_needs_review_and_caps_confidence():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "needs_review", "confidence": 0.5}
    harness = {"verdict": "mechanism_confirmed", "dynamically_triggered": False,
               "confidence": 0.9, "function_mechanism_verified": True}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"          # 机理级不升级为确认
    assert f.get("dynamically_verified") is not True
    assert f["function_mechanism_verified"] is True
    assert f["confidence"] <= 0.75                 # 机理级贡献置信度上限 0.75
    ver = f["_evidence"]["verification"]
    assert ver["dynamically_verified"] is False


def test_assemble_mechanism_diagnostic_does_not_downgrade_confirmed_finding():
    pipe = _pipeline()
    f = {"type": "insecure-use-strtok-fn", "status": "confirmed", "confidence": 0.9, "verified": True}
    harness = {"verdict": "mechanism_confirmed", "dynamically_triggered": False,
               "confidence": 0.95, "function_mechanism_verified": True}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "confirmed"
    assert f["verified"] is True
    assert f.get("dynamically_verified") is not True
    assert f["confidence"] == 0.9
    assert f["runtime_verification_status"] == "harness_mechanism_confirmed"


def test_assemble_unsafe_harness_diagnostic_preserves_independent_confirmation():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "confirmed", "confidence": 0.96, "verified": True,
         "dynamically_verified": True}
    harness = {"verdict": "unsafe_harness_blocked", "dynamically_triggered": False,
               "reason": "refused to execute dangerous payload"}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "confirmed"
    assert f["verified"] is True
    assert f["dynamically_verified"] is True
    assert f["runtime_verification_status"] == "unsafe_harness_blocked"


def test_function_reproduced_diagnostic_preserves_confirmed_static_finding():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "confirmed", "confidence": 0.93,
         "verified": True, "dynamically_verified": False}
    harness = {"verdict": "function_reproduced", "dynamically_triggered": False,
               "function_extracted": True, "target_function_called": True,
               "verification_level": "target_specific", "entrypoint_reachable": False,
               "harness_source": "scaffold"}

    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"
    assert f["verified"] is False
    assert f["dynamically_verified"] is False
    assert f["function_unit_reproduced"] is True
    assert f["runtime_verification_status"] == "function_reproduced"
    verification = f["_evidence"]["verification"]
    assert verification["dynamic_method"] == "function_harness"
    assert verification["evidence_level"] == "function_unit_reproduced"
    assert verification["entrypoint_confirmed"] is False
    assert f["_evidence"]["actionable"] is False
    assert f["_evidence"]["exploitable"] is False


# --------------------------------------------------------------------------- #
# 3. 集成：needs_review 的 finding 现在会真正进入动态验证流水线（此前被跳过）         #
# --------------------------------------------------------------------------- #
def test_needs_review_finding_now_enters_pipeline(monkeypatch):
    # 强制无 LLM；若可抽取真实目标，固定 Harness 镜像会优先走更强的 scaffold，
    # 否则才走模板回退。两者都证明 needs_review 已真正进入验证流水线。
    monkeypatch.setattr("backend.verifier.harness_verifier.HarnessVerifier._call",
                        lambda self, content: {})
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 38,
                 "status": "needs_review", "severity": "high",
                 "code_snippet": "os.system(...)"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_exploit=False,
                               enable_dynamic=False, enable_harness=True)
    # 修复前：needs_review 不是 confirmed -> _harness 为 None（被跳过）
    # 修复后：needs_review 动态可验证 -> 进入 Harness 验证
    assert findings[0].get("_harness") is not None
    assert findings[0]["_harness"].get("verdict") in {
        "mechanism_confirmed", "target_confirmed", "function_reproduced",
    }


# --------------------------------------------------------------------------- #
# 4. quick 模式（无 verify）：status = unverified，而非虚假 confirmed              #
# --------------------------------------------------------------------------- #
def _quick_orchestrator() -> OrchestratorAgent:
    orch = object.__new__(OrchestratorAgent)
    orch.scan = SimpleNamespace(id="scan-quick")
    orch.project = SimpleNamespace(id="project-quick")
    orch.config = {"enabled_tools": [], "enabled_agents": [], "options": {}}
    orch._acp_context = ACPContext(
        scan_id=orch.scan.id, project_id=orch.project.id,
        enabled_tools=[], enabled_agents=[], options={},
    )
    orch._stage = lambda *_a, **_k: None
    return orch


def test_quick_mode_status_is_unverified_not_confirmed():
    orch = _quick_orchestrator()
    candidates = [{
        "type": "XSS", "file": "src/app.py", "line": 1, "severity": "medium",
        "code_snippet": "return request.args['q']", "confidence": 0.5,
        "source": "audit_agent", "status": "candidate",
    }]
    results = orch._verify_and_poc(candidates)
    assert len(results) == 1
    assert results[0]["status"] == "unverified"    # 检出未验证，不是虚假 confirmed
    assert results[0]["verified"] is False

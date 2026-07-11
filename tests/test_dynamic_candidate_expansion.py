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
from pathlib import Path
from types import SimpleNamespace

from backend.acp.models import ACPContext
from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent
from backend.agents.orchestrator_agent import OrchestratorAgent
from backend.agents.verify_agent import VerifyAgent
from backend.verifier.pipeline import (
    ExploitPipeline,
    _redact_exploit_for_storage,
    _surfaces_for_finding,
)


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


def test_dynamic_budget_caps_confirmed_and_review_together():
    findings = [
        {"type": "SQL Injection", "status": "confirmed", "severity": "high"}
        for _ in range(4)
    ]
    assert len(ExploitPipeline._select_candidates(findings, 2)) == 2

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


# --------------------------------------------------------------------------- #
# 1. 候选选择：needs_review 动态可验证者纳入，not_applicable/false_positive 排除     #
# --------------------------------------------------------------------------- #
def test_select_candidates_includes_dynamic_applicable_needs_review():
    findings = [
        {"type": "SQL Injection", "status": "confirmed"},
        {"type": "Command Injection", "status": "needs_review"},   # 动态可验证
        {"type": "Hardcoded Secret", "status": "needs_review"},     # not_applicable -> 排除
        {"type": "XSS", "status": "false_positive"},                # 非候选状态 -> 排除
    ]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=20)
    types = [f["type"] for f in picked]
    assert "SQL Injection" in types
    assert "Command Injection" in types          # 核心修复：needs_review 也进入验证
    assert "Hardcoded Secret" not in types       # 静态类无运行时触发点
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


def test_select_candidates_budget_caps_needs_review_but_keeps_confirmed():
    findings = [{"type": "SQL Injection", "status": "confirmed"}]
    findings += [{"type": "Command Injection", "status": "needs_review"} for _ in range(5)]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=3)
    # confirmed 全保留 + 剩余 2 个 needs_review 名额 = 3
    assert len(picked) == 3
    assert picked[0]["status"] == "confirmed"
    assert sum(1 for f in picked if f["status"] == "needs_review") == 2


def test_select_candidates_unlimited_when_budget_non_positive():
    findings = [{"type": "SQL Injection", "status": "confirmed"}]
    findings += [{"type": "Command Injection", "status": "needs_review"} for _ in range(5)]
    picked = ExploitPipeline._select_candidates(findings, max_candidates=0)
    assert len(picked) == 6


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


def test_assemble_mechanism_confirmed_downgrades_weak_confirmed():
    pipe = _pipeline()
    f = {"type": "insecure-use-strtok-fn", "status": "confirmed", "confidence": 0.9, "verified": True}
    harness = {"verdict": "mechanism_confirmed", "dynamically_triggered": False,
               "confidence": 0.95, "function_mechanism_verified": True}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"
    assert f["verified"] is False
    assert f.get("dynamically_verified") is not True
    assert f["confidence"] <= 0.75
    assert any("mechanism" in b.lower() for b in f["confirmed_blockers"])


def test_assemble_unsafe_harness_blocked_clears_dynamic_confirmation():
    pipe = _pipeline()
    f = {"type": "Command Injection", "status": "confirmed", "confidence": 0.96, "verified": True,
         "dynamically_verified": True}
    harness = {"verdict": "unsafe_harness_blocked", "dynamically_triggered": False,
               "reason": "refused to execute dangerous payload"}
    pipe._assemble(f, {}, None, harness, None)

    assert f["status"] == "needs_review"
    assert f["verified"] is False
    assert f["dynamically_verified"] is False
    assert f["runtime_verification_status"] == "unsafe_harness_blocked"


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

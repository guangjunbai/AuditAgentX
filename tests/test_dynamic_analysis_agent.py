"""DynamicAnalysisAgent 测试（离线：plan 决策 + harness 执行，不依赖 LLM/靶场）。"""
from pathlib import Path

from backend.agents.dynamic_analysis_agent import DynamicAnalysisAgent, _derive_dynamic_verdict, _dynamic_summary

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_plan_detects_launch_and_endpoints():
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 29,
                 "status": "confirmed", "severity": "high"}]
    plan = DynamicAnalysisAgent().plan(findings, DEMO)
    assert plan["launch"]["framework"] == "Flask"
    assert plan["endpoint_count"] >= 1
    assert plan["dynamic_applicable_count"] == 1


def test_plan_marks_secret_not_applicable():
    findings = [{"type": "Hardcoded Secret", "file": "app.py", "start_line": 12,
                 "status": "confirmed", "severity": "high"}]
    plan = DynamicAnalysisAgent().plan(findings, DEMO)
    strat = plan["strategies"][0]
    assert strat["applicable"] is False
    assert strat["strategy"] == "not_applicable"


def test_run_harness_command_injection_via_selfcontained_slice(monkeypatch):
    """无 LLM 时命令注入走【自包含切片主力】-> function_reproduced（inline 真实函数体、
    mock 一切外部依赖、桩危险 sink、框架 nonce 证明真实函数被调用），比模板机理更强；
    但仍非入口级完全动态确认（不标记 dynamically_verified）。"""
    # 强制 LLM 返回空；用受控本地执行器模拟 Docker，保证离线确定性
    monkeypatch.setattr("backend.verifier.harness_verifier.HarnessVerifier._call",
                        lambda self, content: {})
    from backend.skills import harness_tools
    monkeypatch.setattr(harness_tools, "_run_in_docker",
                        lambda code, timeout, language, code_root=None, harness_kind=None:
                        harness_tools._run_local(code, timeout, language, "scaffold"))
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 38,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(...)"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_exploit=False,
                               enable_dynamic=False, enable_harness=True)
    harness = findings[0].get("_harness") or {}
    assert harness.get("verdict") == "function_reproduced"       # 切片主力：真实函数级复现
    assert harness.get("dynamically_triggered") is False         # 函数级 != 入口级完全动态确认
    assert harness.get("function_mechanism_verified") is True
    # finding 层：函数级复现不应把它标记为 dynamically_verified
    assert findings[0].get("dynamically_verified") is not True


def test_run_only_touches_confirmed():
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 21,
                 "status": "false_positive", "severity": "high"}]
    DynamicAnalysisAgent().run(findings, code_root=DEMO, enable_harness=True)
    assert findings[0].get("_harness") is None


def test_function_reproduced_harness_not_masked_by_http_not_executed():
    """核心：harness 函数级复现 + HTTP 那路没起靶场(not_executed) 时，动态裁决必须是
    function_reproduced，绝不能被 HTTP 的 not_executed 覆盖成"未执行"。"""
    harness = {"verdict": "function_reproduced", "dynamically_triggered": False,
               "verification_level": "target_specific", "function_extracted": True,
               "target_function_called": True}
    http_not_run = {"reproduction_status": "not_executed"}
    assert _derive_dynamic_verdict(http_not_run, harness) == "function_reproduced"
    summary = _dynamic_summary([{"_harness": harness, "_dynamic": http_not_run}], None)
    assert summary["function_reproduced"] == 1
    assert summary["not_executed"] == 0


def test_not_executed_only_when_both_channels_idle():
    """只有 HTTP 与 harness 两路都没有任何真实执行结果时，才算 not_executed。"""
    assert _derive_dynamic_verdict({"reproduction_status": "not_executed"}, {}) == "not_executed"
    assert _derive_dynamic_verdict({}, {}) == "not_executed"
    # harness 跑了但未触发 -> harness_not_reproduced，不是 not_executed
    assert _derive_dynamic_verdict(
        {"reproduction_status": "not_executed"},
        {"verdict": "not_reproduced"}) == "harness_not_reproduced"


def test_mechanism_harness_does_not_count_as_harness_confirmed():
    harness = {
        "verdict": "mechanism_confirmed",
        "dynamically_triggered": True,
        "verification_level": "template_mechanism",
        "function_extracted": False,
        "target_function_called": False,
    }

    # mechanism 级 harness 确实【执行过】——只是证据弱，绝不能被打成 not_executed
    # （那正是"把已验证误报成未执行"的 bug）。它返回 mechanism_confirmed，但不计入
    # harness_confirmed（后者要求入口/目标级）。
    assert _derive_dynamic_verdict({}, harness) == "mechanism_confirmed"
    summary = _dynamic_summary([{"_harness": harness}], None)
    assert summary["harness_confirmed"] == 0
    assert summary["not_executed"] == 0   # 跑过 mechanism 的不算未执行

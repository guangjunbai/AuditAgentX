"""Fuzzing Harness 动态验证测试（DeepAudit 式，离线不依赖 LLM）。"""
from pathlib import Path

from backend.skills.harness_tools import (
    run_harness, build_template_harness, extract_function,
    TRIGGER_MARKER,
)
from backend.verifier.harness_verifier import HarnessVerifier
from backend.mcp.audit_mcp_server import AuditMCPServer

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_run_harness_detects_trigger():
    harness = (
        'executed=[]\n'
        'import os\n'
        'os.system=lambda c:(executed.append(c),0)[1]\n'
        'os.system("ping ; id")\n'
        'if any(";" in c for c in executed):\n'
        f'    print("{TRIGGER_MARKER}","cmdi")\n'
    )
    r = run_harness(harness)
    assert r["executed"] is True
    assert r["triggered"] is True


def test_template_harness_triggers_each_type():
    for vt in ["Command Injection", "SQL Injection", "Path Traversal", "Insecure Deserialization"]:
        harness = build_template_harness(vt)
        r = run_harness(harness)
        assert r["triggered"] is True, f"{vt} 模板 harness 未触发"


def test_extract_function_from_demo():
    f = extract_function(DEMO, "app.py", 21)
    assert f["found"] is True
    assert "def " in f["function_code"]


def test_mcp_harness_tools_end_to_end():
    srv = AuditMCPServer()
    names = {t["name"] for t in srv.list_tools()}
    assert {"extract_target_function", "generate_fuzzing_harness", "run_fuzzing_harness"} <= names
    h = srv.call_tool("generate_fuzzing_harness", {"vuln_type": "Command Injection"})["structuredContent"]
    r = srv.call_tool("run_fuzzing_harness", {"harness_code": h["harness_code"]})["structuredContent"]
    assert r["triggered"] is True


def test_harness_verifier_template_fallback(monkeypatch):
    # 强制 LLM 返回空 -> 走模板兜底，仍应动态确认
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, content: {})
    hv = HarnessVerifier()
    finding = {"type": "Command Injection", "file": "app.py", "line": 29,
               "start_line": 29, "status": "confirmed", "code_snippet": "os.system(...)"}
    result = hv.run(finding, DEMO, max_retries=1)
    assert result["verdict"] == "confirmed_dynamic"
    assert result["dynamically_triggered"] is True
    assert result["harness_source"] == "template"

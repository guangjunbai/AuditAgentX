"""Fuzzing Harness 动态验证测试（DeepAudit 式，离线不依赖 LLM）。"""
import shutil

import pytest
from pathlib import Path

from backend.skills.harness_tools import (
    run_harness, build_template_harness, extract_function,
    normalize_language, TRIGGER_MARKER,
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


def test_expanded_template_harness_types_trigger():
    """扩类后的模板 Harness：代码注入 / SSTI / XPath / LDAP 都应能触发。"""
    for vt in ["Code Injection", "SSTI", "Server-Side Template Injection",
               "XPath Injection", "LDAP Injection"]:
        harness = build_template_harness(vt)
        r = run_harness(harness)
        assert r["triggered"] is True, f"{vt} 模板 harness 未触发"


def test_expanded_types_not_generic_fallback():
    """新类型应命中专用模板，而非弱的通用 sink 检测兜底。"""
    # 通用兜底里不会出现这些专用 mock 关键字
    assert "fake_eval" in build_template_harness("Code Injection")
    assert "fake_render" in build_template_harness("SSTI")
    assert "fake_xpath" in build_template_harness("XPath Injection")
    assert "fake_search" in build_template_harness("LDAP Injection")


def test_normalize_language():
    assert normalize_language("py") == "python"
    assert normalize_language(".php") == "python"  # 带点后缀不匹配 -> 默认 python
    assert normalize_language("php") == "php"
    assert normalize_language("js") == "javascript"
    assert normalize_language("ts") == "javascript"
    assert normalize_language(None) == "python"
    assert normalize_language("rust") == "python"  # 未知回退


@pytest.mark.skipif(not shutil.which("node"), reason="未安装 node，跳过 JS Harness 执行")
def test_run_harness_javascript_triggers():
    """多语言执行：JavaScript Harness 能被 node 真实运行并识别触发标记。"""
    js = (
        "const executed = [];\n"
        "function target(inp){ executed.push('ping ' + inp); }  // mock sink\n"
        "['127.0.0.1','; id','| whoami'].forEach(p => target(p));\n"
        "if (executed.some(c => c.includes(';') || c.includes('|'))) {\n"
        "  console.log('AUDITAGENTX_VULN_TRIGGERED', 'cmdi(js)');\n"
        "} else { console.log('AUDITAGENTX_NO_TRIGGER'); }\n"
    )
    r = run_harness(js, language="javascript")
    assert r["language"] == "javascript"
    assert r["backend"] == "local"
    assert r["triggered"] is True


def test_run_harness_missing_interpreter_is_honest(monkeypatch):
    """解释器未安装时如实返回 interpreter_unavailable，不造假触发。"""
    monkeypatch.setattr("backend.skills.harness_tools.shutil.which", lambda name: None)
    r = run_harness("<?php echo 'x'; ?>", language="php")
    assert r["triggered"] is False
    assert r["executed"] is False
    assert "interpreter_unavailable" in r["reason"]


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

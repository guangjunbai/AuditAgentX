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
    r = run_harness(harness, source="template")  # 可信模板，允许本地执行
    assert r["executed"] is True
    assert r["triggered"] is True


def test_template_harness_triggers_each_type():
    """模板 Harness 触发时 verdict 应为 mechanism_confirmed（机理级），不是 target_confirmed。"""
    for vt in ["Command Injection", "SQL Injection", "Path Traversal", "Insecure Deserialization"]:
        harness = build_template_harness(vt)
        r = run_harness(harness, source="template")
        assert r["triggered"] is True, f"{vt} 模板 harness 未触发"
        assert r["verdict"] == "mechanism_confirmed", f"{vt} 应为 mechanism_confirmed"
        assert r["verification_level"] == "template_mechanism"


def test_expanded_template_harness_types_trigger():
    """扩类后的模板 Harness：代码注入 / SSTI / XPath / LDAP 都应能触发（机理级）。"""
    for vt in ["Code Injection", "SSTI", "Server-Side Template Injection",
               "XPath Injection", "LDAP Injection"]:
        harness = build_template_harness(vt)
        r = run_harness(harness, source="template")
        assert r["triggered"] is True, f"{vt} 模板 harness 未触发"
        assert r["verdict"] == "mechanism_confirmed"


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
    r = run_harness(js, language="javascript", source="template")
    assert r["language"] == "javascript"
    assert r["backend"] == "local"
    assert r["triggered"] is True


def test_run_harness_missing_interpreter_is_honest(monkeypatch):
    """解释器未安装时如实返回 interpreter_unavailable，不造假触发。"""
    monkeypatch.setattr("backend.skills.harness_tools.shutil.which", lambda name: None)
    r = run_harness("<?php echo 'x'; ?>", language="php", source="template")
    assert r["triggered"] is False
    assert r["executed"] is False
    assert "interpreter_unavailable" in r["reason"]


def test_llm_harness_requires_docker_no_local_exec():
    """LLM 生成的 Harness 在 Docker 不可用且 require_docker=True 时不本地执行 -> sandbox_failed。"""
    r = run_harness('print("AUDITAGENTX_VULN_TRIGGERED")', source="llm", require_docker=True)
    assert r["verdict"] == "sandbox_failed"
    assert r["backend"] == "none"
    assert r["triggered"] is False


def test_unsafe_llm_harness_blocked():
    """LLM Harness 含真实 os.system / requests / subprocess 时应被 unsafe_harness_blocked。"""
    for bad in [
        "import os\nos.system('rm -rf /')",              # 未 mock 的真实 os.system
        "import requests\nrequests.get('http://x')",     # 真实网络
        "import socket\nsocket.socket()",                # 真实 socket
    ]:
        r = run_harness(bad, source="llm", require_docker=False)
        assert r["verdict"] == "unsafe_harness_blocked", bad
        assert r["safety"]["allowed"] is False


def test_llm_target_specific_result_json_is_target_confirmed():
    """LLM target-specific harness 输出 RESULT_JSON(target_function_called) -> target_confirmed。"""
    code = (
        "calls=[]\n"
        "def os_system(c): calls.append(c)  # mock sink\n"
        "def target(x): os_system('ping '+x)  # 真实目标函数\n"
        "target('; id')\n"
        "import json\n"
        "print('AUDITAGENTX_RESULT_JSON=' + json.dumps({"
        "'triggered':True,'target_function_called':True,'sink_called':True,"
        "'sink_name':'os.system','captured_argument':calls[-1],'payload':'; id'}))\n"
    )
    r = run_harness(code, source="llm", require_docker=False)
    assert r["verdict"] == "target_confirmed"
    assert r["verification_level"] == "target_specific"
    assert r["target_function_called"] is True
    assert r["sink_name"] == "os.system"


def test_extract_function_ast_metadata():
    """Python AST 提取应返回 function_name / module_path / imports。"""
    f = extract_function(DEMO, "app.py", 21)
    assert f["found"] is True
    assert f["function_name"] == "get_user"
    assert f["module_path"] == "app"
    assert isinstance(f["imports"], list) and len(f["imports"]) >= 1
    assert f["language"] == "python"


def test_extract_function_from_demo():
    f = extract_function(DEMO, "app.py", 21)
    assert f["found"] is True
    assert "def " in f["function_code"]


def test_mcp_harness_tools_end_to_end():
    srv = AuditMCPServer()
    names = {t["name"] for t in srv.list_tools()}
    assert {"extract_target_function", "generate_fuzzing_harness", "run_fuzzing_harness"} <= names
    h = srv.call_tool("generate_fuzzing_harness", {"vuln_type": "Command Injection"})["structuredContent"]
    r = srv.call_tool("run_fuzzing_harness",
                      {"harness_code": h["harness_code"], "source": "template"})["structuredContent"]
    assert r["triggered"] is True
    assert r["verdict"] == "mechanism_confirmed"


def test_harness_verifier_template_fallback(monkeypatch):
    # 强制 LLM 返回空 -> 走模板兜底：只证明漏洞机理，判 mechanism_confirmed（不是真实可利用）
    monkeypatch.setattr(HarnessVerifier, "_call", lambda self, content: {})
    hv = HarnessVerifier()
    finding = {"type": "Command Injection", "file": "app.py", "line": 38,
               "start_line": 38, "status": "confirmed", "code_snippet": "os.system(...)"}
    result = hv.run(finding, DEMO, max_retries=1)
    assert result["verdict"] == "mechanism_confirmed"
    assert result["harness_source"] == "template"
    # 模板机理 != 完全动态确认
    assert result["dynamically_triggered"] is False
    assert result["function_mechanism_verified"] is True
    assert result["confidence"] <= 0.75


def test_harness_verifier_not_applicable_for_static_type():
    """硬编码密钥等静态类漏洞不适合函数级 Harness -> not_applicable，不执行。"""
    hv = HarnessVerifier()
    finding = {"type": "Hardcoded Secret", "file": "app.py", "line": 16,
               "start_line": 16, "status": "confirmed", "code_snippet": "API_KEY='sk-...'"}
    result = hv.run(finding, DEMO, max_retries=1)
    assert result["verdict"] == "not_applicable"
    assert result["dynamically_triggered"] is False

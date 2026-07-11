"""PoC 文件生成 + 不可变复现元数据测试（作业补项 1 与 3）。

核心诚信保证：只有**框架侧真实动态确认**后才生成 PoC；元数据是可核验的不可变事实。
"""
from pathlib import Path

from backend.verifier.poc_writer import (
    build_reproduction_metadata,
    generate_function_forensic_poc,
    generate_poc_file,
)

_CONFIRMED_EV = {
    "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
    "runtime": {
        "reproduction_status": "dynamic_confirmed",
        "matched_indicator": "AAX_PWNED",
        "response_excerpt": "... AAX_PWNED ...",
        "request": {"url": "http://127.0.0.1:8000/lookup?domain=x", "method": "GET",
                    "param": "domain", "payload": "127.0.0.1 & echo AAX_PWNED"},
    },
    "exploit": {"payloads": ["127.0.0.1 & echo AAX_PWNED"], "_injection_points": ["domain"],
                "http_method": "GET"},
}
_FINDING = {"finding_id": "f_demo1", "type": "Command Injection",
            "file": "vulnapp.py", "start_line": 9}


def test_poc_only_generated_after_real_dynamic_confirmation(tmp_path):
    """未真实动态确认 -> 不生成 PoC（不为机理级/自报成功造 PoC）。"""
    not_confirmed = {"verification": {"dynamically_verified": False}}
    assert generate_poc_file(_FINDING, not_confirmed, tmp_path) is None
    # 机理级也不算
    mech = {"verification": {"dynamically_verified": False, "dynamic_method": "mechanism"}}
    assert generate_poc_file(_FINDING, mech, tmp_path) is None


def test_poc_file_contains_required_reproduction_fields(tmp_path):
    """确认后生成的 PoC 必须含：路径/URL、方法、参数位置、payload、成功判据、运行命令、脱敏环境。"""
    r = generate_poc_file(_FINDING, _CONFIRMED_EV, tmp_path)
    assert r is not None
    body = Path(r["path"]).read_text(encoding="utf-8")
    for token in ("Command Injection", "vulnapp.py:9", "/lookup", "GET",
                  "domain", "echo AAX_PWNED", "AAX_PWNED", "运行命令",
                  "target_guard", "trust_env", "脱敏"):
        assert token in body, f"PoC 缺少必要内容: {token}"


def test_reproduction_metadata_is_immutable_and_hashed(tmp_path):
    """复现元数据必须含不可变可核验字段：PoC hash、请求/响应 hash、生成时间、镜像/commit。"""
    r = generate_poc_file(_FINDING, _CONFIRMED_EV, tmp_path)
    meta = r["reproduction_metadata"]
    for k in ("generated_at", "poc_sha256", "request_hash", "response_hash",
              "dynamic_method", "sandbox_image", "source_commit"):
        assert k in meta
    # hash 是稳定的 sha256（同输入同 hash）
    meta2 = build_reproduction_metadata(_FINDING, _CONFIRMED_EV)
    assert meta2["request_hash"] == meta["request_hash"]
    assert len(meta["request_hash"]) == 64
    # PoC 文件本身的 sha256 与返回一致
    assert len(r["sha256"]) == 64


def test_reproduction_metadata_uses_actual_http_sandbox_image(tmp_path):
    evidence = {**_CONFIRMED_EV, "sandbox": {"status": "started", "mode": "docker",
                                                    "image": "target-app:verified"}}
    r = generate_poc_file(_FINDING, evidence, tmp_path)
    assert r["reproduction_metadata"]["sandbox_image"] == "target-app:verified"


def test_reproduction_metadata_records_default_harness_image_when_unconfigured():
    """harness 在 Docker 跑过、但未配置固定镜像时，元数据须如实记默认基础镜像，不得漏成 None。"""
    ev = {
        "verification": {"dynamically_verified": True, "dynamic_method": "target_harness"},
        "runtime": {},
        "harness": {"execution_backend": "docker", "verification_level": "entrypoint_reproduced"},
    }
    from backend.config import settings
    old = settings.harness_sandbox_image
    settings.harness_sandbox_image = ""  # 未配置固定镜像
    try:
        meta = build_reproduction_metadata(_FINDING, ev)
        assert meta["sandbox_image"] == "python:3.11-slim", "docker 跑过就必有真实镜像，不能是 None"
    finally:
        settings.harness_sandbox_image = old


def test_reproduction_metadata_no_image_when_not_docker():
    """非 Docker 后端（如纯本地模板）不应虚构镜像。"""
    ev = {"verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
          "runtime": {}, "harness": {"execution_backend": "local"}}
    meta = build_reproduction_metadata(_FINDING, ev)
    assert meta["sandbox_image"] is None


def test_poc_redacts_sensitive_values(tmp_path):
    """PoC/元数据必须脱敏敏感字段。"""
    ev = {
        "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
        "runtime": {"reproduction_status": "dynamic_confirmed", "matched_indicator": "token=abc123secret",
                    "request": {"url": "http://127.0.0.1:8000/x?password=hunter2", "method": "GET",
                                "param": "q", "payload": "authorization=Bearer sk-xxx"}},
        "exploit": {},
    }
    r = generate_poc_file(_FINDING, ev, tmp_path)
    body = Path(r["path"]).read_text(encoding="utf-8")
    assert "hunter2" not in body
    assert "sk-xxx" not in body
    assert "REDACTED" in body


def test_authenticated_poc_includes_session_aware_exploit_code(tmp_path):
    evidence = {
        **_CONFIRMED_EV,
        "runtime": {
            **_CONFIRMED_EV["runtime"],
            "setup_records": [{"url": "http://127.0.0.1:8000/login", "status_code": 200}],
        },
        "exploit": {
            **_CONFIRMED_EV["exploit"],
            "exploit_code": (
                "import os\n"
                "password = os.environ.get('AAX_SETUP_PASSWORD', 'CHANGE_ME')\n"
                "# login then replay confirmed request"
            ),
        },
    }
    result = generate_poc_file(_FINDING, evidence, tmp_path)
    body = Path(result["path"]).read_text(encoding="utf-8")
    assert "精确利用代码" in body
    assert "AAX_SETUP_PASSWORD" in body
    assert "AAX_TARGET_URL" in body
    assert "python exploit.py" in body


def _function_evidence():
    return {
        "verification": {"dynamically_verified": False, "evidence_level": "function_unit_reproduced"},
        "harness": {
            "verdict": "function_reproduced", "harness_source": "scaffold",
            "harness_kind": "selfcontained_slice", "execution_backend": "docker",
            "verification_level": "target_specific", "target_function_called": True,
            "harness_code": "# framework scaffold\nprint('safe')",
            "function_code_sha256": "b" * 64,
            "sink_name": "system", "captured_argument": "ping 127.0.0.1; id",
            "payload": "127.0.0.1; id", "sandbox_image": "auditagentx-harness:fixed",
            "nonce_attestation": {"scheme": "sha256", "digest": "a" * 64,
                                  "marker_observed": True},
            "function_location": {"file": "vulnapp.py", "start_line": 7, "end_line": 9,
                                  "function_name": "run_ping"},
        },
    }


def test_function_reproduced_generates_separate_forensic_poc(tmp_path):
    result = generate_function_forensic_poc(_FINDING, _function_evidence(), tmp_path)

    assert result is not None
    assert result["path"].endswith("f_demo1.function-forensic.md")
    body = Path(result["path"]).read_text(encoding="utf-8")
    assert "函数级复现(非端到端)" in body
    assert "selfcontained_slice" in body
    assert "run_ping" in body
    assert "auditagentx-harness:fixed" in body
    assert "a" * 64 in body
    metadata = result["reproduction_metadata"]
    assert metadata["artifact_kind"] == "function_forensic_reproduction"
    assert metadata["function_location"]["start_line"] == 7
    assert metadata["nonce_attestation"]["marker_observed"] is True


def test_function_forensic_poc_requires_framework_nonce_and_docker(tmp_path):
    missing_nonce = _function_evidence()
    missing_nonce["harness"].pop("nonce_attestation")
    assert generate_function_forensic_poc(_FINDING, missing_nonce, tmp_path) is None

    local = _function_evidence()
    local["harness"]["execution_backend"] = "local"
    assert generate_function_forensic_poc(_FINDING, local, tmp_path) is None


def test_pipeline_stores_function_forensic_artifact_separately(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from backend.verifier.pipeline import ExploitPipeline

    monkeypatch.setattr("backend.verifier.pipeline.settings", SimpleNamespace(data_path=tmp_path))
    pipeline = object.__new__(ExploitPipeline)
    pipeline.scan_id = "scan-function"
    pipeline._code_root = None
    finding = {**_FINDING, "status": "needs_review", "verified": False, "confidence": 0.7,
               "_verify": {"source": "host", "sink": "os.system"}}
    harness = _function_evidence()["harness"]

    pipeline._assemble(finding, {}, None, harness, None)

    assert "forensic_poc_file" in finding["_evidence"]
    assert finding["_evidence"]["forensic_poc_file"]["label"] == "函数级复现(非端到端)"
    assert "poc_file" not in finding["_evidence"]
    assert finding.get("dynamically_verified") is not True

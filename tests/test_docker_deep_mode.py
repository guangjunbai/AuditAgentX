"""Docker-first Deep Mode 测试（离线：无 docker 环境验证失败路径不造假）。"""
from pathlib import Path

from backend.dynamic.launch_detector import detect_launch
from backend.dynamic.endpoint_extractor import extract_endpoints
from backend.dynamic.strategy import resolve_strategy
from backend.verifier.docker_project_runner import DockerProjectRunner, build_dockerfile
from backend.verifier.pipeline import ExploitPipeline
from backend.verifier.evidence_collector import EvidenceCollector

DEMO = Path(__file__).resolve().parent.parent / "examples" / "vulnerable_projects" / "demo_flask_app"


def test_launch_plan_has_install_and_run():
    plan = detect_launch(DEMO)
    assert plan["framework"] == "Flask"
    assert plan["install_command"]
    assert plan["run_command"]
    assert plan["port"]


def test_build_dockerfile_python_and_node():
    py = build_dockerfile({"framework": "Flask", "run_command": "python app.py",
                           "install_command": "pip install -r requirements.txt"}, 5000)
    assert "FROM python" in py and "EXPOSE 5000" in py and "app.py" in py
    node = build_dockerfile({"framework": "Express", "run_command": "npm start"}, 3000)
    assert "FROM node" in node and "npm" in node


def test_endpoint_extraction_flask():
    eps = extract_endpoints(DEMO)
    assert eps["count"] >= 1
    assert any(e["framework"] == "flask" for e in eps["endpoints"])


def test_strategy_classification():
    assert resolve_strategy("SQL Injection")["strategy"] in ("http", "both")
    assert resolve_strategy("Command Injection")["strategy"] in ("http", "both")
    assert resolve_strategy("Insecure Deserialization")["strategy"] == "harness"
    assert resolve_strategy("Hardcoded Secret")["strategy"] == "not_applicable"


def _force_no_docker(monkeypatch):
    """强制 Docker 不可用（mock），用于稳定测试失败路径，不依赖真实 Docker 环境。"""
    def _boom(*a, **k):
        raise RuntimeError("docker unavailable (mocked)")
    monkeypatch.setattr("backend.verifier.docker_project_runner.get_docker_client", _boom)


def test_docker_runner_no_docker_returns_sandbox_start_failed(monkeypatch):
    """Docker 不可用时：应如实返回 sandbox_start_failed，不崩、不造假，且给出可读 reason。"""
    _force_no_docker(monkeypatch)
    with DockerProjectRunner(DEMO, {"framework": "Flask", "run_command": "python app.py",
                                    "port": 5000}, scan_id="scan_t") as r:
        assert r.base_url is None
        assert r.metadata["status"] == "sandbox_start_failed"
        # 失败必须携带可读原因（回归：旧实现只有状态标签，无 reason）
        assert r.metadata["reason"]
        assert "docker unavailable" in r.metadata["reason"]


def test_docker_runner_preflight_launch_not_detected(tmp_path, monkeypatch):
    """无自带 Dockerfile 且未识别到启动命令时：预检直接返回 launch_not_detected，
    不再生成 CMD 为空的坏容器、也不会触碰 docker（旧 bug 会塌缩成 sandbox_start_failed）。"""
    # 若预检失效而误调 docker，则抛错暴露问题
    def _should_not_be_called(*a, **k):
        raise AssertionError("预检未通过就不应调用 get_docker_client")
    monkeypatch.setattr(
        "backend.verifier.docker_project_runner.get_docker_client", _should_not_be_called)

    (tmp_path / "main.py").write_text("import somelib\n", encoding="utf-8")
    plan = {"framework": None, "run_command": None, "manual_steps": ["请提供启动命令"]}
    with DockerProjectRunner(tmp_path, plan, scan_id="scan_p") as r:
        assert r.base_url is None
        assert r.metadata["status"] == "launch_not_detected"
        assert "无法自动识别项目启动方式" in r.metadata["reason"]


def test_pipeline_surfaces_sandbox_reason(monkeypatch):
    """沙箱失败原因必须透传到漏洞动态结论（reason），供前端展示为什么没验证。"""
    _force_no_docker(monkeypatch)
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 28,
                 "status": "confirmed", "severity": "high", "code_snippet": "...", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_r"},
                          code_root=DEMO)
    dyn = findings[0]["_dynamic"]
    assert dyn["reproduction_status"] == "sandbox_start_failed"
    assert "沙箱未就绪" in dyn["reason"]
    assert dyn["sandbox"]["reason"]  # 沙箱元信息里带 reason


def test_pipeline_docker_project_failure_not_faked(monkeypatch):
    """docker_project 沙箱失败时，HTTP 类漏洞状态是 sandbox_start_failed，而非 dynamic_confirmed。"""
    _force_no_docker(monkeypatch)
    findings = [{"type": "SQL Injection", "file": "app.py", "start_line": 28,
                 "status": "confirmed", "severity": "high", "code_snippet": "...", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_x"},
                          code_root=DEMO)
    dyn = findings[0]["_dynamic"]
    assert dyn["reproduction_status"] == "sandbox_start_failed"
    assert dyn["reproducible"] is False


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _install_fake_compose(monkeypatch, *, up_rc=0, up_err="", ps_json="", healthy=True):
    """mock docker compose 子进程与健康检查，稳定测试 compose 路径（无需真实多服务项目）。"""
    def _run(cmd, **kw):
        if "up" in cmd:
            return _FakeProc(up_rc, "", up_err)
        if "ps" in cmd:
            return _FakeProc(0, ps_json, "")
        if "logs" in cmd:
            return _FakeProc(0, "compose logs...", "")
        return _FakeProc(0, "", "")  # down 等
    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run", _run)
    monkeypatch.setattr("backend.verifier.docker_project_runner._wait_healthy",
                        lambda *a, **k: healthy)


_PS_JSON = ('[{"Service":"web","Publishers":['
            '{"URL":"0.0.0.0","TargetPort":8080,"PublishedPort":49157,"Protocol":"tcp"}]}]')


def test_docker_compose_started(tmp_path, monkeypatch):
    """检测到 docker-compose 时走 compose 编排，解析发布端口并健康检查通过。"""
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")
    _install_fake_compose(monkeypatch, ps_json=_PS_JSON, healthy=True)
    plan = {"compose": "docker-compose.yml", "port": 8080, "health_path": "/"}
    with DockerProjectRunner(tmp_path, plan, scan_id="scan_c") as r:
        assert r.metadata["status"] == "started"
        assert r.base_url == "http://127.0.0.1:49157"
        assert r.metadata["mode"] == "docker_compose"


def test_docker_compose_up_failure_has_reason(tmp_path, monkeypatch):
    """compose up 失败时如实返回失败状态并携带 reason，不造假。"""
    (tmp_path / "docker-compose.yml").write_text("services:\n  web:\n    build: .\n", encoding="utf-8")
    _install_fake_compose(monkeypatch, up_rc=1, up_err="service web failed to build")
    plan = {"compose": "docker-compose.yml"}
    with DockerProjectRunner(tmp_path, plan, scan_id="scan_c2") as r:
        assert r.base_url is None
        assert r.metadata["status"] == "sandbox_start_failed"
        assert "failed to build" in r.metadata["reason"]


def test_compose_published_port_parses_jsonl(tmp_path, monkeypatch):
    """_compose_published_port 兼容逐行 JSON（不同 compose 版本），并优先匹配 port_hint。"""
    jsonl = ('{"Service":"db","Publishers":[{"TargetPort":5432,"PublishedPort":5432,"Protocol":"tcp"}]}\n'
             '{"Service":"web","Publishers":[{"TargetPort":8080,"PublishedPort":33001,"Protocol":"tcp"}]}')
    monkeypatch.setattr("backend.verifier.docker_project_runner.subprocess.run",
                        lambda cmd, **kw: _FakeProc(0, jsonl, ""))
    runner = DockerProjectRunner(tmp_path, {}, scan_id="scan_p2")
    assert runner._compose_published_port("proj", 8080) == 33001  # 命中 hint
    assert runner._compose_published_port("proj", None) == 5432   # 无 hint 取第一个


def test_pipeline_target_harness_confirmed_when_sandbox_failed(monkeypatch):
    """HTTP 沙箱起不来但目标函数级 Harness(target_confirmed) 触发时：回退为动态确认，不至于纯失败。"""
    _force_no_docker(monkeypatch)
    monkeypatch.setattr(
        "backend.verifier.harness_verifier.HarnessVerifier.run",
        lambda self, f, code_root: {"dynamically_triggered": True, "verdict": "target_confirmed",
                                    "confidence": 0.97, "harness_code": "def test(): ...",
                                    "trigger_detail": "mock", "target_function_called": True},
    )
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 40,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(x)", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=True, enable_harness=True,
                          dynamic_target={"mode": "docker_project", "scan_id": "scan_h"},
                          code_root=DEMO)
    f = findings[0]
    assert f["dynamically_verified"] is True
    assert f["dynamic_method"] == "target_harness"
    assert f["runtime_verification_status"] == "harness_target_confirmed"
    assert f["_dynamic"]["harness_confirmed"] is True
    assert "Harness" in f["_dynamic"]["reason"]


def test_pipeline_mechanism_harness_not_fully_dynamic(monkeypatch):
    """模板机理级 Harness(mechanism_confirmed) 不应把 finding 标记为完全 dynamically_verified。"""
    _force_no_docker(monkeypatch)
    monkeypatch.setattr(
        "backend.verifier.harness_verifier.HarnessVerifier.run",
        lambda self, f, code_root: {"dynamically_triggered": False, "verdict": "mechanism_confirmed",
                                    "function_mechanism_verified": True, "confidence": 0.75,
                                    "harness_code": "..."},
    )
    findings = [{"type": "Command Injection", "file": "app.py", "start_line": 40,
                 "status": "confirmed", "severity": "high", "code_snippet": "os.system(x)", "_verify": {}}]
    ExploitPipeline().run(findings, enable_exploit=False, enable_dynamic=False, enable_harness=True,
                          code_root=DEMO)
    f = findings[0]
    assert f.get("dynamically_verified") is not True         # 机理级不算完全动态确认
    assert f.get("function_mechanism_verified") is True
    assert f.get("runtime_verification_status") == "harness_mechanism_confirmed"


def test_pipeline_parallel_exploit_generation_preserves_order(monkeypatch):
    """并行利用生成：结果按输入顺序一一对应，每条 finding 都被完整装配。"""
    import time

    def _slow_exploit(self, f):
        time.sleep(0.05)  # 制造耗时，串行会明显更慢；仅验证正确性/顺序
        return {"vuln_type": f.get("type"), "trigger_location": f"{f.get('file')}:1",
                "payloads": ["p"], "success_indicators": ["x"], "exploit_code": "code"}
    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", _slow_exploit)

    findings = [
        {"type": "SQL Injection", "file": "a.py", "start_line": 1, "status": "confirmed",
         "severity": "high", "code_snippet": "...", "_verify": {}},
        {"type": "Command Injection", "file": "b.py", "start_line": 2, "status": "confirmed",
         "severity": "high", "code_snippet": "...", "_verify": {}},
        {"type": "XSS", "file": "c.py", "start_line": 3, "status": "confirmed",
         "severity": "medium", "code_snippet": "...", "_verify": {}},
    ]
    ExploitPipeline().run(findings, enable_exploit=True, enable_dynamic=False, enable_harness=False)

    # 顺序保持：每条 finding 的利用方案对应自己的类型/位置
    assert findings[0]["_exploit"]["trigger_location"] == "a.py:1"
    assert findings[1]["_exploit"]["vuln_type"] == "Command Injection"
    assert findings[2]["_exploit"]["trigger_location"] == "c.py:1"
    # 每条都完成装配
    for f in findings:
        assert "_exploit" in f and "_evidence" in f
        assert f["_exploit"] is not findings[0]["_exploit"] or f is findings[0]  # 各自独立 dict


def test_pipeline_parallel_worker_failure_isolated(monkeypatch):
    """并行阶段单条任务抛异常不影响其余任务（返回默认值兜底）。"""
    def _maybe_boom(self, f):
        if f.get("file") == "boom.py":
            raise RuntimeError("exploit gen failed")
        return {"vuln_type": f.get("type"), "payloads": [], "success_indicators": []}
    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", _maybe_boom)

    findings = [
        {"type": "SQL Injection", "file": "ok.py", "start_line": 1, "status": "confirmed",
         "severity": "high", "_verify": {}},
        {"type": "SQL Injection", "file": "boom.py", "start_line": 2, "status": "confirmed",
         "severity": "high", "_verify": {}},
    ]
    ExploitPipeline().run(findings, enable_exploit=True, enable_dynamic=False, enable_harness=False)
    assert findings[0]["_exploit"]["vuln_type"] == "SQL Injection"
    assert findings[1]["_exploit"] == {}          # 失败条目兜底为独立空 dict
    assert "_evidence" in findings[1]             # 仍完成装配


def test_evidence_collector_emits_sandbox_and_candidate_endpoints():
    sandbox = {"mode": "docker_project", "status": "sandbox_start_failed",
               "image": "auditagentx-x", "health_check": "failed", "launch_command": "python app.py"}
    dynamic = {"reproduction_status": "sandbox_start_failed", "reproducible": False,
               "candidate_endpoints": ["/user", "/ping"], "records": [], "logs": []}
    ev = EvidenceCollector.build({}, dynamic=dynamic, sandbox=sandbox)
    assert ev["sandbox"]["status"] == "sandbox_start_failed"
    assert ev["runtime"]["reproduction_status"] == "sandbox_start_failed"
    assert ev["runtime"]["candidate_endpoints"] == ["/user", "/ping"]
    assert ev["runtime"]["sandbox"]["mode"] == "docker_project"

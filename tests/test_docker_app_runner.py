"""普通 Docker 动态目标的失败闭合测试。"""
from contextlib import contextmanager

import pytest

from backend.verifier import app_runner
from backend.verifier.pipeline import _resolve_target
from backend.verifier.pipeline import ExploitPipeline


class _FakeContainer:
    status = "exited"

    def __init__(self):
        self.removed = False

    def reload(self):
        return None

    def logs(self, **kwargs):
        return b"Traceback: dependency mismatch\npassword=do-not-store"

    def remove(self, force=False):
        self.removed = bool(force)


class _FakeContainers:
    def __init__(self, container):
        self.container = container

    def run(self, **kwargs):
        return self.container


class _FakeClient:
    def __init__(self, container):
        self.containers = _FakeContainers(container)


def test_docker_app_runner_raises_structured_health_failure_and_cleans_up(monkeypatch):
    container = _FakeContainer()
    monkeypatch.setattr(app_runner, "get_docker_client", lambda: _FakeClient(container))
    monkeypatch.setattr(app_runner, "_free_port", lambda: 49152)
    monkeypatch.setattr(app_runner, "_wait_healthy", lambda *args, **kwargs: False)

    with pytest.raises(app_runner.DockerTargetStartError) as captured:
        with app_runner.DockerAppRunner("broken:latest", internal_port=5002,
                                        health_timeout=1):
            raise AssertionError("unhealthy target must never be yielded")

    metadata = captured.value.metadata
    assert metadata["status"] == "health_check_failed"
    assert metadata["container_status"] == "exited"
    assert "dependency mismatch" in metadata["logs_excerpt"]
    assert container.removed is True


def test_pipeline_resolve_target_returns_failure_metadata_instead_of_dead_url(monkeypatch):
    @contextmanager
    def failed_runner(*args, **kwargs):
        raise app_runner.DockerTargetStartError({
            "status": "health_check_failed", "mode": "docker",
            "image": "broken:latest", "reason": "container exited",
            "logs_excerpt": "startup failed",
        })
        yield  # pragma: no cover

    monkeypatch.setattr(app_runner, "DockerAppRunner", failed_runner)
    with _resolve_target({
        "mode": "docker", "image": "broken:latest", "internal_port": 5002,
        "endpoints": ["/search"],
    }) as resolved:
        base_url, endpoints, metadata, logs = resolved

    assert base_url is None
    assert endpoints == ["/search"]
    assert metadata["status"] == "health_check_failed"
    assert logs is None


def test_failed_docker_target_skips_llm_and_preserves_failure_status(monkeypatch):
    @contextmanager
    def failed_runner(*args, **kwargs):
        raise app_runner.DockerTargetStartError({
            "status": "health_check_failed", "mode": "docker",
            "image": "broken:latest", "reason": "dependency mismatch",
            "logs_excerpt": "startup failed",
        })
        yield  # pragma: no cover

    monkeypatch.setattr(app_runner, "DockerAppRunner", failed_runner)
    pipeline = ExploitPipeline(scan_id="failed-target")
    pipeline.exploit_agent.run = lambda finding: (_ for _ in ()).throw(
        AssertionError("failed target must not spend an LLM call"))
    finding = {
        "finding_id": "f-sqli", "type": "SQL Injection", "severity": "high",
        "status": "needs_review", "file": "app.py", "start_line": 9,
    }

    result = pipeline.run(
        [finding], enable_exploit=True, enable_dynamic=True, enable_harness=False,
        dynamic_target={
            "mode": "docker", "image": "broken:latest", "internal_port": 5002,
            "endpoints": ["/search"],
        },
    )[0]

    assert result["_dynamic"]["reproduction_status"] == "health_check_failed"
    assert result["_dynamic"]["sandbox"]["logs_excerpt"] == "startup failed"
    assert result["_exploit"]["_from_template"] is True

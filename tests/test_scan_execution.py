"""Cancellable subprocess execution tests (real local processes, no Docker)."""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from backend.acp.models import ACPContext
from backend.agents.orchestrator_agent import OrchestratorAgent, ScanCancelled

from backend.runtime.scan_execution import (
    SandboxCommandTimeout,
    begin_scan,
    finish_scan,
    is_cancelled,
    register_cleanup_callback,
    register_managed_process,
    request_cancel,
    run_managed_command,
    unregister_cleanup_callback,
)


def test_managed_command_timeout_terminates_the_process_tree(tmp_path):
    marker = tmp_path / "child-survived.txt"
    child_code = (
        "import pathlib,time; time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('alive', encoding='utf-8')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "time.sleep(10)"
    )
    scan_id = "managed-timeout-tree"
    begin_scan(scan_id)
    started = time.monotonic()
    try:
        with pytest.raises(SandboxCommandTimeout) as caught:
            run_managed_command(
                scan_id, [sys.executable, "-c", parent_code], cwd=tmp_path,
                env=None, timeout=0.15, phase="test_timeout",
            )
        assert caught.value.phase == "test_timeout"
        assert time.monotonic() - started < 3
        time.sleep(1.0)
        assert not marker.exists(), "timed-out child process was not terminated"
    finally:
        finish_scan(scan_id)


def test_register_after_cancel_immediately_terminates_process_and_cancel_is_idempotent():
    scan_id = "cancel-register-race"
    begin_scan(scan_id)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        first = request_cancel(scan_id)
        assert is_cancelled(scan_id) is True

        registered = []
        thread = threading.Thread(
            target=lambda: registered.append(register_managed_process(scan_id, proc))
        )
        thread.start()
        thread.join(timeout=3)

        assert registered == [False]
        assert proc.wait(timeout=3) is not None
        assert request_cancel(scan_id) == 0
        assert first == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        finish_scan(scan_id)


def test_orchestrator_dynamic_generic_catch_does_not_swallow_user_cancellation(tmp_path):
    orchestrator = object.__new__(OrchestratorAgent)
    orchestrator.scan = type("Scan", (), {"id": "cancel-dynamic", "config_json": "{}"})()
    orchestrator.project = type("Project", (), {"id": "project-cancel"})()
    orchestrator.config = {
        "enabled_agents": [],
        "options": {"enable_dynamic": True, "dynamic_target": {"mode": "url"}},
    }
    orchestrator._acp_context = ACPContext(
        scan_id=orchestrator.scan.id, project_id=orchestrator.project.id,
        enabled_tools=[], enabled_agents=[], options={},
    )
    orchestrator._stage = lambda *_args, **_kwargs: None
    orchestrator._dispatch_acp = lambda _request: (_ for _ in ()).throw(RuntimeError("dispatch failed"))
    orchestrator._cancel_requested = lambda: True

    with pytest.raises(ScanCancelled):
        orchestrator._verify_and_poc([
            {
                "type": "SQL Injection", "file": "app.py", "line": 1,
                "severity": "high", "status": "candidate", "confidence": 0.7,
            }
        ], tmp_path)


def test_cancel_callbacks_are_thread_safe_idempotent_and_exception_isolated():
    scan_id = "cancel-cleanup-callbacks"
    calls = []
    begin_scan(scan_id)
    try:
        good = register_cleanup_callback(scan_id, lambda: calls.append("good"))
        bad = register_cleanup_callback(scan_id, lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        assert good is not None and bad is not None

        threads = [threading.Thread(target=request_cancel, args=(scan_id,)) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

        assert calls == ["good"]
        unregister_cleanup_callback(scan_id, good)
        unregister_cleanup_callback(scan_id, bad)
        assert request_cancel(scan_id) == 0
    finally:
        finish_scan(scan_id)


def test_windows_taskkill_failure_uses_cim_fallback_before_parent_kill(monkeypatch):
    import backend.runtime.scan_execution as execution

    calls = []

    class Proc:
        pid = 4242
        killed = False

        def poll(self):
            return 1 if self.killed else None

        def kill(self):
            calls.append("parent-kill")
            self.killed = True

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[0] == "taskkill":
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(execution.os, "name", "nt")
    monkeypatch.setattr(execution.subprocess, "run", fake_run)

    assert execution._terminate_process_tree(Proc()) is True

    assert calls[0][0] == "taskkill"
    assert calls[1][0].lower().endswith("powershell")
    assert "Get-CimInstance Win32_Process" in calls[1][-1]
    assert calls[-1] == "parent-kill"


def test_process_tree_termination_does_not_claim_success_while_parent_is_alive(monkeypatch):
    import backend.runtime.scan_execution as execution

    class StubbornProc:
        pid = 4343

        def poll(self):
            return None

        def kill(self):
            pass

    monkeypatch.setattr(execution.os, "name", "nt")
    monkeypatch.setattr(
        execution.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )

    assert execution._terminate_process_tree(StubbornProc()) is False


def test_persist_cancel_race_rolls_back_and_raises_scan_cancelled():
    orchestrator = object.__new__(OrchestratorAgent)
    orchestrator.scan = SimpleNamespace(id="persist-cancel", status="running")

    class FakeDb:
        def __init__(self):
            self.added = []
            self.rollback_called = False
            self.committed = False

        def add(self, value):
            self.added.append(value)
            orchestrator.scan.status = "cancelling"

        def refresh(self, _scan):
            pass

        def rollback(self):
            self.rollback_called = True
            self.added.clear()

        def commit(self):
            self.committed = True

    orchestrator.db = FakeDb()
    orchestrator._stage = lambda *_args: None

    with pytest.raises(ScanCancelled):
        orchestrator._persist([{
            "type": "SQL Injection", "severity": "high", "file": "app.py",
            "line": 1, "status": "needs_review",
        }])

    assert orchestrator.db.rollback_called is True
    assert orchestrator.db.committed is False
    assert orchestrator.db.added == []


def test_final_transition_cancellation_between_guard_and_commit_converges_to_cancelled():
    """即使取消紧贴最终提交到达，也不能让 done 覆盖 cancelled。"""
    from backend.runtime.scan_execution import request_cancel

    scan_id = "final-commit-cancel-race"
    begin_scan(scan_id)
    try:
        orchestrator = object.__new__(OrchestratorAgent)
        orchestrator.scan = SimpleNamespace(
            id=scan_id, status="running", progress=95, current_stage="Persisting",
            error=None, finished_at=None,
        )
        orchestrator.config = {"enabled_tools": [], "scanner_status": []}

        class FakeDb:
            def __init__(self):
                self.commits = []

            def refresh(self, _scan):
                pass

            def rollback(self):
                pass

            def commit(self):
                self.commits.append(orchestrator.scan.status)
                # Model the cancellation latch arriving after the final guard but
                # before the commit returns to the orchestrator.
                if len(self.commits) == 1:
                    request_cancel(scan_id)

        orchestrator.db = FakeDb()

        with pytest.raises(ScanCancelled):
            orchestrator._finish_success([])

        assert orchestrator.scan.status == "cancelled"
        assert orchestrator.db.commits == ["done", "cancelled"]
    finally:
        finish_scan(scan_id)


def test_final_transition_completes_normally_without_a_cancellation_latch():
    scan_id = "final-commit-normal"
    begin_scan(scan_id)
    try:
        orchestrator = object.__new__(OrchestratorAgent)
        orchestrator.scan = SimpleNamespace(
            id=scan_id, status="running", progress=95, current_stage="Persisting",
            error=None, finished_at=None,
        )
        orchestrator.config = {"enabled_tools": [], "scanner_status": []}
        orchestrator.db = SimpleNamespace(
            refresh=lambda _scan: None,
            rollback=lambda: None,
            commit=lambda: None,
        )

        orchestrator._finish_success([])

        assert orchestrator.scan.status == "done"
        assert orchestrator.scan.progress == 100
        assert orchestrator.scan.current_stage == "finished"
    finally:
        finish_scan(scan_id)


def test_persist_keeps_the_previous_visible_scan_stage():
    """保存结果是内部动作，不能把 UI 阶段改成长期停留的 Persisting。"""
    scan_id = "persist-keeps-visible-stage"
    begin_scan(scan_id)
    try:
        orchestrator = object.__new__(OrchestratorAgent)
        orchestrator.scan = SimpleNamespace(
            id=scan_id, status="running", progress=88,
            current_stage="ExploitAgent/DynamicVerify",
        )
        orchestrator._raise_if_cancelled = lambda: None
        orchestrator._persist_db_mutations = lambda _findings: None
        orchestrator._stage = lambda *_args: pytest.fail(
            "_persist must not replace the user-visible scan stage"
        )

        orchestrator._persist([{"_evidence": {}}])

        assert orchestrator.scan.current_stage == "ExploitAgent/DynamicVerify"
        assert orchestrator.scan.progress == 88
    finally:
        finish_scan(scan_id)

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts" / "run_deep_target_api.py"
SPEC = importlib.util.spec_from_file_location("run_deep_target_api", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(runner)


def test_aggregate_metrics_uses_strict_http_records_and_strategy_counts():
    findings = [
        {
            "finding": {"finding_id": "f1", "type": "SQL Injection"},
            "evidence": {
                "runtime": {
                    "reproduction_status": "dynamic_confirmed",
                    "reproducible": True,
                    "records": [
                        {"role": "baseline", "url": "http://target/", "method": "GET", "status_code": 200},
                        {"role": "attack", "url": "http://target/?id=x", "method": "GET", "status_code": 500},
                    ],
                    "sandbox": {"status": "ready"},
                },
                "harness": {"verdict": "target_confirmed"},
            },
        },
        {
            "finding": {"finding_id": "f2", "type": "Hardcoded Secret"},
            "evidence": {
                "runtime": {
                    "reproduction_status": "not_runtime_verifiable",
                    "records": [{"role": "baseline", "url": "http://target/", "method": "GET", "status_code": 200}],
                },
                "harness": {"verdict": "not_executed"},
            },
        },
        {
            "finding": {"finding_id": "f3", "type": "XSS"},
            "evidence": {
                "runtime": {
                    "reproduction_status": "blocked",
                    "reason": "authorization_blocked",
                    "confirmation_records": [
                        {"url": "http://target/search", "method": "GET", "status_code": 403}
                    ],
                },
                "harness": {"verdict": "sandbox_failed"},
                "sandbox": {"status": "failed"},
            },
        },
        {
            "finding": {"finding_id": "f4", "type": "Command Injection"},
            "evidence": {
                "runtime": {"reproduction_status": "not_reproduced", "records": []},
                "harness": {"verdict": "not_reproduced"},
            },
        },
    ]

    def strategy(vulnerability_type):
        return {
            "strategy": "not_applicable" if vulnerability_type == "Hardcoded Secret" else "http"
        }

    metrics = runner.aggregate_metrics(
        findings,
        {
            "stage_detail": {"raw_finding_count": 9, "elapsed_seconds": 42},
            "error": None,
        },
        strategy_resolver=strategy,
    )

    assert metrics["raw_static_count"] == 9
    assert metrics["persisted_findings"] == 4
    assert metrics["dynamic_candidates"] == 3
    assert metrics["not_applicable"] == 1
    assert metrics["strict_http_executed"] == 2
    assert metrics["strict_http_executed_finding_ids"] == ["f1", "f3"]
    assert metrics["blocked"] == 1
    assert metrics["not_reproduced"] == 1
    assert metrics["dynamic_confirmed"] == 1
    assert metrics["sandbox_status"] == {"ready": 1, "failed": 1}
    assert metrics["harness_verdict"] == {
        "target_confirmed": 1,
        "not_executed": 1,
        "sandbox_failed": 1,
        "not_reproduced": 1,
    }
    assert metrics["elapsed_seconds"] == 42
    assert any("authorization_blocked" in item for item in metrics["problems"])


def test_aggregate_metrics_prefers_runtime_candidate_total_and_strict_verdicts():
    findings = [
        {
            "finding": {"finding_id": "f1", "type": "SQL Injection", "status": "confirmed"},
            "evidence": {
                "runtime": {
                    "reproduction_status": "dynamic_confirmed",
                    "reproducible": False,
                }
            },
        },
        {
            "finding": {"finding_id": "f2", "type": "XSS", "status": "needs_review"},
            "evidence": {"runtime": {"reproduction_status": "state_contamination_blocked"}},
        },
        {
            "finding": {"finding_id": "f3", "type": "Hardcoded Secret", "status": "confirmed"},
            "evidence": {},
        },
        {
            "finding": {"finding_id": "f4", "type": "Hardcoded Secret", "status": "false_positive"},
            "evidence": {},
        },
    ]

    def strategy(vulnerability_type):
        return {
            "strategy": "not_applicable" if vulnerability_type == "Hardcoded Secret" else "http"
        }

    metrics = runner.aggregate_metrics(
        findings,
        {"stage_detail": {"dynamic_total": 2}},
        strategy_resolver=strategy,
    )

    assert metrics["dynamic_candidates"] == 2
    assert metrics["not_applicable"] == 1
    assert metrics["blocked"] == 0
    assert metrics["dynamic_confirmed"] == 0


def test_redact_secrets_recurses_and_sanitizes_urls_and_bearer_values():
    value = {
        "api_key": "sk-live-secret",
        "nested": {
            "Authorization": "Bearer abc.def.ghi",
            "repo": "https://alice:password@example.test/repo.git?token=query-secret&ref=main",
        },
        "safe": "visible",
        "code": "password = embedded-secret",
        "items": [{"password": "hunter2"}],
    }

    redacted = runner.redact_secrets(value)
    serialized = json.dumps(redacted)

    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["nested"]["Authorization"] == "[REDACTED]"
    assert redacted["safe"] == "visible"
    assert "embedded-secret" not in redacted["code"]
    assert redacted["items"][0]["password"] == "[REDACTED]"
    assert "alice" not in serialized
    assert "password" not in redacted["nested"]["repo"]
    assert "query-secret" not in serialized
    assert "ref=main" in redacted["nested"]["repo"]


def test_poll_scan_terminal_returns_terminal_response_without_extra_fetch():
    responses = iter([
        {"scan_id": "s1", "status": "queued"},
        {"scan_id": "s1", "status": "running"},
        {"scan_id": "s1", "status": "partial_completed", "progress": 100},
    ])
    calls = []
    clock_values = iter([0.0, 0.1, 0.2, 0.3])

    result = runner.poll_scan_terminal(
        lambda: calls.append(True) or next(responses),
        poll_interval=0,
        overall_timeout=5,
        sleep=lambda _: None,
        monotonic=lambda: next(clock_values),
    )

    assert result["status"] == "partial_completed"
    assert len(calls) == 3


def test_poll_scan_terminal_rejects_malformed_and_times_out():
    with pytest.raises(runner.PollingError, match="status"):
        runner.poll_scan_terminal(
            lambda: {"scan_id": "s1"},
            poll_interval=0,
            overall_timeout=5,
            sleep=lambda _: None,
            monotonic=lambda: 0,
        )


def test_api_client_disables_environment_proxies(monkeypatch):
    observed = {}

    class FakeOpener:
        pass

    def fake_build_opener(*handlers):
        observed["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr(runner, "build_opener", fake_build_opener, raising=False)

    client = runner.ApiClient("http://127.0.0.1:8000")

    assert isinstance(client._opener, FakeOpener)
    assert len(observed["handlers"]) == 1
    assert observed["handlers"][0].proxies == {}

    clock_values = iter([0.0, 0.0, 2.0])
    with pytest.raises(TimeoutError, match="last status=running"):
        runner.poll_scan_terminal(
            lambda: {"scan_id": "s1", "status": "running"},
            poll_interval=0,
            overall_timeout=1,
            sleep=lambda _: None,
            monotonic=lambda: next(clock_values),
        )


def test_cleanup_guard_only_removes_immediate_matching_project_child(tmp_path):
    root = tmp_path / "data" / "projects"
    target = root / "proj_123"
    target.mkdir(parents=True)
    (target / "clone.txt").write_text("clone", encoding="utf-8")

    assert runner.cleanup_project_workspace(root, "proj_123") is True
    assert not target.exists()

    outside = tmp_path / "user-project"
    outside.mkdir()
    with pytest.raises(runner.CleanupSafetyError):
        runner.cleanup_project_workspace(root, str(outside))
    assert outside.exists()
    with pytest.raises(runner.CleanupSafetyError):
        runner.cleanup_project_workspace(root, "../user-project")
    assert outside.exists()


def test_cleanup_guard_removes_readonly_git_pack(tmp_path):
    root = tmp_path / "projects"
    pack = root / "proj_readonly" / ".git" / "objects" / "pack" / "pack.idx"
    pack.parent.mkdir(parents=True)
    pack.write_bytes(b"git-pack-index")
    pack.chmod(0o444)

    assert runner.cleanup_project_workspace(root, "proj_readonly") is True
    assert not (root / "proj_readonly").exists()

def test_cleanup_guard_rejects_root_and_symlink_targets(tmp_path):
    root = tmp_path / "projects"
    root.mkdir()

    with pytest.raises(runner.CleanupSafetyError):
        runner.cleanup_project_workspace(root, ".")
    assert root.exists()

    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "proj_link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this Windows host")

    with pytest.raises(runner.CleanupSafetyError):
        runner.cleanup_project_workspace(root, "proj_link")
    assert outside.exists()

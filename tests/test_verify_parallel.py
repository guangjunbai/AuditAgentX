from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from backend.acp.models import ACPContext
from backend.agents.orchestrator_agent import OrchestratorAgent


def _candidate(idx: int) -> dict:
    return {
        "type": "XSS",
        "file": f"src/app_{idx}.py",
        "line": idx + 1,
        "severity": "medium",
        "code_snippet": "return request.args['q']",
        "confidence": 0.5,
        "source": "audit_agent",
        "status": "candidate",
    }


def _orchestrator(max_verify_workers: int = 4) -> OrchestratorAgent:
    orch = object.__new__(OrchestratorAgent)
    orch.scan = SimpleNamespace(id="scan-parallel")
    orch.project = SimpleNamespace(id="project-parallel")
    orch.config = {
        "enabled_tools": [],
        "enabled_agents": ["audit", "verify"],
        "options": {"max_verify_workers": max_verify_workers},
    }
    orch._acp_context = ACPContext(
        scan_id=orch.scan.id,
        project_id=orch.project.id,
        enabled_tools=[],
        enabled_agents=["audit", "verify"],
        options=orch.config["options"],
    )
    orch._stage = lambda *_args, **_kwargs: None
    return orch


def _reply(static_verdict: str = "confirmed", confidence: float = 0.7) -> SimpleNamespace:
    return SimpleNamespace(
        payload={
            "verification": {
                "static_verdict": static_verdict,
                "dynamic_verdict": "not_executed",
                "final_verdict": static_verdict,
            },
            "knowledge": {},
        },
        status=SimpleNamespace(confidence=confidence),
    )


def test_verify_agent_static_review_runs_in_parallel() -> None:
    orch = _orchestrator(max_verify_workers=4)
    lock = threading.Lock()
    active = 0
    max_active = 0
    seen_indexes: list[int] = []

    def dispatch(request):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
            seen_indexes.append(request.payload["verify_index"])
        time.sleep(0.05)
        with lock:
            active -= 1
        return _reply(confidence=0.75)

    orch._dispatch_acp = dispatch
    results = orch._verify_and_poc([_candidate(i) for i in range(4)])

    assert max_active > 1
    assert sorted(seen_indexes) == [0, 1, 2, 3]
    assert all(item["status"] == "confirmed" for item in results)
    assert all(item["verified"] is True for item in results)


def test_verify_agent_static_review_failure_degrades_to_needs_review() -> None:
    orch = _orchestrator(max_verify_workers=3)

    def dispatch(request):
        if request.payload["verify_index"] == 1:
            raise RuntimeError("verify backend unavailable")
        return _reply(confidence=0.8)

    orch._dispatch_acp = dispatch
    results = orch._verify_and_poc([_candidate(i) for i in range(3)])
    by_file = {item["file"]: item for item in results}

    assert by_file["src/app_0.py"]["status"] == "confirmed"
    assert by_file["src/app_2.py"]["status"] == "confirmed"
    failed = by_file["src/app_1.py"]
    assert failed["status"] == "needs_review"
    assert failed["verified"] is False
    assert failed["_verify"]["static_verdict"] == "needs_review"
    assert "verify backend unavailable" in failed["_verify"]["false_positive_reason"]

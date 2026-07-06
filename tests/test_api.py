"""API 冒烟测试（不触发 LLM）。"""
from fastapi.testclient import TestClient

from backend.main import app
from backend.database import SessionLocal
from backend.core import ids
from backend.models import Finding, Project, Scan

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_agents_list():
    r = client.get("/api/agents")
    assert r.status_code == 200
    assert r.json()["total"] >= 5


def test_create_and_parse_local_project():
    r = client.post("/api/projects", json={
        "name": "demo_flask_app", "source_type": "local",
        "local_path": "examples/vulnerable_projects/demo_flask_app",
    })
    assert r.status_code == 200
    pid = r.json()["project_id"]

    r2 = client.post(f"/api/projects/{pid}/parse")
    assert r2.status_code == 200
    assert "Python" in r2.json()["metadata"]["languages"]

    r3 = client.get(f"/api/projects/{pid}/tree")
    assert r3.status_code == 200
    assert any(item["path"] == "app.py" for item in r3.json()["tree"])


def test_verify_finding_api_records_evidence(monkeypatch):
    class FakeDynamicResult:
        def __init__(self):
            self.verified = True
            self.reproducible = True
            self.matched_indicator = "SQL syntax"
            self.confirmed_record = {
                "url": "http://target.local/user",
                "method": "GET",
                "params": {"id": "1' OR '1'='1"},
                "payload": "1' OR '1'='1",
                "status_code": 200,
                "response_excerpt": "You have an error in your SQL syntax",
                "elapsed_ms": 12,
            }
            self.records = [self.confirmed_record]
            self.logs = ["matched test indicator"]
            self.skipped = False
            self.reason = ""
            self.error = ""

    def fake_exploit_run(self, finding):
        return {
            "vuln_type": "SQL Injection",
            "trigger_location": "app.py:21",
            "exploit_path": "id parameter reaches SQL string concatenation",
            "attack_vector": "HTTP GET id",
            "payloads": ["1' OR '1'='1"],
            "exploit_code": "print('local poc')",
            "verification_method": "match SQL syntax indicator",
            "success_indicators": ["SQL syntax"],
            "impact": "unauthorized data read",
        }

    def fake_verify(self, base_url, exploit, endpoints=None):
        return FakeDynamicResult()

    monkeypatch.setattr("backend.agents.exploit_agent.ExploitAgent.run", fake_exploit_run)
    monkeypatch.setattr("backend.verifier.dynamic_verifier.DynamicVerifier.verify", fake_verify)

    db = SessionLocal()
    project = Project(
        id=ids.project_id(), name="api_verify_demo", source_type="local",
        local_path="examples/vulnerable_projects/demo_flask_app", status="created",
    )
    db.add(project)
    db.commit()
    scan = Scan(id=ids.scan_id(), project_id=project.id, scan_type="static", status="done")
    db.add(scan)
    db.commit()
    finding = Finding(
        id=ids.finding_id(), scan_id=scan.id, type="SQL Injection", severity="high",
        file_path="app.py", start_line=21,
        code_snippet='cur.execute("select * from users where id=" + uid)',
        confidence=0.7, verified=False, status="confirmed",
    )
    db.add(finding)
    db.commit()
    fid = finding.id
    db.close()

    r = client.post(f"/api/findings/{fid}/verify", json={
        "mode": "url",
        "base_url": "http://target.local",
        "endpoints": ["/user"],
        "timeout": 5,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert body["reproducible"] is True
    assert body["matched_indicator"] == "SQL syntax"
    assert body["evidence_id"]

    ev = client.get(f"/api/findings/{fid}/evidence")
    assert ev.status_code == 200
    evidence = ev.json()["evidence"]
    assert evidence["exploit"]["trigger_location"] == "app.py:21"
    assert evidence["runtime"]["reproducible"] is True
    assert evidence["runtime"]["response_status"] == 200

    detail = client.get(f"/api/findings/{fid}")
    assert detail.status_code == 200
    assert detail.json()["verification"]["reproducible"] is True

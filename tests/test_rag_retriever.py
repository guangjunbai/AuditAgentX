from backend.rag.retriever import SecurityKnowledgeRetriever
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.skills.loader import load_skill
from backend.verifier.evidence_collector import EvidenceCollector


def test_retriever_maps_sql_injection_to_cwe_and_playbook():
    candidate = {
        "type": "SQL Injection",
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "code_snippet": "cursor.execute('select * from users where id=' + uid)",
    }

    result = SecurityKnowledgeRetriever().retrieve(candidate=candidate, limit=2)

    assert result["top_result"]["cwe_id"] == "CWE-89"
    assert "A03:2021 Injection" in result["summary"]["owasp"]
    assert result["summary"]["verification_checks"]


def test_retriever_filters_verification_playbooks():
    candidate = {"type": "Command Injection", "sink": "subprocess.run", "source": "req.body"}

    result = SecurityKnowledgeRetriever().retrieve_playbook(candidate)

    assert result["top_result"]["id"] == "PLAYBOOK-COMMAND-INJECTION"
    assert result["top_result"]["source_type"] == "verification_playbook"
    assert result["summary"]["dynamic_strategy"] == "harness_or_sandbox_http"


def test_retriever_filters_remediation_guides():
    candidate = {"type": "SQL Injection", "sink": "db.query"}

    result = SecurityKnowledgeRetriever().retrieve_remediation(candidate)

    assert result["top_result"]["id"] == "FIX-SQLI"
    assert any("parameterized" in item.lower() for item in result["summary"]["remediation"])


def test_mcp_verification_skill_includes_knowledge_tools():
    candidate = {
        "type": "SQL Injection",
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "code_snippet": "cursor.execute('select * from users where id=' + uid)",
    }

    context = AuditMCPClient().run_verification_skill(candidate, None, load_skill("vulnerability-verification"))

    tool_names = [tool["name"] for tool in context["tools_used"]]
    assert "retrieve_security_knowledge" in tool_names
    assert "retrieve_verification_playbook" in tool_names
    assert "retrieve_remediation_advice" in tool_names
    assert context["knowledge_result"]["top_result"]["cwe_id"] == "CWE-89"
    assert context["playbook_result"]["top_result"]["id"] == "PLAYBOOK-SQLI"


def test_evidence_collector_preserves_knowledge_evidence():
    verify_result = {
        "source": "request.args['id']",
        "sink": "cursor.execute",
        "knowledge": {
            "cwe_id": "CWE-89",
            "owasp": ["A03:2021 Injection"],
            "verification_checks": ["Confirm source reaches SQL sink."],
            "false_positive_signals": ["Prepared statement is present."],
            "remediation": ["Use parameterized queries."],
            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        },
    }

    evidence = EvidenceCollector.build(verify_result)

    assert evidence["knowledge"]["cwe_id"] == "CWE-89"
    assert "A03:2021 Injection" in evidence["knowledge"]["owasp"]
    assert any("安全知识增强" in log for log in evidence["logs"])

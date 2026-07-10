from backend.agents.summary_agent import SummaryAgent
from backend.report import report_builder


def test_summary_agent_fallback_covers_workflow_and_recommendations(monkeypatch):
    monkeypatch.setattr(SummaryAgent, "_llm_enabled", staticmethod(lambda: False))
    project = {
        "name": "maccms10",
        "url": "https://github.com/magicblack/maccms10",
        "local_path": None,
        "languages": ["PHP", "JavaScript"],
        "frameworks": [],
        "file_count": 856,
        "loc": 253912,
    }
    scan = {"id": "scan_demo", "scan_type": "full", "status": "done", "config": {}}
    findings = [
        {
            "type": "SQL Injection",
            "severity": "high",
            "file": "app/controller/User.php",
            "start_line": 21,
            "confidence": 0.86,
            "source": "semgrep",
            "verified": True,
            "status": "confirmed",
            "evidence": {
                "runtime": {"reproducible": True},
                "exploit": {"exploit_path": "request id reaches SQL sink"},
            },
        },
        {
            "type": "Path Traversal",
            "severity": "medium",
            "file": "app/controller/File.php",
            "start_line": 42,
            "confidence": 0.7,
            "source": "audit_agent",
            "verified": False,
            "status": "candidate",
            "evidence": None,
        },
    ]
    stats = report_builder.severity_stats(findings)

    summary = SummaryAgent(scan_id="scan_demo").run(project, scan, findings, stats)

    assert "maccms10" in summary["executive_summary"]
    assert "RepoParserAgent" in summary["executive_summary"]
    assert "StaticScanAgent" in "\n".join(summary["workflow_summary"])
    assert "VerifyAgent" in "\n".join(summary["workflow_summary"])
    assert "静态分析" in summary["static_summary"]
    assert "动态验证" in summary["dynamic_summary"]
    assert summary["overall_risk"] == "high"
    assert summary["remediation_plan"]

    ctx = report_builder.build_context(project, scan, findings, summary)
    html = report_builder.render_html(ctx)
    assert "多智能体工作流" in html
    assert "SummaryAgent 修改建议" in html
    assert "动态验证总结" in html


def test_summary_does_not_count_mechanism_self_report_as_target_confirmation(monkeypatch):
    monkeypatch.setattr(SummaryAgent, "_llm_enabled", staticmethod(lambda: False))
    findings = [{
        "type": "Command Injection", "severity": "high", "status": "needs_review",
        "evidence": {
            "runtime": {"reproduction_status": "not_executed", "skipped": True},
            "harness": {
                "verdict": "mechanism_confirmed", "dynamically_triggered": True,
                "verification_level": "template_mechanism", "function_extracted": False,
                "target_function_called": False,
            },
        },
    }]
    ctx = SummaryAgent(scan_id="s")._build_context(
        {"name": "demo"}, {"config": {}}, findings,
        report_builder.severity_stats(findings),
    )

    assert ctx["dynamic_total"] == 0
    assert ctx["dynamic_breakdown"]["harness_target_confirmed"] == 0
    assert ctx["dynamic_breakdown"]["harness_mechanism_confirmed"] == 1

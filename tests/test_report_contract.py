import json

from backend.report import report_builder


def _confirmed_finding():
    return {
        "finding_id": "f-report", "type": "SQL Injection", "severity": "high",
        "file": "app.py", "start_line": 21, "status": "confirmed", "verified": True,
        "_evidence": {
            "call_path": [
                {"stage": "source", "file": "app.py", "line": 18, "detail": "request.args[id]"},
                {"stage": "sink", "file": "app.py", "line": 21, "detail": "cursor.execute"},
            ],
            "exploit": {"exploit_code": "import httpx\n# exact confirmed request"},
            "runtime": {"reproduction_status": "dynamic_confirmed", "reproducible": True},
            "verification": {"dynamically_verified": True, "dynamic_method": "http_dynamic"},
            "knowledge": {"remediation": ["Use parameterized queries."]},
            "poc_file": {"path": "pocs/f-report.md", "sha256": "abc123"},
            "reproduction_metadata": {
                "source_commit": "deadbeef", "sandbox_image": "target:verified",
                "request_hash": "reqhash", "response_hash": "resphash",
            },
        },
    }


def test_structured_reports_preserve_required_dynamic_contract():
    ctx = report_builder.build_context(
        {"name": "demo"}, {"id": "scan-report", "scan_type": "deep"},
        [_confirmed_finding()], {"dynamic_breakdown": {}, "remediation_plan": []},
    )

    normalized = ctx["findings"][0]
    assert normalized["severity"] == "high"
    assert normalized["evidence"]["call_path"][1]["detail"] == "cursor.execute"
    assert "parameterized" in normalized["fix_suggestion"]

    markdown = report_builder.render_markdown(ctx)
    html = report_builder.render_html(ctx)
    structured = json.loads(json.dumps(ctx, ensure_ascii=False))
    for output in (markdown, html):
        assert "SQL Injection" in output
        assert "cursor.execute" in output
        assert "exact confirmed request" in output
        assert "Use parameterized queries" in output
        assert "pocs/f-report.md" in output
        assert "target:verified" in output
    assert structured["findings"][0]["evidence"]["verification"]["dynamically_verified"] is True

"""ACP 适配器测试：finding 字段统一转换 + legacy↔ACP 互转。

全部离线，无 LLM，无网络。
"""
from __future__ import annotations

import pytest
from backend.acp.adapters import (
    raw_finding_to_acp,
    audit_finding_to_acp,
    legacy_finding_to_acp,
    acp_to_legacy_finding,
    legacy_dict_to_message,
    message_to_legacy_dict,
)
from backend.acp.models import ACPMessageType


# ---------------------------------------------------------------------------
# RawFinding → ACP finding
# ---------------------------------------------------------------------------

class _RawFindingMock:
    """最小 RawFinding mock（不依赖真实扫描器）。"""
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_raw_finding_to_acp_maps_location():
    """RawFinding → ACP: location.file 和 location.start_line 必须正确映射。"""
    rf = _RawFindingMock(
        type="SQL Injection",
        file="backend/app.py",
        line=42,
        severity="high",
        source="semgrep",
        code_snippet="cur.execute(sql + uid)",
        message="字符串拼接 SQL",
        rule_id="sqli-001",
        extra={},
    )
    result = raw_finding_to_acp(rf)
    assert result["type"] == "SQL Injection"
    assert result["severity"] == "high"
    assert result["location"]["file"] == "backend/app.py"
    assert result["location"]["start_line"] == 42
    assert result["code"]["snippet"] == "cur.execute(sql + uid)"
    assert result["source"]["tool"] == "semgrep"
    assert result["source"]["rule_id"] == "sqli-001"
    assert result["source"]["agent"] == "static_scan_agent"
    assert result["description"] == "字符串拼接 SQL"


def test_raw_finding_to_acp_generates_finding_id():
    """RawFinding → ACP: finding_id 必须被自动生成（非空字符串）。"""
    rf = _RawFindingMock(
        type="Command Injection", file="run.py", line=5,
        severity="critical", source="bandit",
        code_snippet="os.system(cmd)", message="", rule_id="", extra={},
    )
    result = raw_finding_to_acp(rf)
    assert result["finding_id"], "finding_id 不得为空"
    assert len(result["finding_id"]) > 8


# ---------------------------------------------------------------------------
# AuditAgent finding → ACP finding
# ---------------------------------------------------------------------------

def test_audit_finding_to_acp_maps_vulnerability_type():
    """AuditAgent finding → ACP: vulnerability_type → type。"""
    lf = {
        "vulnerability_type": "Path Traversal",
        "severity": "medium",
        "file_path": "api/files.py",
        "start_line": 18,
        "end_line": 20,
        "vulnerable_code": "open(path + filename)",
        "confidence": 0.8,
        "fix_suggestion": "使用 os.path.abspath 校验",
    }
    result = audit_finding_to_acp(lf)
    assert result["type"] == "Path Traversal"
    assert result["location"]["file"] == "api/files.py"
    assert result["location"]["start_line"] == 18
    assert result["code"]["snippet"] == "open(path + filename)"
    assert result["source"]["agent"] == "audit_agent"
    assert result["extra"]["confidence"] == pytest.approx(0.8)
    assert result["extra"]["fix_suggestion"] == "使用 os.path.abspath 校验"


def test_audit_finding_to_acp_handles_missing_fields():
    """AuditAgent finding → ACP: 缺少字段时不应抛异常。"""
    lf = {"vulnerability_type": "Hardcoded Secret"}
    result = audit_finding_to_acp(lf)
    assert result["type"] == "Hardcoded Secret"
    assert result["severity"] == "medium"
    assert result["location"]["file"] is None


# ---------------------------------------------------------------------------
# ACP finding → legacy dict（向后兼容）
# ---------------------------------------------------------------------------

def test_acp_to_legacy_finding_roundtrip():
    """统一 ACP finding → legacy dict，字段必须可供旧代码读取。"""
    acp = {
        "finding_id": "f-abc",
        "type": "Command Injection",
        "severity": "critical",
        "location": {"file": "cmd.py", "start_line": 7, "end_line": 7},
        "code": {"snippet": "os.system(cmd)"},
        "source": {"agent": "audit_agent", "tool": "bandit", "rule_id": "B605"},
        "description": "命令注入",
        "extra": {"confidence": 0.95, "verified": False, "status": "candidate"},
    }
    legacy = acp_to_legacy_finding(acp)
    assert legacy["type"] == "Command Injection"
    assert legacy["severity"] == "critical"
    assert legacy["file"] == "cmd.py"
    assert legacy["start_line"] == 7
    assert legacy["line"] == 7
    assert legacy["code_snippet"] == "os.system(cmd)"
    assert legacy["source"] == "bandit"
    assert legacy["confidence"] == pytest.approx(0.95)
    assert legacy["status"] == "candidate"


def test_legacy_finding_to_acp_maps_old_fields():
    """旧散字段 finding → ACP: file/start_line/line 都应映射。"""
    old = {
        "type": "SQL Injection",
        "severity": "high",
        "file": "db.py",
        "start_line": 30,
        "line": 30,
        "code_snippet": "cursor.execute(q + v)",
        "source": "semgrep",
        "confidence": 0.7,
    }
    result = legacy_finding_to_acp(old)
    assert result["type"] == "SQL Injection"
    assert result["location"]["file"] == "db.py"
    assert result["location"]["start_line"] == 30


# ---------------------------------------------------------------------------
# legacy dict ↔ ACPMessage
# ---------------------------------------------------------------------------

def test_legacy_dict_to_message_wraps_payload():
    """legacy_dict_to_message: 原始 dict 进入 payload 字段。"""
    d = {"type": "XSS", "severity": "medium"}
    msg = legacy_dict_to_message(
        d,
        sender="test_agent",
        receiver="orchestrator",
        message_type=ACPMessageType.AUDIT_RESULT,
        scan_id="scan-001",
    )
    assert msg.payload == d
    assert msg.header.sender == "test_agent"
    assert msg.context.scan_id == "scan-001"
    assert msg.header.message_type == ACPMessageType.AUDIT_RESULT


def test_message_to_legacy_dict_returns_payload():
    """message_to_legacy_dict: 有 payload 时直接返回 payload dict。"""
    from backend.acp.factory import make_message
    msg = make_message(
        sender="a",
        receiver="b",
        message_type=ACPMessageType.VERIFY_RESULT,
        payload={"is_valid": True, "confidence": 0.88},
    )
    legacy = message_to_legacy_dict(msg)
    assert legacy["is_valid"] is True
    assert legacy["confidence"] == pytest.approx(0.88)

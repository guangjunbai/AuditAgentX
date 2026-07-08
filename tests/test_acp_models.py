"""ACP 协议模型测试：ACPMessage 结构完整性验证。

全部离线：无 LLM 调用，无网络，无真实 HTTP。
"""
from __future__ import annotations

import pytest
from backend.acp.models import (
    ACPMessage, ACPHeader, ACPContext, ACPStatus,
    ACPVerdict, ACPMessageType, ACPState,
    ACPFinding, ACPVerification, ACPExploit,
    ACPToolCall, ACPArtifact,
)
from backend.acp.factory import make_message, make_reply


# ---------------------------------------------------------------------------
# ACPMessage 基本结构
# ---------------------------------------------------------------------------

def test_acp_message_has_required_sections():
    """ACPMessage 必须包含 header / context / payload / status 四个主节。"""
    msg = make_message(
        sender="orchestrator",
        receiver="verify_agent",
        message_type=ACPMessageType.VERIFY_REQUEST,
        intent="测试消息",
        payload={"key": "value"},
        context=ACPContext(scan_id="s1", project_id="p1"),
    )
    assert msg.header is not None
    assert msg.context is not None
    assert msg.payload is not None
    assert msg.status is not None


def test_acp_header_protocol_fields():
    """ACPHeader 必须有 protocol='AuditAgentX-ACP' 及自动生成字段。"""
    msg = make_message(
        sender="agent_a",
        receiver="agent_b",
        message_type=ACPMessageType.AUDIT_REQUEST,
    )
    h = msg.header
    assert h.protocol == "AuditAgentX-ACP"
    assert h.version == "1.0"
    assert h.message_id  # 自动生成
    assert h.timestamp   # 自动生成
    assert h.trace_id    # 自动生成
    assert h.sender == "agent_a"
    assert h.receiver == "agent_b"


def test_acp_context_carries_scan_info():
    """ACPContext 应正确传递 scan_id / project_id / enabled_tools。"""
    ctx = ACPContext(
        scan_id="scan-xyz",
        project_id="proj-abc",
        enabled_tools=["semgrep", "gitleaks"],
        enabled_agents=["audit", "verify"],
        options={"enable_exploit": True},
    )
    msg = make_message(
        sender="orch",
        receiver="agent",
        message_type=ACPMessageType.SCAN_START,
        context=ctx,
    )
    assert msg.context.scan_id == "scan-xyz"
    assert msg.context.project_id == "proj-abc"
    assert "semgrep" in msg.context.enabled_tools
    assert msg.context.options["enable_exploit"] is True


def test_acp_status_default_is_success():
    """ACPStatus 默认状态为 success，裁决和置信度可选。"""
    msg = make_message(sender="a", receiver="b", message_type=ACPMessageType.HEARTBEAT)
    assert msg.status.state == ACPState.SUCCESS
    assert msg.status.verdict is None
    assert msg.status.confidence is None


def test_acp_status_with_verdict_and_confidence():
    """状态可携带 verdict 和 confidence。"""
    msg = make_message(
        sender="verify_agent",
        receiver="orchestrator",
        message_type=ACPMessageType.VERIFY_RESULT,
        state=ACPState.SUCCESS,
        verdict=ACPVerdict.STATICALLY_VERIFIED,
        confidence=0.92,
    )
    assert msg.status.verdict == ACPVerdict.STATICALLY_VERIFIED
    assert msg.status.confidence == pytest.approx(0.92)


def test_acp_verdict_enum_covers_all_required_values():
    """ACPVerdict 必须覆盖任务要求的全部裁决值。"""
    required = {
        "candidate", "statically_verified", "false_positive",
        "exploit_generated", "dynamic_confirmed", "not_reproduced",
        "not_executed", "connection_failed", "endpoint_not_found",
        "request_timeout", "harness_confirmed", "harness_inconclusive",
    }
    available = {v.value for v in ACPVerdict}
    assert required <= available, f"缺少裁决值: {required - available}"


def test_acp_message_type_covers_key_types():
    """ACPMessageType 必须覆盖验证/利用/动态验证流程的消息类型。"""
    required_types = {
        "verify.request", "verify.result",
        "exploit.generate.request", "exploit.generate.result",
        "scan.start", "scan.complete",
    }
    available = {t.value for t in ACPMessageType}
    assert required_types <= available


def test_make_reply_inherits_context():
    """make_reply 必须继承 request 的 context / conversation_id / trace_id。"""
    req = make_message(
        sender="orch",
        receiver="verify_agent",
        message_type=ACPMessageType.VERIFY_REQUEST,
        context=ACPContext(scan_id="s99"),
        conversation_id="conv-123",
    )
    reply = make_reply(
        req,
        sender="verify_agent",
        message_type=ACPMessageType.VERIFY_RESULT,
        payload={"result": "ok"},
        verdict=ACPVerdict.CONFIRMED,
        confidence=0.85,
    )
    assert reply.header.receiver == "orch"          # 回复给原发送方
    assert reply.header.sender == "verify_agent"
    assert reply.header.in_reply_to == req.header.message_id
    assert reply.header.conversation_id == req.header.conversation_id
    assert reply.header.trace_id == req.header.trace_id
    assert reply.context.scan_id == "s99"           # 继承 context


def test_acp_message_serialization_roundtrip():
    """ACPMessage 必须能序列化为 dict 并无损反序列化。"""
    original = make_message(
        sender="sender",
        receiver="receiver",
        message_type=ACPMessageType.EXPLOIT_GENERATE_REQUEST,
        payload={"finding": {"type": "SQL Injection"}},
        verdict=ACPVerdict.EXPLOIT_GENERATED,
        confidence=0.75,
    )
    data = original.to_dict()
    restored = ACPMessage.from_dict(data)
    assert restored.header.message_id == original.header.message_id
    assert restored.header.sender == "sender"
    assert restored.status.verdict == original.status.verdict
    assert restored.payload == original.payload


# ---------------------------------------------------------------------------
# ACPFinding / ACPVerification / ACPExploit 内嵌模型
# ---------------------------------------------------------------------------

def test_acp_finding_has_unified_structure():
    """ACPFinding 必须包含 location / code / source 三个子结构。"""
    f = ACPFinding(
        finding_id="f-001",
        type="SQL Injection",
        severity="high",
        location={"file": "app.py", "start_line": 10, "end_line": 10},
        code={"snippet": "cur.execute('SELECT ' + uid)"},
        source={"agent": "audit_agent", "tool": "semgrep", "rule_id": "sql-001"},
        description="用户输入未转义直接拼接 SQL",
        extra={"confidence": 0.9},
    )
    assert f.type == "SQL Injection"
    assert f.location["file"] == "app.py"
    assert f.code["snippet"]
    assert f.source["agent"] == "audit_agent"


def test_acp_verification_default_dynamic_verdict_is_not_executed():
    """ACPVerification 默认 dynamic_verdict 必须是 not_executed 而非 not_reproduced。"""
    v = ACPVerification()
    assert v.dynamic_verdict == "not_executed", (
        "未配置动态目标时，dynamic_verdict 必须是 not_executed，不能是 not_reproduced"
    )


def test_acp_tool_call_structure():
    """ACPToolCall 必须记录 tool_name / input / output / success。"""
    tc = ACPToolCall(
        tool_name="read_code_context",
        input={"candidate": {}, "radius": 8},
        output={"found": True},
        success=True,
    )
    assert tc.tool_name == "read_code_context"
    assert tc.success is True


# ---------------------------------------------------------------------------
# LLM 输出类型不可靠时的防御性强制转换（回归：字符串 call_path/evidence_chain 崩溃）
# ---------------------------------------------------------------------------

def test_acp_verification_coerces_wrong_llm_types():
    """LLM 把 call_path 输出成字符串、evidence_chain 输出成字符串时，不应抛 ValidationError。"""
    v = ACPVerification(
        static_verdict="confirmed",
        call_path="contrib/cmake/git-version.py:63-65",     # 应为 list，LLM 给了 str
        evidence_chain="构建脚本，无外部输入，无实际利用路径。",  # 应为 dict，LLM 给了 str
    )
    assert isinstance(v.call_path, list)
    assert v.call_path[0]["detail"] == "contrib/cmake/git-version.py:63-65"
    assert isinstance(v.evidence_chain, dict)
    assert v.evidence_chain["summary"].startswith("构建脚本")
    # 列表里混入非 dict 元素也应被规整
    v2 = ACPVerification(call_path=["a.py:1", {"stage": "sink", "detail": "x"}])
    assert all(isinstance(hop, dict) for hop in v2.call_path)


def test_acp_exploit_coerces_str_lists():
    """payloads / success_indicators 被 LLM 输出成单个字符串时，统一转成 list。"""
    e = ACPExploit(vuln_type="SQLi", payloads="1 OR 1=1", success_indicators="SQL syntax error")
    assert e.payloads == ["1 OR 1=1"]
    assert e.success_indicators == ["SQL syntax error"]

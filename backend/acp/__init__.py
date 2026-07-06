"""AuditAgentX ACP（Agent Communication Protocol）通信协议包。

按北邮 ACP 字段思想，统一多 Agent 间的消息接口：
  - models.py   : ACPMessage 数据模型
  - factory.py  : 便捷消息构造器
  - adapters.py : legacy dict ↔ ACPMessage 互转 + finding 字段统一
  - trace.py    : 消息持久化与回放
"""
from __future__ import annotations

from backend.acp.models import (
    ACPMessage,
    ACPHeader,
    ACPContext,
    ACPStatus,
    ACPVerdict,
    ACPMessageType,
    ACPState,
)
from backend.acp.factory import make_message, make_reply
from backend.acp.adapters import (
    raw_finding_to_acp,
    audit_finding_to_acp,
    acp_to_legacy_finding,
    legacy_dict_to_message,
    message_to_legacy_dict,
)
from backend.acp.trace import ACPTracer

__all__ = [
    "ACPMessage", "ACPHeader", "ACPContext", "ACPStatus",
    "ACPVerdict", "ACPMessageType", "ACPState",
    "make_message", "make_reply",
    "raw_finding_to_acp", "audit_finding_to_acp", "acp_to_legacy_finding",
    "legacy_dict_to_message", "message_to_legacy_dict",
    "ACPTracer",
]

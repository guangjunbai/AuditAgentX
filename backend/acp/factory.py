"""ACP 消息工厂：自动填充 message_id / timestamp / trace_id 等。

所有 Agent 构造 ACPMessage 时应优先使用此模块，避免手动拼装。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from backend.acp.models import (
    ACPMessage, ACPHeader, ACPContext, ACPStatus,
    ACPMessageType, ACPState, ACPVerdict,
)


def _now_iso() -> str:
    """返回 UTC ISO 8601 时间戳。"""
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


def make_message(
    *,
    sender: str,
    receiver: str,
    message_type: ACPMessageType | str,
    intent: str = "",
    conversation_id: str = "",
    task_id: str = "",
    trace_id: str = "",
    in_reply_to: str | None = None,
    context: ACPContext | None = None,
    payload: dict[str, Any] | None = None,
    tools: list | None = None,
    artifacts: list | None = None,
    state: ACPState = ACPState.SUCCESS,
    verdict: ACPVerdict | str | None = None,
    confidence: float | None = None,
    error: str | None = None,
    **kwargs: Any,
) -> ACPMessage:
    """构造一条完整的 ACPMessage，自动填充 message_id / timestamp 等。

    Parameters
    ----------
    sender:          发送方 Agent 名称
    receiver:        接收方 Agent 名称
    message_type:    消息类型（ACPMessageType 枚举或字符串）
    intent:          人类可读意图描述
    conversation_id: 所属会话 ID
    task_id:         所属任务 ID（通常为 scan_id）
    trace_id:        跨消息追踪 ID；缺省自动生成一个
    in_reply_to:     被回复消息的 message_id
    context:         ACPContext 对象；传 None 则构造空 context
    payload:         业务 payload dict
    tools:           MCP tool 调用列表（ACPToolCall）
    artifacts:       附件列表（ACPArtifact）
    state:           消息状态
    verdict:         裁决结果
    confidence:      置信度
    error:           错误信息（state=failed 时填写）
    """
    header = ACPHeader(
        message_id=_new_id(),
        conversation_id=conversation_id or _new_id(),
        task_id=task_id,
        sender=sender,
        receiver=receiver,
        message_type=message_type,
        intent=intent,
        timestamp=_now_iso(),
        trace_id=trace_id or _new_id(),
        in_reply_to=in_reply_to,
    )
    status = ACPStatus(
        state=state,
        verdict=verdict,
        confidence=confidence,
    )
    return ACPMessage(
        header=header,
        context=context or ACPContext(),
        payload=payload or {},
        tools=tools or [],
        artifacts=artifacts or [],
        status=status,
        error=error,
    )


def make_reply(
    request: ACPMessage,
    *,
    sender: str,
    message_type: ACPMessageType | str,
    intent: str = "",
    payload: dict[str, Any] | None = None,
    tools: list | None = None,
    artifacts: list | None = None,
    state: ACPState = ACPState.SUCCESS,
    verdict: ACPVerdict | str | None = None,
    confidence: float | None = None,
    error: str | None = None,
) -> ACPMessage:
    """在 request 基础上构造回复消息，自动继承 context / conversation_id / trace_id。

    Parameters
    ----------
    request:      原始请求消息
    sender:       回复方 Agent 名称
    message_type: 回复消息类型
    """
    return make_message(
        sender=sender,
        receiver=request.header.sender,
        message_type=message_type,
        intent=intent,
        conversation_id=request.header.conversation_id,
        task_id=request.header.task_id,
        trace_id=request.header.trace_id,
        in_reply_to=request.header.message_id,
        context=request.context,
        payload=payload,
        tools=tools,
        artifacts=artifacts,
        state=state,
        verdict=verdict,
        confidence=confidence,
        error=error,
    )

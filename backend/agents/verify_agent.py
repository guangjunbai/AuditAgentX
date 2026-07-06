"""VerifyAgent: independent MCP+Skill review agent for candidate findings.

新增 run_acp() 方法，输入/输出符合 AuditAgentX-ACP 协议：
  输入：message_type="verify.request"，payload.finding 为统一 finding 结构
  输出：message_type="verify.result"，payload.verification 含静/动/综合裁决
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.agents.verification_tools import build_verification_context
from backend.mcp.audit_mcp_client import AuditMCPClient
from backend.skills.loader import load_skill


logger = logging.getLogger(__name__)


class VerifyAgent(BaseAgent):
    name = "verify_agent"
    prompt_file = "verify_agent_prompt.md"

    def run(self, candidate: dict[str, Any], code_root: Path | None = None) -> dict[str, Any]:
        """Review one candidate finding and return a normalized verdict."""
        tool_context = self._build_mcp_skill_context(candidate, code_root)
        user_content = json.dumps({
            "candidate_finding": candidate,
            "tool_evidence": tool_context,
            "instruction": (
                "Use the MCP+Skill tool_evidence to independently confirm or reject the finding. "
                "Return JSON with is_valid, false_positive_reason, confidence, source, "
                "sink, propagation_path, call_path, tool_calls, evidence_chain, "
                "required_runtime_conditions, and recommended_poc_strategy."
            ),
        }, ensure_ascii=False)

        llm_result = self._call(user_content)
        if not isinstance(llm_result, dict):
            llm_result = {"_error": "verify_agent returned non-dict output"}

        return self._merge_verdict(candidate, tool_context, llm_result)

    def run_batch(self, candidates: list[dict[str, Any]],
                  code_root: Path | None = None) -> list[dict[str, Any]]:
        return [self.run(c, code_root=code_root) for c in candidates]

    @staticmethod
    def _build_mcp_skill_context(candidate: dict[str, Any], code_root: Path | None) -> dict[str, Any]:
        try:
            skill = load_skill("vulnerability-verification")
            return AuditMCPClient().run_verification_skill(candidate, code_root, skill)
        except Exception as exc:  # noqa: BLE001
            logger.exception("MCP+Skill verification failed, falling back to local tools: %s", exc)
            context = build_verification_context(candidate, code_root)
            context["architecture"] = "local-tool-fallback"
            context["mcp_error"] = str(exc)
            return context

    @staticmethod
    def _merge_verdict(candidate: dict[str, Any], tool_context: dict[str, Any],
                       llm_result: dict[str, Any]) -> dict[str, Any]:
        heuristic = tool_context.get("heuristic_result", {}) or {}
        local_valid = heuristic.get("is_valid")

        verdict = dict(llm_result)
        if local_valid is False:
            verdict["is_valid"] = False
            verdict["false_positive_reason"] = (
                heuristic.get("false_positive_reason")
                or verdict.get("false_positive_reason")
                or heuristic.get("reason")
                or "Local verification tools rejected this candidate."
            )
        elif "is_valid" not in verdict or verdict.get("_error"):
            verdict["is_valid"] = True if local_valid is None else bool(local_valid)

        if not verdict.get("confidence"):
            verdict["confidence"] = heuristic.get("confidence", candidate.get("confidence", 0.5))
        verdict["confidence"] = _bounded_float(verdict.get("confidence"), default=0.5)

        for field in ("source", "sink", "propagation_path", "recommended_poc_strategy", "call_path"):
            if not verdict.get(field) and heuristic.get(field):
                verdict[field] = heuristic[field]

        if not verdict.get("evidence_chain"):
            verdict["evidence_chain"] = tool_context.get("evidence_chain") or {
                "tool_calls": tool_context.get("tools_used", []),
                "call_path": verdict.get("call_path", []),
                "checks": heuristic.get("checks", []),
                "sast_replay": tool_context.get("sast_replay", {}),
            }
        verdict["tool_calls"] = tool_context.get("tools_used", [])

        if not verdict.get("required_runtime_conditions"):
            verdict["required_runtime_conditions"] = _runtime_conditions(candidate, heuristic)

        verdict.setdefault("mcp_server", tool_context.get("mcp_server"))
        verdict.setdefault("skill", tool_context.get("skill"))
        verdict["_tool_evidence"] = tool_context
        verdict["_llm_result"] = llm_result
        return verdict


    # ------------------------------------------------------------------ #
    # ACP 接口（新增）                                                     #
    # ------------------------------------------------------------------ #
    def run_acp(self, request: "ACPMessage") -> "ACPMessage":  # noqa: F821
        """ACP 接口：输入 verify.request，输出 verify.result。

        Parameters
        ----------
        request : ACPMessage
            message_type = "verify.request"
            payload.finding = 统一 ACP finding dict

        Returns
        -------
        ACPMessage
            message_type = "verify.result"
            payload.verification = ACPVerification 结构
            status.verdict = 综合裁决
            status.confidence = 置信度
        """
        # 延迟导入避免循环依赖
        from backend.acp.factory import make_reply
        from backend.acp.models import ACPMessageType, ACPState, ACPVerdict
        from backend.acp.adapters import acp_to_legacy_finding
        from backend.acp.models import ACPToolCall

        acp_finding = request.payload.get("finding") or {}
        legacy = acp_to_legacy_finding(acp_finding)
        code_root_str = (request.context.code_root or
                         acp_finding.get("extra", {}).get("code_root"))
        code_root = Path(code_root_str) if code_root_str else None

        # 调用原有验证逻辑
        vr = self.run(legacy, code_root=code_root)

        # 将旧 is_valid / call_path 等映射为 ACP verification 结构
        is_valid = vr.get("is_valid", True)
        if is_valid is False:
            static_verdict = "false_positive"
            final_verdict = "false_positive"
            state = ACPState.SUCCESS
            verdict_enum = ACPVerdict.FALSE_POSITIVE
        else:
            static_verdict = "confirmed"
            final_verdict = "confirmed"
            state = ACPState.SUCCESS
            verdict_enum = ACPVerdict.STATICALLY_VERIFIED

        verification = {
            "static_verdict": static_verdict,
            "dynamic_verdict": "not_executed",   # 默认未配置动态目标
            "final_verdict": final_verdict,
            "source": vr.get("source"),
            "sink": vr.get("sink"),
            "call_path": vr.get("call_path") or [],
            "evidence_chain": vr.get("evidence_chain") or {},
            "false_positive_reason": vr.get("false_positive_reason"),
            "recommended_poc_strategy": vr.get("recommended_poc_strategy"),
            "confidence": float(vr.get("confidence") or 0.5),
        }

        # 构建 tool_calls 列表
        tool_calls = [
            ACPToolCall(
                tool_name=tc.get("name", ""),
                input={},
                output=tc.get("result_summary") or {},
                success=tc.get("success", True),
            )
            for tc in (vr.get("tool_calls") or [])
        ]

        return make_reply(
            request,
            sender=self.name,
            message_type=ACPMessageType.VERIFY_RESULT,
            intent="漏洞静态验证完成，返回裁决结果",
            payload={
                "finding": acp_finding,
                "verification": verification,
            },
            tools=tool_calls,
            state=state,
            verdict=verdict_enum,
            confidence=verification["confidence"],
        )


def _bounded_float(value: Any, *, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0.0, min(parsed, 1.0))


def _runtime_conditions(candidate: dict[str, Any], heuristic: dict[str, Any]) -> list[str]:
    vuln_type = str(candidate.get("type") or "").lower()
    if "secret" in vuln_type:
        return ["Confirm whether the literal credential is real and reachable by runtime code."]
    if heuristic.get("is_valid") is False:
        return ["No runtime verification required unless a new unsafe path is identified."]
    return ["Run only against a local authorized target or sandbox.", "Use the recommended PoC strategy if dynamic validation is enabled."]

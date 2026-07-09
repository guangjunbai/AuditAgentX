"""HarnessVerifier —— 动态验证智能体（DeepAudit 式 Fuzzing Harness 闭环）。

闭环流程（ReAct 思路）：
  1. 提取目标漏洞函数（extract_function）
  2. LLM 生成 Fuzzing Harness（harness_agent_prompt）
  3. 沙箱执行 Harness（run_harness）
  4. 未触发/报错 -> 把执行输出回喂 LLM 自我修正，重试（最多 max_retries 次）
  5. 输出 verdict：dynamic_confirmed / not_reproduced / inconclusive + harness_code + 执行日志

作用：把"生成利用脚本"升级为"生成并真跑，跑通才算数"，是模块③真正的自动化利用验证。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from backend.agents.base_agent import BaseAgent
from backend.config import settings
from backend.skills.harness_tools import (
    extract_function, run_harness, build_template_harness, normalize_language,
    build_target_scaffold_harness,
)
from backend.mcp.audit_mcp_server import AuditMCPServer
from backend.skills.loader import load_skill
from backend.dynamic.strategy import is_dynamic_applicable

logger = logging.getLogger(__name__)

# HarnessVerifier 输出的 finding 级 verdict -> (dynamically_triggered, function_mechanism_verified, confidence)
_VERDICT_EFFECT = {
    "target_confirmed":       (True,  True,  0.97),   # 真实目标函数 + sink 被触发
    "mechanism_confirmed":    (False, True,  0.75),   # 仅模板机理，封顶 0.75，不算完全动态确认
    "not_reproduced":         (False, False, 0.50),
    "inconclusive":           (False, False, 0.40),
    "sandbox_failed":         (False, False, 0.40),
    "unsafe_harness_blocked": (False, False, 0.40),
    "not_applicable":         (False, False, 0.40),
}


class HarnessVerifier(BaseAgent):
    name = "harness_verifier"
    prompt_file = "harness_agent_prompt.md"

    def __init__(self, scan_id: "str | None" = None) -> None:
        super().__init__(scan_id=scan_id)
        # 经 MCP 工具边界执行「提取函数 / 运行 Harness」，并加载 dynamic-exploitation Skill
        self.mcp = AuditMCPServer()
        try:
            self.skill = load_skill("dynamic-exploitation")
        except Exception:  # noqa: BLE001
            self.skill = {}
        self._tool_calls: list[dict] = []

    def run(self, finding: dict, code_root: Path | None = None,
            *, max_retries: int | None = None) -> dict:
        max_retries = (max_retries if max_retries is not None
                       else int(getattr(settings, "harness_max_retries", 2)))
        self._tool_calls = []

        # 0) 不适合函数级 Harness 的类型（硬编码密钥/弱加密/配置类）直接判 not_applicable
        if not is_dynamic_applicable(finding.get("type")):
            return self._finalize_verdict(
                "not_applicable", {}, [], {"found": False}, "n/a", "n/a",
                reason="漏洞类型无运行时触发点（如硬编码密钥/弱加密配置），不适合函数级 Harness")

        func = self._mcp_extract(finding, code_root)
        target_lang = normalize_language(func.get("language"))
        attempts: list[dict] = []
        last_exec: dict = {}
        harness_source = "llm"
        harness_lang = target_lang

        for attempt in range(max_retries + 1):
            gen = self._generate(finding, func, target_lang, previous=last_exec if attempt else None)
            harness_code = gen.get("harness_code") or ""
            harness_source = gen.get("_source", "llm")
            harness_lang = gen.get("_language", target_lang)
            if not harness_code.strip():
                attempts.append({"attempt": attempt + 1, "error": "no_harness_generated"})
                last_exec = {"verdict": "inconclusive", "reason": "no_harness_generated"}
                break

            last_exec = self._mcp_run(harness_code, harness_lang, harness_source)
            last_exec["attempt"] = attempt + 1
            attempts.append({
                "attempt": attempt + 1, "source": harness_source, "language": harness_lang,
                "verdict": last_exec.get("verdict"),
                "triggered": last_exec.get("triggered", False),
                "verification_level": last_exec.get("verification_level"),
                "backend": last_exec.get("backend"),
                "sink_name": last_exec.get("sink_name"),
                "reason": last_exec.get("reason"),
                "stdout": (last_exec.get("stdout") or "")[:400],
            })
            # 停止条件：目标级确认 / 模板或脚手架（确定性，重试无意义）/ 被安全阻止 / 沙箱失败
            exec_verdict = last_exec.get("verdict")
            if (exec_verdict in ("target_confirmed", "mechanism_confirmed",
                                 "unsafe_harness_blocked", "sandbox_failed")
                    or harness_source in ("template", "scaffold")):
                break

        # 执行级 verdict -> finding 级 verdict
        finding_verdict = self._map_finding_verdict(last_exec, harness_source)
        return self._finalize_verdict(finding_verdict, last_exec, attempts, func,
                                      harness_source, harness_lang)

    @staticmethod
    def _map_finding_verdict(last_exec: dict, harness_source: str) -> str:
        """run_harness 的执行级 verdict -> HarnessVerifier 的 finding 级 verdict。"""
        ev = last_exec.get("verdict") or "inconclusive"
        if ev in ("unsafe_harness_blocked", "sandbox_failed", "not_reproduced",
                  "target_confirmed", "mechanism_confirmed"):
            return ev
        return "inconclusive"

    def _finalize_verdict(self, verdict: str, last_exec: dict, attempts: list,
                          func: dict, harness_source: str, harness_lang: str,
                          *, reason: str | None = None) -> dict:
        triggered, mechanism_verified, confidence = _VERDICT_EFFECT.get(
            verdict, (False, False, 0.40))
        return {
            "verdict": verdict,
            "dynamically_triggered": triggered,           # 仅 target_confirmed 为 True
            "function_mechanism_verified": mechanism_verified,
            "confidence": confidence,
            "verification_level": last_exec.get("verification_level", "none"),
            "harness_source": harness_source,
            "harness_language": harness_lang,
            "harness_code": last_exec.get("_harness_code") or "",
            "sink_name": last_exec.get("sink_name"),
            "captured_argument": last_exec.get("captured_argument"),
            "payload": last_exec.get("payload"),
            "target_function_called": last_exec.get("target_function_called", False),
            "trigger_detail": last_exec.get("trigger_detail", ""),
            "execution_backend": last_exec.get("backend"),
            "function_extracted": func.get("found", False),
            "function_name": func.get("function_name"),
            "safety": last_exec.get("safety", {"allowed": True, "blocked_reason": None, "checks": []}),
            "attempts": attempts,
            "reason": reason or last_exec.get("reason"),
            "execution_log": {
                "stdout": last_exec.get("stdout", ""),
                "stderr": last_exec.get("stderr", ""),
                "reason": last_exec.get("reason"),
            },
            "skill": {"name": self.skill.get("name"), "version": self.skill.get("version"),
                      "workflow": self.skill.get("workflow", [])},
            "tool_calls": self._tool_calls,
        }

    # ---------- MCP 工具调用（经 AuditMCPServer 边界）----------
    def _mcp_extract(self, finding: dict, code_root: Path | None) -> dict:
        candidate = {
            "file": finding.get("file"),
            "start_line": finding.get("start_line") or finding.get("line"),
            "line": finding.get("line"),
        }
        out = self.mcp.call_tool("extract_target_function", {
            "candidate": candidate,
            "code_root": str(code_root) if code_root else None,
        })["structuredContent"]
        self._tool_calls.append({
            "name": "extract_target_function",
            "purpose": "Extract vulnerable function via MCP for harness building.",
            "success": bool(out.get("found")),
        })
        return out

    def _mcp_run(self, harness_code: str, language: str = "python",
                 source: str = "llm") -> dict:
        out = self.mcp.call_tool("run_fuzzing_harness", {
            "harness_code": harness_code,
            "language": language,
            "source": source,
        })["structuredContent"]
        out["_harness_code"] = harness_code   # 供上层保留完整 harness 源码
        self._tool_calls.append({
            "name": "run_fuzzing_harness",
            "purpose": "Execute fuzzing harness in Docker sandbox via MCP.",
            "success": out.get("verdict") in ("target_confirmed", "mechanism_confirmed"),
        })
        return out

    # ---------- 内部 ----------
    def _generate(self, finding: dict, func: dict, target_lang: str,
                  previous: dict | None) -> dict:
        payload = {
            "vulnerability": {
                "type": finding.get("type"),
                "file": finding.get("file"),
                "line": finding.get("start_line") or finding.get("line"),
                "code_snippet": finding.get("code_snippet"),
            },
            "target_function": {
                "function_name": func.get("function_name"),
                "class_name": func.get("class_name"),
                "module_path": func.get("module_path"),
                "imports": func.get("imports"),
                "function_code": func.get("function_code") or finding.get("code_snippet"),
                "found": func.get("found", False),
                "extract_reason": func.get("reason"),
            },
            "target_language": target_lang,
            "instruction": (
                f"用 {target_lang} 编写一个【目标函数级】Fuzzing Harness（DeepAudit 式）：\n"
                "1) 尽量 import 项目真实模块/函数（module_path/function_name）；无法 import 则内联 function_code；\n"
                "2) 必须 mock 掉危险 sink（os.system/subprocess/cursor.execute/open/pickle.loads/"
                "render_template_string 等），mock 只记录被调用的参数，绝不真实执行/联网/删文件；\n"
                "3) 必须真实调用目标函数，喂多个恶意 payload；\n"
                "4) 最后一行必须打印结构化结果（单行）：\n"
                "   AUDITAGENTX_RESULT_JSON={\"triggered\":true,\"target_function_called\":true,"
                "\"sink_called\":true,\"sink_name\":\"os.system\",\"captured_argument\":\"...\",\"payload\":\"...\","
                "\"trigger_detail\":\"...\"}\n"
                "   （未触发则 triggered=false；同时兼容保留 AUDITAGENTX_VULN_TRIGGERED / "
                "AUDITAGENTX_NO_TRIGGER 旧标记）。\n"
                "严禁真实网络请求、删除文件、反射逃逸（__subclasses__/ctypes 等）——违规会被安全策略拦截。"
            ),
        }
        if previous:
            # DeepAudit 式 self-correction：把上一次执行结果回喂，要求修正
            payload["previous_attempt"] = {
                "verdict": previous.get("verdict"),
                "triggered": previous.get("triggered"),
                "target_function_called": previous.get("target_function_called"),
                "stdout": (previous.get("stdout") or "")[:600],
                "stderr": (previous.get("stderr") or "")[:400],
                "reason": previous.get("reason"),
                "instruction": ("上一次未复现或未真正调用目标函数，请修正：确认目标函数被真实调用、"
                                "危险 sink 已被 mock 且被触发、payload 更全，并输出 AUDITAGENTX_RESULT_JSON。"),
            }
        result = self._call(json.dumps(payload, ensure_ascii=False))
        harness_code = result.get("harness_code") if isinstance(result, dict) else None
        if harness_code:
            result.setdefault("_source", "llm")
            result.setdefault("_language", target_lang)
            return result
        # 中间层：目标脚手架——内联真实函数 + mock 精确 sink + 真实调用（target_specific，确定性）
        if func.get("found"):
            scaffold = build_target_scaffold_harness(func, finding.get("type"))
            if scaffold:
                logger.info("HarnessVerifier 使用目标脚手架 Harness (func=%s)", func.get("function_name"))
                return {"harness_code": scaffold, "_source": "scaffold", "_language": "python"}
        # 兜底：类型模板（仅证明漏洞机理，非真实可利用；标 template）
        logger.info("HarnessVerifier 使用模板兜底 Harness (type=%s)", finding.get("type"))
        return {
            "harness_code": build_template_harness(finding.get("type"), finding.get("code_snippet")),
            "_source": "template",
            "_language": "python",
        }

"""SummaryAgent: aggregate audit results into an executive summary.

This agent is intentionally deterministic first: reports must be useful even
when no LLM key is configured. If a real LLM key is available, the model may
polish the wording, but the local summary remains the fallback contract.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

from backend.agents.base_agent import BaseAgent
from backend.config import settings


class SummaryAgent(BaseAgent):
    name = "summary_agent"
    prompt_file = "summary_agent_prompt.md"

    def run(self, project: dict, scan: dict, findings: list[dict], stats: dict) -> dict:
        context = self._build_context(project, scan, findings, stats)
        fallback = self._fallback(context)
        if not self._llm_enabled():
            self._trace(json.dumps(context, ensure_ascii=False), "", fallback)
            return fallback

        result = self._call(json.dumps(context, ensure_ascii=False, default=str))
        if not isinstance(result, dict) or result.get("_error"):
            return fallback
        return self._normalize(result, fallback)

    def _build_context(self, project: dict, scan: dict, findings: list[dict], stats: dict) -> dict:
        static_findings = list(findings)
        dynamic_findings = [f for f in findings if self._has_runtime_evidence(f)]
        reproduced = [
            f for f in dynamic_findings
            if ((f.get("evidence") or {}).get("runtime") or {}).get("reproducible")
        ]
        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        verified = [f for f in findings if f.get("verified")]
        type_counts = Counter(f.get("type") or "Unknown" for f in findings)
        source_counts = Counter(f.get("source") or "unknown" for f in findings)

        return {
            "project": project,
            "scan": scan,
            "stats": stats,
            "total": len(findings),
            "confirmed": len(confirmed),
            "verified": len(verified),
            "static_total": len(static_findings),
            "dynamic_total": len(dynamic_findings),
            "reproduced": len(reproduced),
            "type_counts": dict(type_counts.most_common(8)),
            "source_counts": dict(source_counts.most_common(8)),
            "top_findings": self._top_findings(findings),
            "agent_workflow": [
                {
                    "agent": "RepoParserAgent",
                    "role": "解析仓库结构、语言、框架、入口文件、依赖与代码规模，为后续审计提供项目画像。",
                },
                {
                    "agent": "StaticScanAgent",
                    "role": "调用 Semgrep、Gitleaks、自定义规则等工具进行静态扫描，产出 SQL 注入、命令注入、路径遍历、硬编码密钥等候选风险。",
                },
                {
                    "agent": "AuditAgent",
                    "role": "基于 LLM 对代码上下文做语义审计，补充传统 SAST 工具可能漏掉的业务逻辑与调用链风险。",
                },
                {
                    "agent": "VerifyAgent",
                    "role": "独立复核候选漏洞，调用本地代码上下文读取、启发式分析和 SAST replay 工具过滤误报。",
                },
                {
                    "agent": "ExploitAgent / DynamicVerifier",
                    "role": "为已确认漏洞生成授权 PoC、触发路径和利用代码，并在本地靶场或授权目标上保存动态验证证据。",
                },
                {
                    "agent": "SummaryAgent",
                    "role": "汇总项目概况、静态/动态结果、证据链和修复优先级，生成执行摘要与修改建议。",
                },
            ],
        }

    def _fallback(self, ctx: dict) -> dict:
        project = ctx["project"]
        stats = ctx["stats"]
        total = ctx["total"]
        risk = self._overall_risk(stats)
        languages = "、".join(project.get("languages") or []) or "未识别"
        frameworks = "、".join(project.get("frameworks") or []) or "未识别"
        source = project.get("url") or project.get("local_path") or "未记录"
        top_types = self._format_top_types(ctx["type_counts"])

        executive_summary = (
            f"本次审计对象为 {project.get('name')}，来源为 {source}，项目主要语言为 {languages}，"
            f"框架识别结果为 {frameworks}，共解析 {project.get('file_count', 0)} 个文件、"
            f"{project.get('loc', 0)} 行代码。AuditAgentX 的流程先由 RepoParserAgent 建立项目画像，"
            f"再由 StaticScanAgent 调用静态规则和 SAST 工具产生候选漏洞，AuditAgent 补充语义层面的风险发现，"
            f"VerifyAgent 独立复核并过滤误报，随后 ExploitAgent/DynamicVerifier 对可验证漏洞生成授权 PoC "
            f"并保存运行证据，最后由 SummaryAgent 汇总为本报告。当前共发现 {total} 条风险，"
            f"其中 Critical {stats.get('critical', 0)} 条、High {stats.get('high', 0)} 条、"
            f"Medium {stats.get('medium', 0)} 条、Low {stats.get('low', 0)} 条；"
            f"静态分析覆盖 {ctx['static_total']} 条，动态验证覆盖 {ctx['dynamic_total']} 条，"
            f"其中 {ctx['reproduced']} 条已复现。主要风险类型集中在 {top_types}，总体风险评级为 {risk.upper()}。"
        )

        static_summary = (
            f"静态分析阶段合并 SAST 工具、硬编码密钥检测和自定义规则结果，共形成 {ctx['static_total']} 条静态风险。"
            f"主要来源分布为 {self._format_top_types(ctx['source_counts'])}。这些结果先作为候选项进入 VerifyAgent，"
            "避免仅凭规则命中直接下结论。"
        )
        dynamic_summary = (
            f"动态验证阶段对 {ctx['dynamic_total']} 条漏洞保存了运行证据，其中 {ctx['reproduced']} 条具备可复现结果。"
            "报告中的 Source、Sink、调用路径、PoC 和 runtime 证据共同构成证据链。"
            if ctx["dynamic_total"]
            else "本次报告未发现已落库的动态运行证据。若需要展示漏洞利用效果，应启用 ExploitAgent 和动态验证配置，并在本地授权靶场执行。"
        )

        workflow_summary = [
            f"{item['agent']}：{item['role']}" for item in ctx["agent_workflow"]
        ]
        key_risks = self._key_risks(ctx)
        remediation_plan = self._remediation_plan(ctx, risk)
        conclusion = (
            f"综合项目规模、漏洞数量、严重等级和验证结果，当前项目处于 {risk.upper()} 风险水平。"
            "建议先处理已确认的高危/可复现漏洞，再统一治理同类输入校验、权限控制、敏感信息管理和依赖安全问题。"
        )
        return {
            "executive_summary": executive_summary,
            "overall_risk": risk,
            "static_summary": static_summary,
            "dynamic_summary": dynamic_summary,
            "workflow_summary": workflow_summary,
            "key_risks": key_risks,
            "remediation_plan": remediation_plan,
            "conclusion": conclusion,
        }

    def _normalize(self, result: dict, fallback: dict) -> dict:
        normalized = dict(fallback)
        for key in (
            "executive_summary", "overall_risk", "static_summary", "dynamic_summary",
            "workflow_summary", "key_risks", "remediation_plan", "conclusion",
        ):
            value = result.get(key)
            if value:
                normalized[key] = value
        normalized["overall_risk"] = str(normalized["overall_risk"]).lower()
        if normalized["overall_risk"] not in {"critical", "high", "medium", "low"}:
            normalized["overall_risk"] = fallback["overall_risk"]
        return normalized

    @staticmethod
    def _llm_enabled() -> bool:
        if os.getenv("SUMMARY_AGENT_USE_LLM") != "1":
            return False
        key = (settings.llm_api_key or "").strip().lower()
        return bool(key and key not in {"sk-test", "your-api-key-here", "test"})

    @staticmethod
    def _has_runtime_evidence(finding: dict) -> bool:
        evidence = finding.get("evidence") or {}
        return bool(evidence.get("runtime"))

    @staticmethod
    def _overall_risk(stats: dict) -> str:
        if stats.get("critical", 0) > 0:
            return "critical"
        if stats.get("high", 0) > 0:
            return "high"
        if stats.get("medium", 0) > 0:
            return "medium"
        return "low"

    @staticmethod
    def _format_top_types(counter: dict) -> str:
        if not counter:
            return "暂无明显集中类型"
        return "、".join(f"{name}({count})" for name, count in list(counter.items())[:4])

    @staticmethod
    def _top_findings(findings: list[dict]) -> list[dict]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows = sorted(
            findings,
            key=lambda f: (order.get(str(f.get("severity", "low")).lower(), 9), -(f.get("confidence") or 0)),
        )
        return [
            {
                "type": f.get("type"),
                "severity": f.get("severity"),
                "file": f.get("file"),
                "line": f.get("start_line") or f.get("line"),
                "verified": f.get("verified"),
                "status": f.get("status"),
            }
            for f in rows[:8]
        ]

    def _key_risks(self, ctx: dict) -> list[str]:
        risks: list[str] = []
        for item in ctx["top_findings"][:5]:
            risks.append(
                f"{item.get('severity', 'unknown').upper()} {item.get('type') or 'Unknown'} "
                f"位于 {item.get('file') or '未知文件'}:{item.get('line') or '-'}，"
                f"状态为 {item.get('status') or 'unknown'}。"
            )
        if not risks:
            risks.append("未发现可展示的漏洞明细，但仍建议保留依赖、密钥和输入校验的基础安全检查。")
        return risks

    def _remediation_plan(self, ctx: dict, risk: str) -> list[dict[str, Any]]:
        plan: list[dict[str, Any]] = []
        if ctx["stats"].get("critical", 0) or ctx["stats"].get("high", 0):
            plan.append({
                "priority": "P0",
                "title": "优先修复 Critical/High 漏洞",
                "detail": "先处理已确认、已复现或处于核心入口路径上的高危问题，修复后重新扫描并保留复测证据。",
            })
        plan.extend([
            {
                "priority": "P1",
                "title": "按漏洞类型批量治理",
                "detail": "对 SQL 注入、命令注入、路径遍历等同类问题统一采用参数化查询、白名单校验和安全 API。",
            },
            {
                "priority": "P1",
                "title": "补充动态验证覆盖",
                "detail": "为高危候选漏洞配置本地靶场或授权 URL，让 ExploitAgent/DynamicVerifier 生成可复现证据。",
            },
            {
                "priority": "P2",
                "title": "纳入持续审计流程",
                "detail": "将静态扫描、VerifyAgent 复核和报告生成接入提交前或 CI 流程，避免修复后回归。",
            },
        ])
        if risk in {"medium", "low"}:
            plan[0]["detail"] += " 当前无 Critical 结论时，也应优先处理已确认且靠近外部输入面的 Medium 风险。"
        return plan

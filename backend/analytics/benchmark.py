"""同类开源安全审计系统能力对标（课件模块⑤：与其他开源项目对比，验证创新性）。

数据说明：下述同类系统的能力标注基于其公开资料/课件描述整理，作为**对标框架**供参考，
具体能力以各系统最新文档为准；本文件不编造实验数据，仅用于定性对比展示。
标注取值：yes（支持）/ partial（部分支持）/ unknown（资料未明确）。
"""
from __future__ import annotations

# 对比维度（与 docs/comparison.md 对齐）
DIMENSIONS = [
    {"key": "sast_fusion", "label": "SAST 工具融合"},
    {"key": "llm_audit", "label": "LLM 语义审计"},
    {"key": "independent_verify", "label": "独立验证智能体(降误报)"},
    {"key": "tool_calling_verify", "label": "验证智能体工具调用"},
    {"key": "auto_exploit", "label": "漏洞自动利用"},
    {"key": "dynamic_sandbox", "label": "动态验证/沙箱"},
    {"key": "evidence_chain", "label": "证据链可追溯"},
    {"key": "reproducible", "label": "结果可复现"},
    {"key": "multi_report", "label": "多格式报告"},
    {"key": "open_source", "label": "开源可扩展"},
]

# 各系统在各维度的标注
SYSTEMS = [
    {
        "name": "AuditAgentX (本系统)",
        "is_self": True,
        "positioning": "多源融合 + 双智能体交叉验证 + 可追溯证据链 + 动态利用验证",
        "caps": {
            "sast_fusion": "yes", "llm_audit": "yes", "independent_verify": "yes",
            "tool_calling_verify": "yes", "auto_exploit": "yes", "dynamic_sandbox": "yes",
            "evidence_chain": "yes", "reproducible": "yes", "multi_report": "yes",
            "open_source": "yes",
        },
    },
    {
        "name": "DeepAudit",
        "is_self": False,
        "positioning": "面向 Web 的代码漏洞挖掘智能体系统，多智能体协作 + 自动化沙箱 PoC 验证",
        "caps": {
            "sast_fusion": "partial", "llm_audit": "yes", "independent_verify": "yes",
            "tool_calling_verify": "yes", "auto_exploit": "yes", "dynamic_sandbox": "yes",
            "evidence_chain": "partial", "reproducible": "unknown", "multi_report": "unknown",
            "open_source": "partial",
        },
    },
    {
        "name": "AgentStalker",
        "is_self": False,
        "positioning": "以 LLM 智能体行为为对象的端到端审计框架：静态建模→意图假设→沙箱动态验证→证据聚合",
        "caps": {
            "sast_fusion": "partial", "llm_audit": "yes", "independent_verify": "yes",
            "tool_calling_verify": "yes", "auto_exploit": "partial", "dynamic_sandbox": "yes",
            "evidence_chain": "yes", "reproducible": "partial", "multi_report": "unknown",
            "open_source": "partial",
        },
    },
    {
        "name": "OpenSecurity",
        "is_self": False,
        "positioning": "AI 驱动的多层安全测试 Agent 平台，LLM 驱动多工具完成端到端安全测试",
        "caps": {
            "sast_fusion": "yes", "llm_audit": "yes", "independent_verify": "partial",
            "tool_calling_verify": "yes", "auto_exploit": "partial", "dynamic_sandbox": "partial",
            "evidence_chain": "partial", "reproducible": "unknown", "multi_report": "partial",
            "open_source": "partial",
        },
    },
    {
        "name": "ESAA-Security",
        "is_self": False,
        "positioning": "新兴开源架构安全审计系统，审计行为可确定、可水线，输出格式化清单",
        "caps": {
            "sast_fusion": "partial", "llm_audit": "yes", "independent_verify": "partial",
            "tool_calling_verify": "unknown", "auto_exploit": "unknown", "dynamic_sandbox": "unknown",
            "evidence_chain": "partial", "reproducible": "yes", "multi_report": "yes",
            "open_source": "yes",
        },
    },
    {
        "name": "Sandyaa",
        "is_self": False,
        "positioning": "基于智能体的审计工具，可递归深入挖掘直至验证出真实漏洞",
        "caps": {
            "sast_fusion": "partial", "llm_audit": "yes", "independent_verify": "yes",
            "tool_calling_verify": "partial", "auto_exploit": "partial", "dynamic_sandbox": "partial",
            "evidence_chain": "partial", "reproducible": "unknown", "multi_report": "unknown",
            "open_source": "partial",
        },
    },
]

# 本系统创新点（课件第 12 节）
INNOVATIONS = [
    "多源审计融合：SAST 工具 + 自定义规则 + LLM 语义审计 + 动态 PoC 验证",
    "双智能体交叉验证：AuditAgent 发现、VerifyAgent 独立复核（含本地工具调用），降低误报",
    "证据链可追溯：source → 逐跳调用路径 → sink → PoC → 运行时证据",
    "结果可复现：保存扫描配置、工具版本、Prompt、模型输出与 PoC",
    "沙箱验证：PoC 仅在本地授权/隔离环境运行，绝不攻击真实第三方系统",
]


def benchmark() -> dict:
    return {
        "disclaimer": "同类系统能力标注基于公开资料整理，仅作定性对标；具体以各系统最新文档为准。",
        "dimensions": DIMENSIONS,
        "systems": SYSTEMS,
        "innovations": INNOVATIONS,
    }

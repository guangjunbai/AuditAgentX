"""Models for structured security knowledge retrieval."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SecurityKnowledgeItem:
    """One structured knowledge record used by VerifyAgent."""

    id: str
    source_type: str
    title: str
    summary: str = ""
    cwe_id: str | None = None
    owasp: list[str] = field(default_factory=list)
    vuln_types: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    verification_checks: list[str] = field(default_factory=list)
    false_positive_signals: list[str] = field(default_factory=list)
    dynamic_strategy: str = "not_applicable"
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityKnowledgeItem":
        return cls(
            id=str(data.get("id") or ""),
            source_type=str(data.get("source_type") or "knowledge"),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            cwe_id=data.get("cwe_id"),
            owasp=_list(data.get("owasp")),
            vuln_types=_list(data.get("vuln_types")),
            aliases=_list(data.get("aliases")),
            languages=_list(data.get("languages")),
            frameworks=_list(data.get("frameworks")),
            sources=_list(data.get("sources")),
            sinks=_list(data.get("sinks")),
            sanitizers=_list(data.get("sanitizers")),
            verification_checks=_list(data.get("verification_checks")),
            false_positive_signals=_list(data.get("false_positive_signals")),
            dynamic_strategy=str(data.get("dynamic_strategy") or "not_applicable"),
            remediation=_list(data.get("remediation")),
            references=_list(data.get("references")),
            tags=_list(data.get("tags")),
        )

    def to_dict(self, *, score: float | None = None) -> dict[str, Any]:
        result = {
            "id": self.id,
            "source_type": self.source_type,
            "title": self.title,
            "summary": self.summary,
            "cwe_id": self.cwe_id,
            "owasp": self.owasp,
            "vuln_types": self.vuln_types,
            "aliases": self.aliases,
            "languages": self.languages,
            "frameworks": self.frameworks,
            "sources": self.sources,
            "sinks": self.sinks,
            "sanitizers": self.sanitizers,
            "verification_checks": self.verification_checks,
            "false_positive_signals": self.false_positive_signals,
            "dynamic_strategy": self.dynamic_strategy,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
        }
        if score is not None:
            result["score"] = round(float(score), 3)
        return result


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]

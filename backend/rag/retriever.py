"""Deterministic offline retriever for security knowledge records."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from backend.rag.models import SecurityKnowledgeItem


SOURCES_DIR = Path(__file__).resolve().parent / "sources"
TOKEN_RE = re.compile(r"[a-zA-Z0-9_.$:-]+")


class SecurityKnowledgeRetriever:
    """Small keyword/metadata retriever for vulnerability verification.

    Phase 1 intentionally avoids embedding dependencies. The retriever favors
    exact vulnerability/CWE matches, then source/sink overlap and full-text
    token overlap. This keeps results predictable and easy to test.
    """

    def __init__(self, items: list[SecurityKnowledgeItem] | None = None) -> None:
        self.items = items or load_default_items()

    def retrieve(self, query: str = "", candidate: dict[str, Any] | None = None,
                 *, source_type: str | None = None, limit: int = 3) -> dict[str, Any]:
        candidate = candidate or {}
        query_text = _build_query(query, candidate)
        query_tokens = _tokens(query_text)
        scored: list[tuple[float, SecurityKnowledgeItem]] = []
        for item in self.items:
            if source_type and item.source_type != source_type:
                continue
            score = self._score(item, query_text, query_tokens, candidate)
            if score > 0:
                scored.append((score, item))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        results = [item.to_dict(score=score) for score, item in scored[:max(limit, 1)]]
        return {
            "query": query_text,
            "results": results,
            "top_result": results[0] if results else None,
            "summary": _summarize(results),
        }

    def retrieve_playbook(self, candidate: dict[str, Any], *, limit: int = 2) -> dict[str, Any]:
        return self.retrieve(candidate=candidate, source_type="verification_playbook", limit=limit)

    def retrieve_remediation(self, candidate: dict[str, Any], *, limit: int = 2) -> dict[str, Any]:
        return self.retrieve(candidate=candidate, source_type="remediation_guide", limit=limit)

    @staticmethod
    def _score(item: SecurityKnowledgeItem, query_text: str, query_tokens: set[str],
               candidate: dict[str, Any]) -> float:
        haystack = " ".join([
            item.id, item.title, item.summary, item.cwe_id or "",
            " ".join(item.vuln_types), " ".join(item.aliases),
            " ".join(item.sources), " ".join(item.sinks),
            " ".join(item.sanitizers), " ".join(item.tags),
        ]).lower()
        item_tokens = _tokens(haystack)
        score = len(query_tokens & item_tokens) * 0.8

        vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "").lower()
        cwe = str(candidate.get("cwe_id") or candidate.get("cwe") or "").lower()
        if cwe and cwe == (item.cwe_id or "").lower():
            score += 20
        if vuln_type:
            names = [item.title, *item.vuln_types, *item.aliases]
            if any(vuln_type == name.lower() for name in names):
                score += 16
            elif any(vuln_type in name.lower() or name.lower() in vuln_type for name in names):
                score += 10

        source_sink_text = " ".join([
            str(candidate.get("source") or ""),
            str(candidate.get("sink") or ""),
            str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        ]).lower()
        for source in item.sources:
            if source.lower() in source_sink_text:
                score += 2.5
        for sink in item.sinks:
            if sink.lower() in source_sink_text:
                score += 3.5
        return score


@lru_cache(maxsize=1)
def load_default_items() -> list[SecurityKnowledgeItem]:
    items: list[SecurityKnowledgeItem] = []
    for path in sorted(SOURCES_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        records = data.get("items", data if isinstance(data, list) else [])
        items.extend(SecurityKnowledgeItem.from_dict(record) for record in records)
    return items


def _build_query(query: str, candidate: dict[str, Any]) -> str:
    parts = [query]
    for key in ("type", "vulnerability_type", "cwe_id", "cwe", "rule_id", "source", "sink",
                "code_snippet", "vulnerable_code", "file", "file_path"):
        value = candidate.get(key)
        if value:
            parts.append(str(value))
    return " ".join(part for part in parts if part).strip()


def _tokens(text: str) -> set[str]:
    return {match.group(0).lower() for match in TOKEN_RE.finditer(text or "") if len(match.group(0)) > 1}


def _summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        return {"cwe_id": None, "owasp": [], "verification_checks": [], "remediation": []}
    top = results[0]
    return {
        "cwe_id": top.get("cwe_id"),
        "owasp": top.get("owasp") or [],
        "dynamic_strategy": top.get("dynamic_strategy"),
        "verification_checks": top.get("verification_checks") or [],
        "false_positive_signals": top.get("false_positive_signals") or [],
        "remediation": top.get("remediation") or [],
        "references": top.get("references") or [],
    }

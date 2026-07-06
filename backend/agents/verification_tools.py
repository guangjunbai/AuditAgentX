"""Local tools used by VerifyAgent.

These helpers make the verifier more than a pure LLM prompt: the agent can read
nearby source code and run deterministic checks before making a final decision.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def build_verification_context(
    candidate: dict[str, Any],
    code_root: Path | None,
    *,
    radius: int = 8,
) -> dict[str, Any]:
    context = {
        "tools_used": [],
        "code_context": _read_code_context(candidate, code_root, radius=radius),
    }
    context["tools_used"].append({
        "name": "code_context_reader",
        "purpose": "Read source lines around the candidate finding.",
        "success": bool(context["code_context"].get("found")),
    })
    heuristic = _run_heuristic_verifier(candidate, context["code_context"])
    context["heuristic_result"] = heuristic
    context["tools_used"].append({
        "name": "heuristic_static_verifier",
        "purpose": "Check common source-to-sink and false-positive patterns.",
        "success": True,
    })
    return context


def _read_code_context(candidate: dict[str, Any], code_root: Path | None, *, radius: int) -> dict[str, Any]:
    rel_file = candidate.get("file") or candidate.get("file_path")
    line = _to_int(candidate.get("start_line") or candidate.get("line")) or 1
    fallback = candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""
    if not code_root or not rel_file:
        return {
            "found": False,
            "file": rel_file,
            "line": line,
            "snippet": fallback,
            "reason": "code_root_or_file_missing",
        }

    root = code_root.resolve()
    target = (root / str(rel_file)).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {
            "found": False,
            "file": rel_file,
            "line": line,
            "snippet": fallback,
            "reason": "candidate_file_outside_workspace",
        }
    if not target.exists() or not target.is_file():
        return {
            "found": False,
            "file": rel_file,
            "line": line,
            "snippet": fallback,
            "reason": "candidate_file_not_found",
        }

    lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    numbered = [
        {"line": idx, "code": lines[idx - 1]}
        for idx in range(start, end + 1)
    ]
    return {
        "found": True,
        "file": rel_file,
        "line": line,
        "start_line": start,
        "end_line": end,
        "lines": numbered,
        "snippet": "\n".join(f"{row['line']}: {row['code']}" for row in numbered),
    }


def _run_heuristic_verifier(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "").lower()
    text = "\n".join([
        str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        str(code_context.get("snippet") or ""),
    ])
    lowered = text.lower()
    checks: list[dict[str, Any]] = []

    if "sql" in vuln_type:
        return _verify_sql(lowered, checks)
    if "command" in vuln_type or "rce" in vuln_type:
        return _verify_command(lowered, checks)
    if "path" in vuln_type or "traversal" in vuln_type:
        return _verify_path_traversal(lowered, checks)
    if "secret" in vuln_type or "credential" in vuln_type or "key" in vuln_type:
        return _verify_secret(text, checks)

    checks.append({"name": "generic_context_present", "passed": bool(text.strip())})
    return {
        "is_valid": None,
        "confidence": 0.55,
        "checks": checks,
        "reason": "No type-specific local verifier matched this finding.",
    }


def _verify_sql(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"\b(execute|query|cursor\.execute)\s*\(", text))
    concatenates_query = bool(re.search(r"(select|insert|update|delete).*?(\+|f['\"]|format\s*\()", text, re.S))
    parameterized = bool(re.search(r"execute\s*\([^)]*,\s*(\(|\[|\{)", text, re.S))
    checks.extend([
        {"name": "sql_sink_present", "passed": has_sink},
        {"name": "query_uses_string_concatenation_or_formatting", "passed": concatenates_query},
        {"name": "parameterized_execute_detected", "passed": parameterized},
    ])
    if parameterized and not concatenates_query:
        return {
            "is_valid": False,
            "confidence": 0.82,
            "checks": checks,
            "false_positive_reason": "SQL execution appears parameterized; no direct user-controlled string concatenation was detected.",
            "source": "user input parameter",
            "sink": "SQL execution API",
            "propagation_path": [],
            "recommended_poc_strategy": "No PoC recommended unless a non-parameterized path is found.",
        }
    if has_sink and concatenates_query:
        return {
            "is_valid": True,
            "confidence": 0.86,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "SQL execution API",
            "propagation_path": ["user input", "string-built SQL query", "execute/query sink"],
            "recommended_poc_strategy": "Send a boolean or error-based SQL payload to the controlling parameter in a local target.",
        }
    return _uncertain(checks, "SQL sink or unsafe query construction was not clearly established.")


def _verify_command(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"(os\.system|subprocess\.(run|call|popen)|exec|eval)\s*\(", text))
    shell_true = "shell=true" in text
    dynamic_arg = bool(re.search(r"(\+|format\s*\(|f['\"]|\{.*\})", text))
    safe_list = bool(re.search(r"subprocess\.(run|call|popen)\s*\(\s*\[", text)) and not shell_true
    checks.extend([
        {"name": "command_execution_sink_present", "passed": has_sink},
        {"name": "shell_true_detected", "passed": shell_true},
        {"name": "dynamic_argument_detected", "passed": dynamic_arg},
        {"name": "safe_argument_list_detected", "passed": safe_list},
    ])
    if safe_list and not dynamic_arg:
        return {
            "is_valid": False,
            "confidence": 0.78,
            "checks": checks,
            "false_positive_reason": "Command is invoked with a static argument list and shell=False.",
            "source": "user input parameter",
            "sink": "process execution API",
            "propagation_path": [],
            "recommended_poc_strategy": "No PoC recommended unless user input reaches a shell string.",
        }
    if has_sink and (shell_true or dynamic_arg):
        return {
            "is_valid": True,
            "confidence": 0.84,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "process execution API",
            "propagation_path": ["user input", "command string/argument", "process execution sink"],
            "recommended_poc_strategy": "Use a harmless marker command against a local authorized target.",
        }
    return _uncertain(checks, "Command sink or user-controlled command construction was not clearly established.")


def _verify_path_traversal(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_file_sink = bool(re.search(r"\b(open|readfile|file_get_contents|include|require)\s*\(", text))
    user_input = any(token in text for token in ["request", "_get", "_post", "params", "input", "args.get"])
    safe_join = any(token in text for token in ["safe_join", "secure_filename", "basename(", "normpath("])
    checks.extend([
        {"name": "file_read_sink_present", "passed": has_file_sink},
        {"name": "user_input_reference_present", "passed": user_input},
        {"name": "path_sanitizer_detected", "passed": safe_join},
    ])
    if safe_join and not (has_file_sink and user_input):
        return {
            "is_valid": False,
            "confidence": 0.74,
            "checks": checks,
            "false_positive_reason": "A path sanitizer was detected and no direct unsafe file read path was established.",
            "source": "path parameter",
            "sink": "file read/include API",
            "propagation_path": [],
            "recommended_poc_strategy": "No PoC recommended unless a sanitizer bypass is found.",
        }
    if has_file_sink and user_input and not safe_join:
        return {
            "is_valid": True,
            "confidence": 0.82,
            "checks": checks,
            "source": "request path parameter",
            "sink": "file read/include API",
            "propagation_path": ["user input", "path construction", "file read/include sink"],
            "recommended_poc_strategy": "Try harmless traversal payloads against a local target and check for expected marker files.",
        }
    return _uncertain(checks, "Path source-to-sink flow was not clearly established.")


def _verify_secret(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    secret = bool(re.search(r"(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['\"][^'\"]{6,}['\"]", text, re.I))
    placeholder = bool(re.search(r"(your-|example|dummy|test|placeholder|changeme)", text, re.I))
    checks.extend([
        {"name": "secret_assignment_detected", "passed": secret},
        {"name": "placeholder_detected", "passed": placeholder},
    ])
    if secret and placeholder:
        return {
            "is_valid": False,
            "confidence": 0.7,
            "checks": checks,
            "false_positive_reason": "The detected secret-like value appears to be a placeholder or test value.",
            "source": "source file literal",
            "sink": "credential/configuration",
            "propagation_path": [],
            "recommended_poc_strategy": "Do not execute PoC; manually confirm whether the value is real.",
        }
    if secret:
        return {
            "is_valid": True,
            "confidence": 0.8,
            "checks": checks,
            "source": "source file literal",
            "sink": "credential/configuration",
            "propagation_path": ["hardcoded literal", "runtime configuration or authentication use"],
            "recommended_poc_strategy": "No exploit execution; validate usage and rotate the credential if real.",
        }
    return _uncertain(checks, "No concrete secret assignment was detected.")


def _uncertain(checks: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {"is_valid": None, "confidence": 0.55, "checks": checks, "reason": reason}


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

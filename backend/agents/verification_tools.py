"""Local tools used by VerifyAgent.

These helpers make the verifier more than a pure LLM prompt: the agent can read
nearby source code and run deterministic checks before making a final decision.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from backend.verifier.context_classifier import classify_finding_context


RUNTIME_VULN_KEYWORDS = ("sql", "command", "rce", "path", "traversal", "ssrf", "ssti", "upload")
STATIC_ASSET_PARTS = {
    "static", "assets", "asset", "public", "dist", "build", "vendor",
    "node_modules", "third-party", "third_party", "layui", "ueditor", "dplayer",
}
STATIC_ASSET_SUFFIXES = (".min.js", ".bundle.js", ".chunk.js", ".map")


def build_verification_context(
    candidate: dict[str, Any],
    code_root: Path | None,
    *,
    radius: int = 8,
) -> dict[str, Any]:
    context = {
        "mcp_skill_style": True,
        "tool_manifest": [
            {
                "name": "code_context_reader",
                "description": "Read nearby source code around a candidate finding.",
                "input_schema": {"file": "string", "line": "integer", "radius": "integer"},
            },
            {
                "name": "heuristic_static_verifier",
                "description": "Run deterministic source-to-sink and false-positive checks.",
                "input_schema": {"candidate": "object", "code_context": "object"},
            },
            {
                "name": "local_sast_replay",
                "description": "Replay lightweight SAST checks on the local code window.",
                "input_schema": {"snippet": "string", "vulnerability_type": "string"},
            },
        ],
        "tools_used": [],
        "code_context": read_code_context(candidate, code_root, radius=radius),
    }
    context["tools_used"].append({
        "name": "code_context_reader",
        "purpose": "Read source lines around the candidate finding.",
        "success": bool(context["code_context"].get("found")),
    })
    context["context_classification"] = classify_finding_context(
        candidate, context["code_context"].get("snippet"))
    heuristic = run_heuristic_static_verifier(candidate, context["code_context"])
    context["heuristic_result"] = heuristic
    context["tools_used"].append({
        "name": "heuristic_static_verifier",
        "purpose": "Check common source-to-sink and false-positive patterns.",
        "success": True,
    })
    sast_replay = run_local_sast_replay(candidate, context["code_context"])
    context["sast_replay"] = sast_replay
    context["tools_used"].append({
        "name": "local_sast_replay",
        "purpose": "Replay lightweight SAST checks on the candidate code window.",
        "success": True,
        "matched_rules": [rule["rule_id"] for rule in sast_replay.get("matched_rules", [])],
    })
    return context


def read_code_context(candidate: dict[str, Any], code_root: Path | None, *, radius: int = 8) -> dict[str, Any]:
    """Public MCP tool implementation for reading nearby source code."""
    return _read_code_context(candidate, code_root, radius=radius)


def run_heuristic_static_verifier(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    """Public MCP tool implementation for source-to-sink and false-positive checks."""
    return _run_heuristic_verifier(candidate, code_context)


def run_local_sast_replay(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    """Public MCP tool implementation for deterministic local SAST replay."""
    return _local_sast_replay(candidate, code_context)


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
    context = classify_finding_context(candidate, code_context.get("snippet"))
    if not context.get("allow_confirmed", True) and context.get("risk_modifier") == "false_positive":
        return _with_call_path({
            "is_valid": False,
            "confidence": 0.9,
            "checks": [{"name": "context_false_positive", "passed": True, "context": context.get("context")}],
            "false_positive_reason": context.get("reason"),
            "context": context.get("context"),
            "risk_modifier": context.get("risk_modifier"),
            "allow_confirmed": False,
            "confirmed_blockers": context.get("confirmed_blockers") or [],
            "runtime_verification_status": "not_runtime_verifiable",
            "recommended_poc_strategy": "Do not run dynamic verification unless a browser/HTTP sink is identified.",
        }, candidate, code_context)

    asset_fp = _static_asset_false_positive(candidate, vuln_type)
    if asset_fp:
        return _with_call_path(asset_fp, candidate, code_context)

    text = "\n".join([
        str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        str(code_context.get("snippet") or ""),
    ])
    lowered = text.lower()
    checks: list[dict[str, Any]] = []

    if "sql" in vuln_type:
        return _with_context(_with_call_path(_verify_sql(lowered, checks), candidate, code_context), context)
    if "command" in vuln_type or "rce" in vuln_type:
        return _with_context(_with_call_path(_verify_command(lowered, checks), candidate, code_context), context)
    if "path" in vuln_type or "traversal" in vuln_type:
        return _with_context(_with_call_path(_verify_path_traversal(lowered, checks), candidate, code_context), context)
    if "secret" in vuln_type or "credential" in vuln_type or "key" in vuln_type:
        return _with_context(_with_call_path(_verify_secret(text, checks), candidate, code_context), context)

    # 确定性缺陷（存在即漏洞，无需污点源）——本该高置信确认，绝不塞人工
    if "random" in vuln_type or "prng" in vuln_type or "weakrand" in vuln_type:
        return _with_context(_with_call_path(_verify_weak_random(lowered, checks), candidate, code_context), context)
    if ("crypto" in vuln_type or "cipher" in vuln_type or "ecb" in vuln_type or "cbc" in vuln_type
            or ("hash" in vuln_type and ("weak" in vuln_type or "insecure" in vuln_type or "md5" in vuln_type or "sha1" in vuln_type))):
        return _with_context(_with_call_path(_verify_weak_crypto(lowered, checks), candidate, code_context), context)

    # 注入类：补齐 SQL/命令/路径 之外的常见类型（此前全部落 needs_review）
    _INJ = {
        "xss": (r"innerhtml|document\.write|\.write\s*\(|(?<!//\s)echo\s|render_template_string|response\.(write|getwriter)|out\.print|\|\s*safe\b|<[a-z][a-z0-9]*[\s/>]",
                "HTML/JS 输出 sink", r"escape|htmlspecialchars|bleach|markupsafe|sanitize|\|\s*e\b", "xss"),
        "ssti": (r"render_template_string|template\s*\(|from_string\s*\(|env\.from_string", "模板引擎渲染 sink", r"", "ssti"),
        "deserial": (r"pickle\.loads|cpickle\.loads|yaml\.load\s*\(|marshal\.loads|jsonpickle|__reduce__|unserialize\s*\(", "反序列化 sink", r"safeloader|safe_load|yaml\.safe_load", "deserialization"),
        "pickle": (r"pickle\.loads|cpickle\.loads|marshal\.loads", "反序列化 sink", r"", "deserialization"),
        "ssrf": (r"requests\.(get|post|put|head|delete|request)|urlopen|urllib\.request|httpx\.(get|post|client)|http\.client|\bfetch\s*\(", "出站请求 sink", r"", "ssrf"),
        "code injection": (r"\beval\s*\(|\bexec\s*\(|compile\s*\(|__import__\s*\(", "动态代码执行 sink", r"", "code_injection"),
        "ldap": (r"\.search\s*\(|dircontext|initialdircontext", "LDAP 查询 sink", r"", "ldap"),
        "xpath": (r"xpath|\.evaluate\s*\(|xpathexpression|newxpath", "XPath 表达式 sink", r"", "xpath"),
        "open redirect": (r"redirect\s*\(|sendredirect|header\s*\(\s*['\"]location|location\s*=", "重定向 sink", r"url_has_allowed_host|is_safe_url|allowlist|whitelist", "open_redirect"),
        "xxe": (r"etree|xml\.dom|sax|documentbuilder|parsexml|lxml", "XML 解析 sink", r"resolve_entities\s*=\s*false|no_network|forbid_dtd", "xxe"),
    }
    for key, (sink_rx, label, san_rx, vuln) in _INJ.items():
        if key in vuln_type:
            return _with_context(_with_call_path(
                _verify_generic_injection(lowered, checks, sink_rx=sink_rx, sink_label=label,
                                          sanitizer_rx=san_rx, vuln=vuln), candidate, code_context), context)

    checks.append({"name": "generic_context_present", "passed": bool(text.strip())})
    return _with_context(_with_call_path({
        "is_valid": None,
        "confidence": 0.55,
        "checks": checks,
        "reason": "No type-specific local verifier matched this finding.",
        "runtime_verification_status": "not_runtime_verifiable",
    }, candidate, code_context), context)


def _local_sast_replay(candidate: dict[str, Any], code_context: dict[str, Any]) -> dict[str, Any]:
    vuln_type = str(candidate.get("type") or candidate.get("vulnerability_type") or "")
    text = "\n".join([
        str(candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""),
        str(code_context.get("snippet") or ""),
    ])
    rules = []
    rule_specs = [
        ("sqli-string-concat", "SQL Injection", r"(execute|query|cursor\.execute)\s*\(.*?(\+|f['\"]|format\s*\()"),
        ("command-dynamic-exec", "Command Injection", r"(os\.system|subprocess\.(run|call|popen)|exec|eval)\s*\(.*?(\+|shell\s*=\s*true|f['\"]|format\s*\()"),
        ("path-user-file-read", "Path Traversal", r"(open|readfile|file_get_contents|include|require)\s*\(.*?(request|_GET|_POST|params|args\.get|input)"),
        ("hardcoded-secret-literal", "Hardcoded Secret", r"(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
    ]
    for rule_id, rule_type, pattern in rule_specs:
        if rule_type.lower() in vuln_type.lower() or not vuln_type:
            if re.search(pattern, text, re.I | re.S):
                rules.append({"rule_id": rule_id, "type": rule_type, "matched": True})
    if "sql" in vuln_type.lower() and not any(rule["type"] == "SQL Injection" for rule in rules):
        built_query_var = re.search(
            r"(?P<var>[a-zA-Z_][\w]*)\s*=\s*[^\n]*(select|insert|update|delete)[^\n]*(\+|f['\"]|format\s*\()",
            text,
            re.I,
        )
        if built_query_var and re.search(rf"\bexecute\s*\(\s*{re.escape(built_query_var.group('var'))}\s*\)", text, re.I):
            rules.append({
                "rule_id": "sqli-built-query-variable",
                "type": "SQL Injection",
                "matched": True,
                "detail": "SQL query is built dynamically and later passed to execute().",
            })
    return {"matched_rules": rules, "snippet_available": bool(text.strip())}


def _with_call_path(result: dict[str, Any], candidate: dict[str, Any],
                    code_context: dict[str, Any]) -> dict[str, Any]:
    result.setdefault("call_path", _build_static_call_path(candidate, code_context, result))
    return result


def _with_context(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    result.setdefault("context", context.get("context"))
    result.setdefault("risk_modifier", context.get("risk_modifier"))
    result.setdefault("allow_confirmed", context.get("allow_confirmed", True))
    result.setdefault("confirmed_blockers", context.get("confirmed_blockers") or [])
    if not context.get("allow_confirmed", True):
        result.setdefault("downgrade_reason", context.get("reason"))
        result["confidence"] = min(float(result.get("confidence") or 0.55), 0.65)
        if context.get("risk_modifier") == "informational":
            result.setdefault("runtime_verification_status", "not_runtime_verifiable")
    return result


def _static_asset_false_positive(candidate: dict[str, Any], vuln_type: str) -> dict[str, Any] | None:
    """Reject server-side runtime findings reported inside static/third-party assets.

    A SQL/command/path traversal finding in a minified frontend asset usually has no
    server-side source-to-sink path and should not be sent to dynamic HTTP probing.
    """
    if not any(keyword in vuln_type for keyword in RUNTIME_VULN_KEYWORDS):
        return None

    file_path = str(candidate.get("file") or candidate.get("file_path") or "").replace("\\", "/").lower()
    if not file_path:
        return None
    parts = {part for part in file_path.split("/") if part}
    is_static_asset = (
        bool(parts & STATIC_ASSET_PARTS)
        or file_path.endswith(STATIC_ASSET_SUFFIXES)
        or "/static_" in file_path
    )
    if not is_static_asset:
        return None

    return {
        "is_valid": False,
        "confidence": 0.9,
        "checks": [
            {"name": "static_or_third_party_asset_detected", "passed": True, "file": file_path},
            {"name": "server_side_runtime_flow_absent", "passed": True},
        ],
        "false_positive_reason": (
            "Candidate is located in a static/third-party/minified frontend asset, "
            "so no server-side runtime source-to-sink path is established."
        ),
        "source": None,
        "sink": None,
        "propagation_path": [],
        "runtime_verification_status": "not_runtime_verifiable",
        "recommended_poc_strategy": "Do not run dynamic HTTP verification unless a backend route reaches this code.",
    }


def _build_static_call_path(candidate: dict[str, Any], code_context: dict[str, Any],
                            verdict: dict[str, Any]) -> list[dict[str, Any]]:
    file_path = candidate.get("file") or candidate.get("file_path") or code_context.get("file")
    finding_line = _to_int(candidate.get("start_line") or candidate.get("line") or code_context.get("line"))
    lines = code_context.get("lines") or []
    snippet = candidate.get("code_snippet") or candidate.get("vulnerable_code") or ""
    hops: list[dict[str, Any]] = []

    source_line = _find_line(lines, ["request", "args.get", "_get", "_post", "params", "input"], fallback=finding_line)
    sink_line = _find_line(lines, ["execute", "query", "os.system", "subprocess", "open(", "readfile", "pickle.loads"], fallback=finding_line)

    if verdict.get("source"):
        hops.append({"stage": "source", "file": file_path, "line": source_line, "detail": verdict["source"]})
    if snippet:
        hops.append({"stage": "candidate", "file": file_path, "line": finding_line, "detail": snippet[:240]})
    if verdict.get("sink"):
        hops.append({"stage": "sink", "file": file_path, "line": sink_line, "detail": verdict["sink"]})
    return hops


def _find_line(lines: list[dict[str, Any]], needles: list[str], fallback: int | None) -> int | None:
    for row in lines:
        code = str(row.get("code") or "").lower()
        if any(needle in code for needle in needles):
            return _to_int(row.get("line")) or fallback
    return fallback


def _verify_sql(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"\b(execute|query|cursor\.execute)\s*\(", text))
    concatenates_query = bool(re.search(r"(select|insert|update|delete).*?(\+|f['\"]|format\s*\()", text, re.S))
    parameterized = bool(re.search(r"execute\s*\([^)]*,\s*(\(|\[|\{)", text, re.S))
    user_input = _has_user_source(text)
    checks.extend([
        {"name": "sql_sink_present", "passed": has_sink},
        {"name": "query_uses_string_concatenation_or_formatting", "passed": concatenates_query},
        {"name": "parameterized_execute_detected", "passed": parameterized},
        {"name": "attacker_controlled_source_present", "passed": user_input},
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
    if has_sink and concatenates_query and user_input:
        return {
            "is_valid": True,
            "confidence": 0.74,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "SQL execution API",
            "propagation_path": ["user input", "string-built SQL query", "execute/query sink"],
            "evidence_strength": "window_heuristic",
            "recommended_poc_strategy": "Send a boolean or error-based SQL payload to the controlling parameter in a local target.",
        }
    if has_sink and concatenates_query and not user_input:
        return _uncertain(checks, "SQL is built dynamically, but no attacker-controlled source was established.")
    return _uncertain(checks, "SQL sink or unsafe query construction was not clearly established.")


def _verify_command(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    has_sink = bool(re.search(r"(os\.system|subprocess\.(run|call|popen)|exec|eval)\s*\(", text))
    shell_true = "shell=true" in text
    dynamic_arg = bool(re.search(r"(\+|format\s*\(|f['\"]|\{.*\})", text))
    safe_list = bool(re.search(r"subprocess\.(run|call|popen)\s*\(\s*\[", text)) and not shell_true
    user_input = _has_user_source(text)
    checks.extend([
        {"name": "command_execution_sink_present", "passed": has_sink},
        {"name": "shell_true_detected", "passed": shell_true},
        {"name": "dynamic_argument_detected", "passed": dynamic_arg},
        {"name": "safe_argument_list_detected", "passed": safe_list},
        {"name": "attacker_controlled_source_present", "passed": user_input},
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
    if has_sink and (shell_true or dynamic_arg) and user_input:
        return {
            "is_valid": True,
            "confidence": 0.74,
            "checks": checks,
            "source": "request/user-controlled value",
            "sink": "process execution API",
            "propagation_path": ["user input", "command string/argument", "process execution sink"],
            "evidence_strength": "window_heuristic",
            "recommended_poc_strategy": "Use a harmless marker command against a local authorized target.",
        }
    if has_sink and (shell_true or dynamic_arg) and not user_input:
        return _uncertain(checks, "A dynamic command sink exists, but no attacker-controlled source was established.")
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
            "deterministic_flow": True,
            "evidence_strength": "literal_assignment",
            "recommended_poc_strategy": "No exploit execution; validate usage and rotate the credential if real.",
        }
    return _uncertain(checks, "No concrete secret assignment was detected.")


def _deterministic_true(checks, sink, conf, strategy, path_desc):
    """存在即漏洞的确定性判定（弱加密/弱随机等，无需污点源）。"""
    return {
        "is_valid": True, "confidence": conf, "checks": checks,
        "source": "N/A（确定性缺陷，无需攻击者输入）", "sink": sink,
        "deterministic_flow": True, "evidence_strength": "deterministic_pattern",
        "propagation_path": [path_desc],
        "recommended_poc_strategy": strategy,
    }


def _verify_weak_crypto(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    weak = re.search(
        r"\b(md5|sha1|sha-1)\b|(?<![\w])des(?![\w])|\brc4\b|\becb\b"
        r"|messagedigest\.getinstance\(\s*['\"](md5|sha-?1)"
        r"|cipher\.getinstance\(\s*['\"]([^'\"]*des|[^'\"]*rc4|[^'\"]*ecb)"
        r"|hashlib\.(md5|sha1)\s*\(", text, re.I)
    checks.append({"name": "weak_or_broken_crypto_primitive", "passed": bool(weak)})
    if weak:
        return _deterministic_true(
            checks, "weak/broken cryptographic primitive", 0.85,
            "无需 PoC；改用强算法（SHA-256/AES-GCM，DES→AES，ECB→GCM）。",
            "使用了已被攻破/弱的加密或哈希原语")
    return _uncertain(checks, "未明确识别到弱加密原语。")


def _verify_weak_random(text: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    weak = re.search(r"\brandom\.(random|randint|randrange|choice|getrandbits|shuffle|uniform)\s*\("
                     r"|\bmath\.random\s*\(|new\s+random\s*\(|mt_rand\s*\(|\brand\s*\(", text, re.I)
    secure = bool(re.search(r"securerandom|\bsecrets\.|random_bytes|crypto\.randombytes", text, re.I))
    checks += [{"name": "insecure_prng_used", "passed": bool(weak)},
               {"name": "secure_random_detected", "passed": secure}]
    if weak and not secure:
        return _deterministic_true(
            checks, "insecure pseudo-random generator", 0.8,
            "无需 PoC；安全场景改用 secrets / os.urandom / SecureRandom。",
            "在安全相关场景使用了不安全的伪随机数生成器")
    return _uncertain(checks, "未明确识别到不安全随机源，或已使用安全随机。")


def _verify_generic_injection(text: str, checks: list[dict[str, Any]], *,
                              sink_rx: str, sink_label: str, sanitizer_rx: str,
                              vuln: str) -> dict[str, Any]:
    """通用注入类复核：危险 sink + 攻击者可控源 + 无净化 -> 确认。"""
    has_sink = bool(re.search(sink_rx, text, re.I))
    user_input = _has_user_source(text)
    sanitized = bool(sanitizer_rx and re.search(sanitizer_rx, text, re.I))
    checks += [{"name": f"{vuln}_sink_present", "passed": has_sink},
               {"name": "attacker_controlled_source_present", "passed": user_input},
               {"name": f"{vuln}_sanitizer_detected", "passed": sanitized}]
    if has_sink and sanitized and not user_input:
        return {"is_valid": False, "confidence": 0.72, "checks": checks,
                "false_positive_reason": f"{sink_label} 处检测到净化/编码，且无直接可控输入到达。",
                "sink": sink_label, "propagation_path": []}
    if has_sink and user_input and not sanitized:
        return {"is_valid": True, "confidence": 0.74, "checks": checks,
                "source": "request/user-controlled value", "sink": sink_label,
                "evidence_strength": "window_heuristic",
                "propagation_path": ["user input", f"unsanitized flow into {sink_label}", sink_label],
                "recommended_poc_strategy": f"对本地授权目标向可控参数发送 {vuln} 载荷并核对成功判据。"}
    if has_sink and not user_input:
        return _uncertain(checks, f"存在 {sink_label} sink，但当前窗口未确立攻击者可控源（可能跨函数）。")
    return _uncertain(checks, f"未清晰确立 {sink_label} 的 source→sink 流。")


def _uncertain(checks: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {"is_valid": None, "confidence": 0.55, "checks": checks, "reason": reason}


def _has_user_source(text: str) -> bool:
    return bool(re.search(
        r"(request\.(args|form|values|json|data|files|headers|cookies|get|post|query_params)|"
        r"args\.get\s*\(|req\.(query|body|params|headers|cookies)|\$_(get|post|request|cookie|server)|"
        r"getparameter\s*\(|@requestparam|@pathvariable|@requestbody|argv\[|\binput\s*\(|"
        r"os\.environ|getenv\s*\(|sys\.stdin|scanf\s*\(|fgets\s*\(|(?<![\w.])gets\s*\(|"
        r"params\[|body\.|\.get_json\s*\(|flask\.request|self\.request|request\.POST|request\.GET)",
        text or "", re.I,
    ))


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

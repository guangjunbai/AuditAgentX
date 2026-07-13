"""漏洞类型 → 动态验证策略映射（覆盖主流可动态验证漏洞）。

策略取值：
  http            : 适合对运行中的靶场发 HTTP 载荷验证
  harness         : 适合函数级 Fuzzing Harness 验证（无需靶场）
  both            : 两者都适用（优先 harness，有靶场再补 http）
  not_applicable  : 静态类漏洞，无运行时触发点，动态验证不适用（dynamic_not_applicable）

每条规则附：http_method / param_hint（HTTP 注入点候选）/ reason。
"""
from __future__ import annotations

HTTP = "http"
HARNESS = "harness"
BOTH = "both"
NOT_APPLICABLE = "not_applicable"

# 规则库：键为漏洞类型关键词（小写，子串匹配），值为策略描述
STRATEGY_RULES: dict[str, dict] = {
    # ---------------- 注入类 ----------------
    "sql injection": {"strategy": BOTH, "http_method": "GET",
                      "param_hint": ["id", "user", "search", "q", "order", "category"],
                      "reason": "可控参数拼入 SQL，可发注入载荷或函数级 mock 验证"},
    "nosql injection": {"strategy": BOTH, "http_method": "POST",
                        "param_hint": ["username", "query", "filter", "id"],
                        "reason": "NoSQL 查询拼接，可发对象注入载荷"},
    "ldap injection": {"strategy": HARNESS, "http_method": "GET",
                       "param_hint": ["user", "cn", "uid", "filter"],
                       "reason": "LDAP 过滤器拼接，函数级验证更稳"},
    "xpath injection": {"strategy": HARNESS, "http_method": "GET",
                        "param_hint": ["user", "name", "query"],
                        "reason": "XPath 表达式拼接"},
    "command injection": {"strategy": BOTH, "http_method": "GET",
                          "param_hint": ["host", "ip", "cmd", "target", "file", "domain"],
                          "reason": "参数拼入系统命令，harness mock 危险 sink 验证最可靠"},
    "code injection": {"strategy": HARNESS, "http_method": "POST",
                       "param_hint": ["code", "expr", "input", "data"],
                       "reason": "eval/exec 执行可控输入"},
    "ssti": {"strategy": BOTH, "http_method": "GET",
             "param_hint": ["name", "q", "input", "template", "msg"],
             "reason": "模板表达式注入，{{7*191}} 类载荷可 HTTP 或函数级验证"},
    "template injection": {"strategy": BOTH, "http_method": "GET",
                           "param_hint": ["name", "q", "template"],
                           "reason": "服务端模板注入"},
    # ---------------- 文件/路径类 ----------------
    "path traversal": {"strategy": BOTH, "http_method": "GET",
                       "param_hint": ["file", "path", "page", "template", "download", "name"],
                       "reason": "../ 目录穿越读取任意文件"},
    "lfi": {"strategy": BOTH, "http_method": "GET",
            "param_hint": ["file", "page", "include", "path"],
            "reason": "本地文件包含"},
    "rfi": {"strategy": HTTP, "http_method": "GET",
            "param_hint": ["file", "url", "page"],
            "reason": "远程文件包含（仅本地授权靶场）"},
    "arbitrary file upload": {"strategy": HTTP, "http_method": "POST",
                              "param_hint": ["file", "upload", "avatar", "attachment"],
                              "reason": "上传可执行脚本绕过校验"},
    "file upload": {"strategy": HTTP, "http_method": "POST",
                    "param_hint": ["file", "upload"],
                    "reason": "任意文件上传"},
    # ---------------- 请求伪造/重定向 ----------------
    "ssrf": {"strategy": HTTP, "http_method": "GET",
             "param_hint": ["url", "uri", "target", "callback", "webhook", "src", "image"],
             "reason": "诱导服务端请求任意地址（仅本地/云元数据探测）"},
    "open redirect": {"strategy": HTTP, "http_method": "GET",
                       "param_hint": ["url", "redirect", "next", "return", "returnUrl", "goto"],
                       # HTTP stays the primary verification lane.  A Harness is
                       # allowed only after the verifier has bound this finding to
                       # a real Express route registration in current project code.
                       "harness_supplement": "source_bound_express_route_entrypoint",
                       "reason": "开放重定向到任意地址；仅 source-bound Express 路由入口可补充 Harness 证明"},
    "crlf injection": {"strategy": HTTP, "http_method": "GET",
                       "param_hint": ["url", "redirect", "header"],
                       "reason": "CRLF 注入/响应拆分"},
    "host header injection": {"strategy": HTTP, "http_method": "GET",
                              "param_hint": ["host"],
                              "reason": "Host 头注入"},
    "cors misconfiguration": {"strategy": HTTP, "http_method": "GET",
                              "param_hint": ["origin"],
                              "reason": "CORS 配置不当"},
    # ---------------- XSS ----------------
    "xss": {"strategy": BOTH, "http_method": "GET",
             "param_hint": ["q", "search", "name", "comment", "message", "keyword"],
             "reason": "先由 PoC Sandbox Harness 分析 source-to-DOM/sink；Docker HTTP 仅作可选端到端增强"},
    "cross-site scripting": {"strategy": BOTH, "http_method": "GET",
                              "param_hint": ["q", "search", "name", "comment"],
                              "reason": "先由 PoC Sandbox Harness 分析，再按需做端到端验证"},
    "dom xss": {"strategy": HARNESS,
                 "reason": "DOM/React sink 先在受控 PoC Sandbox 中做源码与污点路径分析；不把文本反射误判为脚本执行"},
    # ---------------- 反序列化/XXE ----------------
    "insecure deserialization": {"strategy": HARNESS, "http_method": "POST",
                                 "param_hint": ["data", "obj", "payload", "session", "state"],
                                 "reason": "反序列化不可信数据，harness 触发 __reduce__ 验证"},
    "deserialization": {"strategy": HARNESS, "http_method": "POST",
                        "param_hint": ["data", "obj", "payload"],
                        "reason": "不安全反序列化"},
    "xxe": {"strategy": BOTH, "http_method": "POST",
            "param_hint": ["xml", "data", "body"],
            "reason": "XML 外部实体注入"},
    # ---------------- 访问控制 ----------------
    "idor": {"strategy": HTTP, "http_method": "GET",
             "param_hint": ["id", "uid", "user_id", "account", "order_id", "doc"],
             "reason": "越权访问对象，遍历 ID 验证"},
    "broken access control": {"strategy": HTTP, "http_method": "GET",
                              "param_hint": ["id", "role", "admin", "user"],
                              "reason": "访问控制缺陷"},
    "auth bypass": {"strategy": HTTP, "http_method": "POST",
                    "param_hint": ["user", "password", "token", "role"],
                    "reason": "认证绕过"},
    "mass assignment": {"strategy": HTTP, "http_method": "POST",
                        "param_hint": ["role", "is_admin", "id"],
                        "reason": "批量赋值污染"},
    # ---------------- 静态类：dynamic_not_applicable ----------------
    "hardcoded secret": {"strategy": NOT_APPLICABLE,
                         "reason": "静态类：源码硬编码密钥无运行时触发点，需人工核对密钥用途与影响面"},
    "hardcoded credential": {"strategy": NOT_APPLICABLE,
                             "reason": "静态类：硬编码凭证"},
    "secret": {"strategy": NOT_APPLICABLE, "reason": "静态类：敏感信息硬编码"},
    "weak crypto": {"strategy": NOT_APPLICABLE, "reason": "静态类：弱加密算法，配置层问题"},
    "weak hash": {"strategy": NOT_APPLICABLE, "reason": "静态类：弱哈希（MD5/SHA1）"},
    "insecure random": {"strategy": HARNESS,
                        "reason": "在 PoC Sandbox 中确认真实安全敏感调用点与随机源；这是源码级证据，不伪装成 HTTP 利用"},
    "insecure configuration": {"strategy": NOT_APPLICABLE, "reason": "静态类：不安全配置"},
    "debug mode": {"strategy": NOT_APPLICABLE, "reason": "静态类：调试模式开启"},
    "sensitive data exposure": {"strategy": NOT_APPLICABLE, "reason": "静态类：敏感信息泄露"},
    "missing security header": {"strategy": NOT_APPLICABLE, "reason": "静态/被动类：缺失安全响应头"},
    "outdated dependency": {"strategy": NOT_APPLICABLE, "reason": "SCA 静态类：依赖已知漏洞（CVE）"},
    "cve": {"strategy": NOT_APPLICABLE, "reason": "SCA 静态类：依赖组件 CVE"},
}

# 别名归一（复用 exploit_templates 的思路）
_ALIASES = {
    "sqli": "sql injection", "rce": "command injection",
    "os command injection": "command injection", "command execution": "command injection",
    "directory traversal": "path traversal", "file inclusion": "lfi",
    "server-side request forgery": "ssrf", "server-side template injection": "ssti",
    "unsafe deserialization": "insecure deserialization",
    "broken object level authorization": "idor", "bola": "idor",
    "hardcoded password": "hardcoded credential",
    # Semgrep/Bandit SSTI 规则 ID：render_template_string 拼接可控输入即 SSTI，
    # 子串 "template-string" 可同时命中 render-template-string / dangerous-template-string。
    "template-string": "ssti", "template_string": "ssti",
    # 新扫描器名称复用已有、且 CWE/playbook/remediation 完整的策略，避免孤儿类型。
    "header injection": "crlf injection", "log injection": "code injection",
    "regex injection": "code injection", "permissive cors": "cors misconfiguration",
    "jwt signature verification disabled": "auth bypass",
    "weak randomness": "insecure random",
    "react-dangerouslysetinnerhtml": "dom xss",
    "dangerouslysetinnerhtml": "dom xss",
    "dangerously-set-inner-html": "dom xss",
    "dependency vulnerability": "outdated dependency",
    "tls certificate validation disabled": "insecure configuration",
    "risky security-sensitive import": "insecure configuration",
}

# 未识别类型绝不能默认交给函数 Harness。否则 Dockerfile/部署建议/配置项会被
# LLM 改写成一个“相似的”玩具函数，再由 Harness 证明它自己刚写的漏洞。
_DEFAULT = {
    "strategy": NOT_APPLICABLE,
    "http_method": "GET",
    "param_hint": [],
    "reason": "未匹配受支持的运行时漏洞类型，需要人工选择验证策略",
    "reason_code": "unsupported_vulnerability_type",
    "needs_manual_strategy": True,
}

_CONFIGURATION_TERMS = {
    "dockerfile", "kubernetes", "terraform", "helm", "compose", "ci", "pipeline",
    "configuration", "config", "deployment", "hardening", "best practice", "permission",
    "security header", "tls", "container", "manifest", "yaml",
}


def _reason_code(key: str, rule: dict) -> str:
    strategy = rule.get("strategy")
    if strategy in {HARNESS, BOTH}:
        return "harness_supported_runtime_vulnerability"
    if strategy == HTTP:
        return "http_supported_runtime_vulnerability"
    if any(term in key for term in _CONFIGURATION_TERMS):
        return "configuration_finding_not_harnessable"
    return "static_finding_not_runtime_verifiable"


def _resolved(vuln_type: str | None, key: str, rule: dict, *, matched: bool) -> dict:
    strategy = rule.get("strategy")
    primary_lane = rule.get("primary_lane") or (
        "poc_sandbox" if strategy in {HARNESS, BOTH}
        else "docker_http_optional" if strategy == HTTP
        else "static_review"
    )
    return {
        **rule,
        # Architecture invariant: Harness/PoC Sandbox owns the primary verdict.
        # Docker/HTTP is an optional end-to-end evidence enhancer, never a gate.
        "primary_lane": primary_lane,
        "docker_fallback": bool(rule.get("docker_fallback", strategy in {HTTP, BOTH})),
        "reason_code": rule.get("reason_code") or _reason_code(key, rule),
        "needs_manual_strategy": bool(rule.get("needs_manual_strategy", False)),
        "matched": matched,
        "vuln_type": vuln_type,
    }


def resolve_strategy(vuln_type: str | None) -> dict:
    """按漏洞类型解析动态验证策略。返回 {strategy, http_method?, param_hint?, reason, matched}。"""
    if not vuln_type:
        return _resolved(vuln_type, "", _DEFAULT, matched=False)
    key = vuln_type.strip().lower()
    # Cookie findings are a distinct proof mode, but not a distinct RAG
    # vulnerability category.  Keep this routing policy out of STRATEGY_RULES
    # so the knowledge-base contract remains one playbook/CWE per public type.
    if "insecure cookie" in key:
        return _resolved(vuln_type, key, {
            "strategy": HARNESS,
            "reason": "在 PoC Sandbox 中断言真实 cookie 配置属性；Docker HTTP 仅在可运行时补充响应头证据",
        }, matched=True)
    # 明确登记的运行时类型优先于配置语义兜底。否则诸如 ``CORS
    # Misconfiguration`` 会因包含 configuration 被错误排除，尽管规则表已明确允许
    # 受控 HTTP 验证。未登记的“Dockerfile command injection hardening”仍会走下方
    # configuration 保护分支，绝不默认交给 Harness。
    if key in STRATEGY_RULES:
        return _resolved(vuln_type, key, STRATEGY_RULES[key], matched=True)
    if key in _ALIASES:
        return _resolved(vuln_type, key, STRATEGY_RULES[_ALIASES[key]], matched=True)
    # 配置/部署语义先于模糊子串匹配。例如 “Dockerfile command injection hardening”
    # 不能因为含 command injection 就进入函数 Harness。
    if any(term in key for term in _CONFIGURATION_TERMS):
        return _resolved(vuln_type, key, {
            "strategy": NOT_APPLICABLE,
            "reason": "配置、部署或安全加固 finding 没有可证明的运行时目标函数",
            "reason_code": "configuration_finding_not_harnessable",
        }, matched=True)
    for name, rule in STRATEGY_RULES.items():
        if name in key or key in name:
            return _resolved(vuln_type, key, rule, matched=True)
    for alias, target in _ALIASES.items():
        if alias in key:
            return _resolved(vuln_type, key, STRATEGY_RULES[target], matched=True)
    return _resolved(vuln_type, key, _DEFAULT, matched=False)


def is_dynamic_applicable(vuln_type: str | None) -> bool:
    """该漏洞类型是否适合动态验证（False 即 dynamic_not_applicable）。"""
    return resolve_strategy(vuln_type)["strategy"] != NOT_APPLICABLE


def is_harness_applicable(vuln_type: str | None, *, source_bound: bool = False) -> bool:
    """Return whether a finding may enter Harness verification.

    Open Redirect deliberately remains HTTP-primary.  Its only exception is a
    supplemental, verifier-proven Express route-handler entrypoint Harness;
    callers must pass ``source_bound=True`` only after binding current project
    source to a concrete route-registration scaffold.
    """
    resolved = resolve_strategy(vuln_type)
    return bool(
        resolved["strategy"] in {HARNESS, BOTH}
        or (source_bound and resolved.get("harness_supplement") ==
            "source_bound_express_route_entrypoint")
    )

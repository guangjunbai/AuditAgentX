"""Fuzzing Harness 底层工具（借鉴 DeepAudit 的动态验证思路）。

提供两类能力：
1. extract_function：从项目源码中提取目标漏洞函数，供构建隔离 Harness。
2. run_harness：在沙箱（优先 Docker，回退受控本地子进程）执行 Python Harness，
   通过统一触发标记判断漏洞是否被动态触发。

安全约束：Harness 由提示词强制 mock 所有危险 sink，只在本地隔离环境短时运行，
绝不真实执行系统命令 / 删除文件 / 发起网络请求。
"""
from __future__ import annotations

import ast
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)

TRIGGER_MARKER = "AUDITAGENTX_VULN_TRIGGERED"
NO_TRIGGER_MARKER = "AUDITAGENTX_NO_TRIGGER"
# 新增：Harness 最后一行输出结构化结果，优先据此判定（无则退回 marker）
RESULT_JSON_MARKER = "AUDITAGENTX_RESULT_JSON="

# 细化的执行级 verdict（run_harness 返回）
V_TARGET_CONFIRMED = "target_confirmed"        # 调用了项目真实目标函数 + 危险 sink 被攻击输入触发
V_MECHANISM_CONFIRMED = "mechanism_confirmed"  # 仅模板机理触发，不等价真实可利用（置信度封顶 0.75）
V_NOT_REPRODUCED = "not_reproduced"            # 成功执行但未触发 sink
V_INCONCLUSIVE = "inconclusive"               # 提取失败/依赖不足/生成失败等无法判断
V_SANDBOX_FAILED = "sandbox_failed"           # Docker/执行环境异常
V_UNSAFE_BLOCKED = "unsafe_harness_blocked"   # Harness 违反安全策略被阻止执行

LEVEL_TARGET = "target_specific"
LEVEL_TEMPLATE = "template_mechanism"
LEVEL_NONE = "none"

# 多语言 Harness 执行运行时：本地解释器 / Docker 镜像 / 文件扩展名 / Docker 内联执行参数
_LANG_RUNTIMES = {
    "python": {"local": None, "image": "python:3.11-slim", "ext": "py", "inline": ["python", "-c"]},
    "javascript": {"local": "node", "image": "node:20-slim", "ext": "js", "inline": ["node", "-e"]},
    "php": {"local": "php", "image": "php:8.2-cli", "ext": "php", "inline": ["php", "-r"]},
}

# 语言/文件后缀 -> 归一化语言（未知一律回退 python，模板 Harness 均为 Python）
_LANG_ALIASES = {
    "py": "python", "python": "python", "python3": "python",
    "js": "javascript", "jsx": "javascript", "mjs": "javascript", "cjs": "javascript",
    "ts": "javascript", "tsx": "javascript", "typescript": "javascript",
    "node": "javascript", "javascript": "javascript", "ecmascript": "javascript",
    "php": "php", "php5": "php", "php7": "php", "php8": "php", "phtml": "php",
}


def normalize_language(value: str | None) -> str:
    """把文件后缀 / 语言名归一化为受支持的 Harness 执行语言（默认 python）。"""
    return _LANG_ALIASES.get(str(value or "").strip().lower(), "python")


# ---------------------------------------------------------------------------
# 安全策略：静态扫描 Harness 代码，阻止真实危险行为（LLM 生成的代码尤其严格）
# ---------------------------------------------------------------------------

# 硬阻断：无论如何都不允许（真实网络 / 删文件 / 反射逃逸 / 外连），Harness 里没有正当理由出现
_HARD_BLOCK = {
    "python": [
        (r"\bsocket\.socket\s*\(", "real socket network access"),
        (r"\brequests\.(get|post|put|delete|head|patch|request)\s*\(", "real HTTP via requests"),
        (r"urllib\.request\.urlopen\s*\(|(?<![\w.])urlopen\s*\(", "real HTTP via urllib"),
        (r"\bhttp\.client|\bhttplib\b|\basyncio\b.*open_connection", "real network client"),
        (r"\b(shutil\.rmtree|os\.remove|os\.unlink|os\.rmdir)\s*\(", "real file deletion"),
        (r"__subclasses__|__mro__\s*\[|__globals__|__builtins__", "python reflection sandbox escape"),
        (r"\bctypes\b|\bmultiprocessing\b|os\.fork\s*\(|\bpty\b", "process/native escape"),
        (r"open\s*\(\s*['\"][^'\"]*(\.ssh|/etc/shadow|id_rsa|/etc/passwd|\\\\Users\\\\)",
         "real read of sensitive path"),
    ],
    "javascript": [
        (r"\bchild_process\b|\.exec(Sync)?\s*\(|\.spawn\s*\(", "js child_process execution"),
        (r"require\s*\(\s*['\"](net|http|https|dgram|dns|tls)['\"]\s*\)", "js network module"),
        (r"(?<![\w.])fetch\s*\(|new\s+XMLHttpRequest", "js real HTTP"),
        (r"\bfs\.(unlink|rm|rmdir|rmSync|unlinkSync)\s*\(", "js file deletion"),
    ],
    "php": [
        (r"\b(shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(", "php real shell exec"),
        (r"(?<![\w])system\s*\(", "php system()"),
        (r"\b(unlink|rmdir)\s*\(", "php file deletion"),
        (r"\b(curl_exec|fsockopen|file_get_contents\s*\(\s*['\"]https?://)", "php real network"),
    ],
}

# mock 感知：危险 sink 只有被 mock（重新赋值/覆盖）后才允许出现；未 mock 的真实调用一律阻止。
# 每项 (调用正则, 展示名)；点号已转义，避免 os.system 误匹配 os_system 之类的 mock 名。
_MOCK_AWARE = {
    "python": [
        (r"os\.system", "os.system"),
        (r"subprocess\.(call|run|Popen|check_output)", "subprocess"),
        (r"(?:cPickle|pickle)\.loads", "pickle.loads"),
        (r"(?<![\w.])eval", "eval"),
        (r"(?<![\w.])exec", "exec"),
    ],
}


def validate_harness_safety(harness_code: str, language: str = "python",
                            source: str = "llm") -> dict:
    """静态审查 Harness 代码是否满足安全策略。

    返回 {allowed, blocked_reason, checks}。
    - 内置模板（source="template"）经过人工审阅、只做 mock，视为可信直接放行。
    - LLM 生成的 Harness（source="llm"）严格审查：禁止真实网络/删文件/反射逃逸/外连；
      危险 sink（os.system/subprocess/eval/pickle.loads…）只有被 mock 后才允许。
    """
    lang = normalize_language(language)
    code = harness_code or ""
    checks: list[str] = []
    if source == "template":
        return {"allowed": True, "blocked_reason": None,
                "checks": ["trusted built-in template (pre-vetted mock harness)"]}

    # 1) 硬阻断项
    for pattern, desc in _HARD_BLOCK.get(lang, []):
        if re.search(pattern, code, re.I):
            checks.append(f"BLOCK: {desc}")
            return {"allowed": False, "blocked_reason": desc, "checks": checks}
    checks.append("no hard-blocked network/file-delete/reflection patterns")

    # 2) mock 感知的危险 sink（仅 Python）：未被 mock 的真实调用 -> 阻止
    for pattern, display in _MOCK_AWARE.get(lang, []):
        if not re.search(pattern + r"\s*\(", code):
            continue
        # 是否被 mock：对同一 sink 的赋值（os.system = ... / subprocess.call = ...）或 def 同名覆盖
        mocked = (re.search(pattern + r"\s*=", code)
                  or (f"def {display.split('.')[-1]}" in code))
        if not mocked:
            checks.append(f"BLOCK: unmocked dangerous sink call: {display}")
            return {"allowed": False,
                    "blocked_reason": f"unmocked dangerous sink: {display}", "checks": checks}
    checks.append("dangerous sinks are mocked (or absent)")
    return {"allowed": True, "blocked_reason": None, "checks": checks}

# 各语言的函数定义起始模式
_FUNC_START = re.compile(
    r"^\s*(?:def |function |func |sub |public |private |protected |static |async def ).*",
    re.IGNORECASE,
)


def _blank_extract(file, line, reason) -> dict:
    return {"found": False, "file": file, "line": line, "function_code": "",
            "function_name": None, "class_name": None, "module_path": None,
            "imports": [], "decorators": [], "language": None, "reason": reason}


def extract_function(code_root: Path | None, file: str | None, line: int | None,
                     *, max_lines: int = 80) -> dict:
    """提取 file:line 所在函数的源码与元信息。

    Python 用 AST 精确定位函数/类/装饰器/import；JS/PHP 用正则（精度有限，reason 里说明）。
    找不到时如实返回 found=False + 具体 reason，不假装成功。
    """
    if not code_root or not file or not line:
        return _blank_extract(file, line, "missing_code_root_or_location")

    target = (Path(code_root) / file).resolve()
    try:
        target.relative_to(Path(code_root).resolve())
    except ValueError:
        return _blank_extract(file, line, "file_outside_workspace")
    if not target.exists() or not target.is_file():
        return _blank_extract(file, line, "file_not_found")

    text = target.read_text(encoding="utf-8", errors="ignore")
    lang = normalize_language(target.suffix.lstrip("."))
    rel = str(Path(file).as_posix())

    if lang == "python":
        return _extract_python(text, rel, line)
    return _extract_regex(text, rel, line, lang, max_lines)


def _extract_python(text: str, rel: str, line: int) -> dict:
    """用 AST 提取 Python 目标函数/方法及其元信息。"""
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return _blank_extract(rel, line, f"python_parse_error: {e}")

    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            imports.extend(f"{mod}.{a.name}" if mod else a.name for a in node.names)

    # 找到包含目标行、且最内层的 FunctionDef
    best = None
    best_class = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            if start <= line <= end:
                if best is None or start >= best.lineno:  # 最内层（起始行更大）
                    best = node
    if best is None:
        return _blank_extract(rel, line, "no_enclosing_function_at_line")

    # 找它所属的类（若有）
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            cstart, cend = node.lineno, getattr(node, "end_lineno", node.lineno)
            if cstart <= best.lineno <= cend:
                best_class = node.name

    seg = ast.get_source_segment(text, best) or "\n".join(
        text.splitlines()[best.lineno - 1:getattr(best, "end_lineno", best.lineno)])
    decorators = [ast.get_source_segment(text, d) or "" for d in best.decorator_list]
    module_path = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel.replace("/", ".")

    return {
        "found": True, "file": rel, "line": line,
        "start_line": best.lineno, "end_line": getattr(best, "end_lineno", best.lineno),
        "function_name": best.name, "class_name": best_class,
        "module_path": module_path, "function_code": seg,
        "imports": imports[:40], "decorators": [d for d in decorators if d],
        "language": "python", "reason": None,
    }


def _extract_regex(text: str, rel: str, line: int, lang: str, max_lines: int) -> dict:
    """JS/PHP 的正则兜底提取（精度有限）。"""
    lines = text.splitlines()
    idx = max(0, min(line - 1, len(lines) - 1))
    start = idx
    for i in range(idx, max(-1, idx - max_lines), -1):
        if _FUNC_START.match(lines[i]):
            start = i
            break
    end = min(len(lines), start + max_lines)
    def_indent = len(lines[start]) - len(lines[start].lstrip())
    for j in range(start + 1, min(len(lines), start + max_lines)):
        if not lines[j].strip():
            continue
        cur_indent = len(lines[j]) - len(lines[j].lstrip())
        if cur_indent <= def_indent and _FUNC_START.match(lines[j]):
            end = j
            break
    m = re.search(r"(?:function|func|def)\s+([A-Za-z_]\w*)", lines[start])
    return {
        "found": True, "file": rel, "line": line,
        "start_line": start + 1, "end_line": end,
        "function_name": m.group(1) if m else None, "class_name": None,
        "module_path": rel, "function_code": "\n".join(lines[start:end]),
        "imports": [], "decorators": [], "language": lang,
        "reason": "regex_extraction_limited_precision",
    }


def build_template_harness(vuln_type: str | None, code_snippet: str | None = None) -> str:
    """LLM 不可用时的兜底：按漏洞类型生成可运行的 mock-based Fuzzing Harness。

    这些 Harness 验证的是「该漏洞类型的可利用机理」（类型级），
    mock 掉危险 sink，喂恶意 payload，检测是否以危险方式触发。
    """
    t = (vuln_type or "").lower()
    # 注意匹配顺序：更具体的类型优先（如 "xpath" 含子串 "path"，必须先于 path 判断）
    if "command" in t or "rce" in t or "os command" in t:
        return _HARNESS_CMDI
    if "xpath" in t:
        return _HARNESS_XPATH
    if "ldap" in t:
        return _HARNESS_LDAP
    if "code injection" in t or "code exec" in t or "eval" in t:
        return _HARNESS_CODEI
    if "ssti" in t or "template" in t:
        return _HARNESS_SSTI
    if "sql" in t:
        return _HARNESS_SQLI
    if "path" in t or "traversal" in t or "lfi" in t:
        return _HARNESS_PATH
    if "deserial" in t or "pickle" in t:
        return _HARNESS_DESERIAL
    # 无类型模板：静态判断代码片段是否含危险 sink 模式
    snippet = (code_snippet or "").replace('"', '\\"')
    return (
        'snippet = "' + snippet[:200] + '"\n'
        'danger = ["os.system","subprocess","eval(","exec(","pickle.loads","+ request","_GET["]\n'
        'if any(d in snippet for d in danger):\n'
        '    print("AUDITAGENTX_VULN_TRIGGERED", "static sink pattern present")\n'
        'else:\n'
        '    print("AUDITAGENTX_NO_TRIGGER")\n'
    )


_HARNESS_CMDI = '''executed = []
import os, subprocess
os.system = lambda c: (executed.append(str(c)), 0)[1]
subprocess.call = lambda *a, **k: (executed.append(str(a)), 0)[1]
def target(user_input):          # 通用命令注入模式：拼接进系统命令
    os.system("ping -c 1 " + user_input)
for p in ["127.0.0.1", "; id", "| whoami", "`id`", "&& ls -la"]:
    executed.clear()
    try: target(p)
    except Exception: pass
    danger = [c for c in executed if any(x in c for x in [";", "|", "`", "&&", "$("])]
    if danger:
        print("AUDITAGENTX_VULN_TRIGGERED", "command injection via", repr(p), "->", danger)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_SQLI = '''queries = []
class Cursor:
    def execute(self, q, params=None):
        queries.append((str(q), params))
def target(uid):                 # 通用 SQL 注入模式：字符串拼接查询
    Cursor().execute("SELECT * FROM users WHERE id=" + str(uid))
for p in ["1", "1' OR '1'='1", "1 UNION SELECT username,password FROM users", "1; DROP TABLE users"]:
    queries.clear()
    try: target(p)
    except Exception: pass
    q, params = queries[-1]
    if params is None and any(x in q.upper() for x in ["OR '1'='1", "UNION SELECT", "DROP TABLE"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "sql injection via", repr(p), "->", q)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_PATH = '''from io import StringIO
reads = []
def mock_open(path, *a, **k):
    reads.append(str(path)); return StringIO("")
def target(filename):            # 通用路径遍历模式：拼接进文件路径
    mock_open("/var/www/uploads/" + filename)
for p in ["report.txt", "../../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"]:
    reads.clear()
    try: target(p)
    except Exception: pass
    if any(".." in r or "%2f" in r.lower() for r in reads):
        print("AUDITAGENTX_VULN_TRIGGERED", "path traversal via", repr(p), "->", reads)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_DESERIAL = '''calls = []
import pickle
pickle.loads = lambda b: (calls.append(repr(b)[:60]), None)[1]
def target(data):                # 通用不安全反序列化模式
    pickle.loads(data)
target(b"cos\\nsystem\\n(S'id'\\ntR.")   # 恶意序列化占位（不真实执行）
if calls:
    print("AUDITAGENTX_VULN_TRIGGERED", "insecure deserialization: pickle.loads on untrusted data", calls)
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_CODEI = '''calls = []
def fake_eval(expr, *a, **k):    # mock：不真实 eval，只记录送入 eval 的内容
    calls.append(str(expr)); return None
def target(user_input):          # 代码注入：用户输入被送入 eval/exec
    fake_eval(user_input)
for p in ["1+1", "__import__('os').system('id')", "().__class__.__mro__[1].__subclasses__()", "globals()"]:
    calls.clear()
    try: target(p)
    except Exception: pass
    last = calls[-1] if calls else ""
    if any(x in last for x in ["__import__", "__class__", "subclasses", "os.system", "globals("]):
        print("AUDITAGENTX_VULN_TRIGGERED", "code injection: user input reaches eval ->", repr(last))
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_SSTI = '''rendered = []
def fake_render(tpl, **ctx):     # mock 模板引擎：记录被当作模板源编译的字符串
    rendered.append(str(tpl)); return str(tpl)
def target(name):                # SSTI：用户输入拼进模板源码本身
    fake_render("Hello " + name)
for p in ["World", "{{7*191}}", "${7*191}", "{{config.__class__}}", "#{7*7}", "<%= 7*7 %>"]:
    rendered.clear()
    try: target(p)
    except Exception: pass
    last = rendered[-1] if rendered else ""
    if any(x in last for x in ["{{", "${", "#{", "<%"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "SSTI: template expression compiled from user input ->", repr(p))
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_XPATH = '''queries = []
def fake_xpath(expr):            # mock XPath 求值：记录表达式
    queries.append(str(expr)); return []
def target(user):                # XPath 注入：用户输入拼进 XPath 表达式
    fake_xpath("//user[name/text()='" + user + "']")
for p in ["alice", "' or '1'='1", "'] | //password | a['", "' or 1=1 or ''='"]:
    queries.clear()
    try: target(p)
    except Exception: pass
    q = queries[-1] if queries else ""
    if any(x in q for x in ["' or '1'='1", "or 1=1", "| //"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "xpath injection via", repr(p), "->", q)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''

_HARNESS_LDAP = '''filters = []
def fake_search(f):              # mock LDAP 搜索：记录过滤器
    filters.append(str(f)); return []
def target(user):                # LDAP 注入：用户输入拼进搜索过滤器
    fake_search("(&(uid=" + user + ")(objectClass=person))")
for p in ["alice", "*", "*)(uid=*))(|(uid=*", "admin)(|(password=*)"]:
    filters.clear()
    try: target(p)
    except Exception: pass
    f = filters[-1] if filters else ""
    if any(x in f for x in ["*)(", ")(|", "uid=*)"]):
        print("AUDITAGENTX_VULN_TRIGGERED", "ldap injection via", repr(p), "->", f)
        break
else:
    print("AUDITAGENTX_NO_TRIGGER")
'''


def _parse_result_json(stdout: str) -> dict | None:
    """解析 Harness 打印的 AUDITAGENTX_RESULT_JSON={...}（取最后一处）。"""
    if RESULT_JSON_MARKER not in (stdout or ""):
        return None
    tail = stdout.rsplit(RESULT_JSON_MARKER, 1)[1]
    line = tail.splitlines()[0] if tail.splitlines() else tail
    try:
        obj = json.loads(line.strip())
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _base_result(language: str, source: str, backend: str) -> dict:
    """结构化结果骨架（保持旧字段兼容 + 新增结构化字段）。"""
    return {
        "executed": False, "triggered": False,
        "verdict": V_INCONCLUSIVE, "verification_level": LEVEL_NONE,
        "backend": backend, "language": language, "harness_source": source,
        "target_function_called": False, "sink_called": False,
        "sink_name": None, "captured_argument": None, "payload": None,
        "trigger_detail": "", "stdout": "", "stderr": "", "reason": None,
        "attempt": 1, "safety": {"allowed": True, "blocked_reason": None, "checks": []},
    }


def run_harness(harness_code: str, *, timeout: int | None = None,
                language: str | None = None, source: str = "llm",
                require_docker: bool | None = None) -> dict:
    """执行 Harness 并返回结构化结果 + 细化 verdict。

    安全策略（Docker-first）：
      - LLM 生成的 Harness（source="llm"）先过 validate_harness_safety，违规 -> unsafe_harness_blocked；
        且**必须 Docker 执行**，Docker 不可用 -> sandbox_failed（不回退本地跑 LLM 代码）。
      - 内置模板（source="template"）可信，Docker 不可用时允许本地回退。
    判定优先读 AUDITAGENTX_RESULT_JSON，无则退回 AUDITAGENTX_VULN_TRIGGERED marker。
    """
    timeout = timeout or int(getattr(settings, "harness_timeout", 8))
    lang = normalize_language(language)
    if require_docker is None:
        require_docker = (source == "llm") and bool(getattr(settings, "harness_require_docker", True))

    res = _base_result(lang, source, "none")
    if not harness_code or not harness_code.strip():
        res["reason"] = "empty_harness"
        return res

    # 1) 安全审查
    safety = validate_harness_safety(harness_code, lang, source)
    res["safety"] = safety
    if not safety["allowed"]:
        res["verdict"] = V_UNSAFE_BLOCKED
        res["reason"] = f"unsafe_harness_blocked: {safety['blocked_reason']}"
        logger.warning("Harness 被安全策略阻止执行: %s", safety["blocked_reason"])
        return res

    # 2) Docker-first 执行
    docker_out = _run_in_docker(harness_code, timeout, lang)
    if docker_out is not None:
        return _finalize(docker_out, source, lang, "docker")

    # Docker 不可用
    if require_docker:
        res["verdict"] = V_SANDBOX_FAILED
        res["reason"] = ("sandbox_failed: Docker 不可用，LLM 生成的 Harness 出于安全禁止本地执行"
                         "（设 enable_sandbox=True 并配置 Docker，或 harness_require_docker=False）")
        return res

    # 仅内置模板允许本地回退
    local_out = _run_local(harness_code, timeout, lang, source)
    return _finalize(local_out, source, lang, local_out.get("backend", "local"))


def _finalize(exec_out: dict, source: str, language: str, backend: str) -> dict:
    """把底层执行输出（stdout/stderr）解析为结构化结果 + verdict + verification_level。"""
    res = _base_result(language, source, backend)
    res.update({k: exec_out.get(k, res.get(k)) for k in
                ("executed", "stdout", "stderr", "reason")})
    stdout = exec_out.get("stdout", "") or ""

    if not exec_out.get("executed"):
        # 未真正执行（解释器缺失/超时/错误）
        res["verdict"] = V_INCONCLUSIVE
        res["reason"] = exec_out.get("reason") or "not_executed"
        return res

    # 优先结构化 JSON
    parsed = _parse_result_json(stdout)
    if parsed:
        res["triggered"] = bool(parsed.get("triggered"))
        res["sink_called"] = bool(parsed.get("sink_called", res["triggered"]))
        res["target_function_called"] = bool(parsed.get("target_function_called"))
        res["sink_name"] = parsed.get("sink_name")
        res["captured_argument"] = parsed.get("captured_argument")
        res["payload"] = parsed.get("payload")
        res["trigger_detail"] = str(parsed.get("trigger_detail") or "")[:300]
    else:
        # 退回旧 marker
        res["triggered"] = TRIGGER_MARKER in stdout
        res["sink_called"] = res["triggered"]
        if res["triggered"]:
            m = re.search(re.escape(TRIGGER_MARKER) + r"(.*)", stdout)
            res["trigger_detail"] = (m.group(1).strip() if m else "")[:300]

    # verification_level：模板恒为机理级；LLM 只有真实调用目标函数才算 target_specific
    if source == "template":
        res["verification_level"] = LEVEL_TEMPLATE
    elif res["target_function_called"]:
        res["verification_level"] = LEVEL_TARGET
    else:
        res["verification_level"] = LEVEL_NONE

    # 执行级 verdict
    if not res["triggered"]:
        res["verdict"] = V_NOT_REPRODUCED
        res["reason"] = res["reason"] or "executed_but_sink_not_triggered"
    elif res["verification_level"] == LEVEL_TARGET:
        res["verdict"] = V_TARGET_CONFIRMED
    else:
        res["verdict"] = V_MECHANISM_CONFIRMED
    return res


def _run_in_docker(harness_code: str, timeout: int, language: str) -> dict | None:
    """Docker 沙箱执行（网络禁用 + 内存/CPU/超时限制 + 自动清理）；不可用返回 None。"""
    if not getattr(settings, "enable_sandbox", False):
        return None
    try:
        import docker
    except ImportError:
        return None
    rt = _LANG_RUNTIMES.get(language, _LANG_RUNTIMES["python"])
    code = harness_code
    if language == "php":
        code = code.replace("<?php", "").replace("?>", "")
    container = None
    try:
        client = docker.DockerClient(base_url=settings.docker_host)
        container = client.containers.run(
            image=rt["image"],
            command=rt["inline"] + [code],
            detach=True,
            network_disabled=True,          # 禁网
            mem_limit="256m",               # 内存上限
            nano_cpus=1_000_000_000,        # CPU 上限（1 核）
            pids_limit=64,                  # 进程数上限，抑制 fork 炸弹
            read_only=True,                 # 根文件系统只读
            tmpfs={"/tmp": "size=16m"},     # 仅 /tmp 可写（受限）
            remove=False,
        )
        container.wait(timeout=timeout)
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")
        return {"executed": True, "stdout": stdout[:4000], "stderr": stderr[:2000],
                "backend": "docker", "reason": None}
    except Exception as e:  # noqa: BLE001
        logger.warning("Docker harness 执行失败: %s", e)
        return None
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                pass


def _run_local(harness_code: str, timeout: int, language: str, source: str) -> dict:
    """受控本地子进程执行——仅供内置模板兜底（LLM 代码不会走到这里）。"""
    if not getattr(settings, "enable_local_harness", True):
        return {"executed": False, "backend": "none", "reason": "local_harness_disabled"}
    rt = _LANG_RUNTIMES.get(language, _LANG_RUNTIMES["python"])
    interpreter = sys.executable if language == "python" else shutil.which(rt["local"])
    if not interpreter:
        return {"executed": False, "backend": "none",
                "reason": f"interpreter_unavailable: {language}"}
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / f"harness.{rt['ext']}"
        script.write_text(harness_code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [interpreter, str(script)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, cwd=tmp,
            )
            return {"executed": True, "stdout": (proc.stdout or "")[:4000],
                    "stderr": (proc.stderr or "")[:2000], "backend": "local", "reason": None}
        except subprocess.TimeoutExpired:
            return {"executed": True, "stdout": "", "stderr": "harness timed out",
                    "backend": "local", "reason": "timeout"}
        except Exception as e:  # noqa: BLE001
            return {"executed": False, "backend": "local", "reason": f"exec_error: {e}"}

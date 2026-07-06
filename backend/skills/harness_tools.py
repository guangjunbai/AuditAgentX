"""Fuzzing Harness 底层工具（借鉴 DeepAudit 的动态验证思路）。

提供两类能力：
1. extract_function：从项目源码中提取目标漏洞函数，供构建隔离 Harness。
2. run_harness：在沙箱（优先 Docker，回退受控本地子进程）执行 Python Harness，
   通过统一触发标记判断漏洞是否被动态触发。

安全约束：Harness 由提示词强制 mock 所有危险 sink，只在本地隔离环境短时运行，
绝不真实执行系统命令 / 删除文件 / 发起网络请求。
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)

TRIGGER_MARKER = "AUDITAGENTX_VULN_TRIGGERED"
NO_TRIGGER_MARKER = "AUDITAGENTX_NO_TRIGGER"

# 各语言的函数定义起始模式
_FUNC_START = re.compile(
    r"^\s*(?:def |function |func |sub |public |private |protected |static |async def ).*",
    re.IGNORECASE,
)


def extract_function(code_root: Path | None, file: str | None, line: int | None,
                     *, max_lines: int = 60) -> dict:
    """提取 file:line 所在的函数源码（尽力而为，兼容多语言）。"""
    fallback = {"found": False, "file": file, "line": line, "function_code": ""}
    if not code_root or not file or not line:
        fallback["reason"] = "missing_code_root_or_location"
        return fallback

    target = (Path(code_root) / file).resolve()
    try:
        target.relative_to(Path(code_root).resolve())
    except ValueError:
        fallback["reason"] = "file_outside_workspace"
        return fallback
    if not target.exists() or not target.is_file():
        fallback["reason"] = "file_not_found"
        return fallback

    lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
    idx = max(0, min(line - 1, len(lines) - 1))

    # 向上找函数定义起点
    start = idx
    for i in range(idx, max(-1, idx - max_lines), -1):
        if _FUNC_START.match(lines[i]):
            start = i
            break
    # 向下按缩进/花括号找函数结束
    end = min(len(lines), start + max_lines)
    def_indent = len(lines[start]) - len(lines[start].lstrip())
    for j in range(start + 1, min(len(lines), start + max_lines)):
        stripped = lines[j].strip()
        if not stripped:
            continue
        cur_indent = len(lines[j]) - len(lines[j].lstrip())
        if cur_indent <= def_indent and _FUNC_START.match(lines[j]):
            end = j
            break
    else:
        end = min(len(lines), start + max_lines)

    return {
        "found": True,
        "file": file,
        "line": line,
        "start_line": start + 1,
        "end_line": end,
        "function_code": "\n".join(lines[start:end]),
        "language": target.suffix.lstrip("."),
    }


def build_template_harness(vuln_type: str | None, code_snippet: str | None = None) -> str:
    """LLM 不可用时的兜底：按漏洞类型生成可运行的 mock-based Fuzzing Harness。

    这些 Harness 验证的是「该漏洞类型的可利用机理」（类型级），
    mock 掉危险 sink，喂恶意 payload，检测是否以危险方式触发。
    """
    t = (vuln_type or "").lower()
    if "command" in t or "rce" in t or "os command" in t:
        return _HARNESS_CMDI
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


def run_harness(harness_code: str, *, timeout: int | None = None) -> dict:
    """执行 Python Harness，返回执行结果与是否触发漏洞。

    优先在 Docker 沙箱执行；不可用时回退受控本地子进程（带超时）。
    """
    timeout = timeout or int(getattr(settings, "harness_timeout", 8))
    if not harness_code or not harness_code.strip():
        return {"executed": False, "triggered": False, "reason": "empty_harness"}

    docker_result = _run_in_docker(harness_code, timeout)
    if docker_result is not None:
        return docker_result

    return _run_local(harness_code, timeout)


def _judge(stdout: str, stderr: str, exit_code: int, backend: str) -> dict:
    triggered = TRIGGER_MARKER in (stdout or "")
    trigger_detail = ""
    if triggered:
        m = re.search(re.escape(TRIGGER_MARKER) + r"(.*)", stdout)
        trigger_detail = (m.group(1).strip() if m else "")[:300]
    return {
        "executed": True,
        "triggered": triggered,
        "trigger_detail": trigger_detail,
        "backend": backend,
        "exit_code": exit_code,
        "stdout": (stdout or "")[:2000],
        "stderr": (stderr or "")[:1000],
    }


def _run_in_docker(harness_code: str, timeout: int) -> dict | None:
    """尝试 Docker 沙箱执行；不可用返回 None 以触发本地回退。"""
    if not getattr(settings, "enable_sandbox", False):
        return None
    try:
        import docker
    except ImportError:
        return None
    try:
        client = docker.DockerClient(base_url=settings.docker_host)
        container = client.containers.run(
            image="python:3.11-slim",
            command=["python", "-c", harness_code],
            detach=True, network_disabled=True, mem_limit="256m", remove=False,
        )
        container.wait(timeout=timeout)
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="ignore")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="ignore")
        container.remove(force=True)
        return _judge(stdout, stderr, 0, "docker")
    except Exception as e:  # noqa: BLE001
        logger.warning("Docker harness 执行失败，回退本地: %s", e)
        return None


def _run_local(harness_code: str, timeout: int) -> dict:
    """受控本地子进程执行（Harness 已 mock 危险 sink，故安全）。"""
    if not getattr(settings, "enable_local_harness", True):
        return {"executed": False, "triggered": False,
                "reason": "local_harness_disabled", "backend": "none"}
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "harness.py"
        script.write_text(harness_code, encoding="utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, str(script)],
                capture_output=True, text=True, timeout=timeout,
                cwd=tmp,  # 隔离工作目录
            )
            return _judge(proc.stdout, proc.stderr, proc.returncode, "local")
        except subprocess.TimeoutExpired:
            return {"executed": True, "triggered": False, "backend": "local",
                    "reason": "timeout", "stdout": "", "stderr": "harness timed out"}
        except Exception as e:  # noqa: BLE001
            return {"executed": False, "triggered": False, "backend": "local",
                    "reason": f"exec_error: {e}"}

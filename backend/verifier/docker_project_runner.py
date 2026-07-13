"""DockerProjectRunner —— Docker-first Deep Mode 沙箱：在容器内启动 GitHub 项目。

流程：code_root + launch_plan → 生成/复用 Dockerfile → build → run → 健康检查 → base_url。
退出时自动 docker rm -f 清理容器，并采集 docker logs 摘要。

安全边界：仅用于本地 Docker 沙箱 / 授权目标；容器限内存，扫描后即销毁。
失败时如实返回状态（sandbox_start_failed / health_check_failed / dependency_install_failed），
绝不造假复现结果。

复用：端口分配 / 健康检查复用 app_runner 的 _free_port / _wait_healthy，不重复实现。
"""
from __future__ import annotations

import json as _json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from backend.config import settings
from backend.runtime.scan_execution import (
    SandboxCommandCancelled,
    SandboxCommandTimeout,
    is_cancelled,
    register_cleanup_callback,
    run_managed_command,
    unregister_cleanup_callback,
)
from backend.verifier.app_runner import _free_port, _wait_healthy, get_docker_client

logger = logging.getLogger(__name__)

# 沙箱状态
STARTED = "started"
SANDBOX_START_FAILED = "sandbox_start_failed"
HEALTH_CHECK_FAILED = "health_check_failed"
DEPENDENCY_INSTALL_FAILED = "dependency_install_failed"
LAUNCH_NOT_DETECTED = "launch_not_detected"   # 预检：无法自动识别启动方式，未尝试构建
NOT_WEB_TARGET = "not_web_target"             # 原生 CLI/系统项目：HTTP 项目沙箱不适用
UNSAFE_PROJECT_CONFIG = "unsafe_project_config"  # 项目容器配置违反沙箱策略
SANDBOX_BUILD_TIMEOUT = "sandbox_build_timeout"
SANDBOX_CANCELLED = "sandbox_cancelled"


def _first_line(text: str, limit: int = 200) -> str:
    """取错误信息的首个有效行，便于生成可读 reason。"""
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return str(text)[:limit]


def _diagnostic_tail(text: str, limit: int = 1200) -> str:
    """保留 Compose 错误末尾；真正原因通常在大量 Pulling/Waiting 输出之后。"""
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    return "\n".join(lines[-12:])[-limit:]


def _transient_pull_failure(text: str) -> bool:
    lower = str(text).lower()
    return any(token in lower for token in (
        " eof", "context canceled", "tls handshake timeout", "i/o timeout",
        "connection reset", "temporary failure", "unexpected status from head request",
        "auth.docker.io", "registry-1.docker.io",
    ))


def build_dockerfile(launch_plan: dict, port: int) -> str:
    """SandboxBuilder：按 launch_plan 生成最小 Dockerfile（无项目 Dockerfile 时）。"""
    framework = (launch_plan.get("framework") or "").lower()
    install = launch_plan.get("install_command")
    run = launch_plan.get("run_command") or launch_plan.get("command") or ""
    run = run.replace("{port}", str(port))
    workdir = _safe_workdir(launch_plan.get("working_dir"))
    app_workdir = "/app" + ("/" + workdir if workdir else "")

    if "node" in framework or "express" in framework:
        install = install or "npm install"
        return (
            "FROM node:20-slim\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            f"RUN {install}\n"
            f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "php" in framework:
        return (
            "FROM php:8.2-cli\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "spring" in framework or "java" in framework:
        return (
            "FROM eclipse-temurin:17-jdk\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            f"WORKDIR {app_workdir}\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    # 默认 Python
    install = install or "pip install --no-cache-dir -r requirements.txt"
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY . /app\n"
        f"WORKDIR {app_workdir}\n"
        # 不能用 `|| pip install flask ...` 吞掉真实依赖失败；否则容器“构建成功”但实际
        # 项目依赖缺失，最终把问题伪装成无意义的健康检查失败。
        f"RUN {install}\n"
        f"EXPOSE {port}\n"
        f"CMD {_cmd_json(run)}\n"
    )


def _safe_workdir(value: str | None) -> str:
    """把源码识别出的相对工作目录转为 Docker 内安全路径。"""
    raw = str(value or ".").replace("\\", "/").strip("/")
    if not raw or raw == ".":
        return ""
    parts = [part for part in raw.split("/") if part and part not in {".", ".."}]
    return "/".join(parts)


def _safe_project_dockerfile(root: Path, value: str | None) -> str | None:
    """Return a repository-relative Dockerfile path, rejecting traversal/absolute paths."""
    raw = str(value or "Dockerfile").replace("\\", "/").strip()
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        return None
    candidate = (root / path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return path.as_posix() if candidate.is_file() else None


def _cmd_json(run_command: str) -> str:
    """把启动命令转成 Dockerfile CMD。

    使用 ``sh -c`` 而不是简单 split 成 argv，原因：
    - Java/Spring 常见 ``target/*.jar`` 需要 shell 展开通配符；
    - 用户手动填写的命令可能包含引号、环境变量或 ``&&``；
    - npm/pip 等命令以 shell 运行更贴近日常启动方式。
    """
    return _json.dumps(["sh", "-c", run_command or "true"], ensure_ascii=False)


class DockerProjectRunner:
    """上下文管理器：进入返回 self（含 base_url / metadata），退出清理容器。"""

    def __init__(self, code_root: Path, launch_plan: dict | None = None,
                 *, env: dict | None = None, scan_id: str | None = None,
                 trust_project_container_config: bool = False,
                 build_timeout: int | None = None, health_timeout: int | None = None) -> None:
        # 未显式传入时读配置：单容器项目默认 90s，镜像构建 900s；compose 另有更长超时。
        if build_timeout is None:
            build_timeout = int(getattr(settings, "sandbox_build_timeout", 900))
        if health_timeout is None:
            health_timeout = int(getattr(settings, "sandbox_project_health_timeout", 90))
        # Compose 命令会以 code_root 作为 cwd；这里必须先绝对化，否则 `-f` 收到相对
        # 路径时会被 cwd 再拼接一次（data/projects/.../data/projects/...）。
        self.code_root = Path(code_root).resolve()
        self.launch_plan = launch_plan or {}
        self.env = env or {}
        self.scan_id = scan_id or "adhoc"
        self.trust_project_container_config = bool(trust_project_container_config)
        self.build_timeout = build_timeout
        self.health_timeout = health_timeout

        self.base_url: str | None = None
        self.metadata: dict = {
            "mode": "docker_project",
            "code_root": str(self.code_root),
            "launch_plan": self.launch_plan,
            "image": f"auditagentx-{re.sub(r'[^a-z0-9]', '', self.scan_id.lower())[:20] or 'scan'}",
            "container_id": None,
            "container_ids": [],
            "compose_project": None,
            "cleanup_attempted": False,
            "cleanup_succeeded": None,
            "base_url": None,
            "port": self.launch_plan.get("port") or 8000,
            "health_path": self.launch_plan.get("health_path") or "/",
            "working_dir": _safe_workdir(self.launch_plan.get("working_dir")) or ".",
            "health_check": "failed",
            "launch_command": (self.launch_plan.get("run_command")
                               or self.launch_plan.get("command")),
            "image_build_attempted": False,
            "container_start_attempted": False,
            "logs_excerpt": "",
            "status": SANDBOX_START_FAILED,
            "reason": "",
            "diagnostics": [],
            "trust_project_container_config": self.trust_project_container_config,
        }
        self._client = None
        self._container = None
        # docker compose 编排（多服务项目）时记录，供清理使用
        self._compose_project: str | None = None
        self._compose_file: str | None = None
        self._generated_compose_file_name: str | None = None
        self._compose_selected_target_port: int | None = None
        self._compose_web_service: str | None = None
        self._compose_environment_temp_dir: Path | None = None
        # 是否有 build 型服务的镜像无法拉取、必须本地构建（决定 up 是否加 --build）。
        self._compose_needs_build: bool = False
        self._generated_dockerfile_name: str | None = None
        self._build_deadline: float | None = None
        self._cleanup_lock = threading.RLock()
        self._cleanup_done = False
        self._cleanup_token: int | None = None

    def __enter__(self) -> "DockerProjectRunner":
        try:
            self._start()
        except SandboxCommandTimeout as e:
            self.metadata["status"] = SANDBOX_BUILD_TIMEOUT
            self.metadata["failure_code"] = SANDBOX_BUILD_TIMEOUT
            self.metadata["phase"] = e.phase
            self.metadata["timeout_seconds"] = e.timeout_seconds
            if e.stderr or e.stdout:
                self.metadata["logs_excerpt"] = _diagnostic_tail(e.stderr or e.stdout)
            self.metadata["reason"] = f"沙箱命令超时（phase={e.phase}）"
            logger.warning("沙箱命令超时: phase=%s", e.phase)
        except SandboxCommandCancelled as e:
            self.metadata["status"] = SANDBOX_CANCELLED
            self.metadata["failure_code"] = SANDBOX_CANCELLED
            self.metadata["phase"] = e.phase
            if e.stderr or e.stdout:
                self.metadata["logs_excerpt"] = _diagnostic_tail(e.stderr or e.stdout)
            self.metadata["reason"] = "扫描取消，沙箱命令已终止并回收"
            logger.info("沙箱命令已取消: phase=%s", e.phase)
        except _ComposeEnvironmentError as e:
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["failure_code"] = e.failure_code
            self.metadata["missing_env_files"] = e.missing_env_files
            self.metadata["reason"] = str(e)
            logger.warning("Compose 环境预检失败: %s", e)
        except _DependencyError as e:
            self.metadata["status"] = DEPENDENCY_INSTALL_FAILED
            self.metadata["logs_excerpt"] = str(e)[:800]
            self.metadata["reason"] = "镜像构建时依赖安装失败：" + _first_line(str(e))
            logger.warning("沙箱依赖安装失败: %s", e)
        except Exception as e:  # noqa: BLE001
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata.setdefault("failure_code", SANDBOX_START_FAILED)
            # _run_compose already captured compose logs/ps before raising. Preserve
            # that primary evidence; only fall back to exception text when no runtime
            # logs were obtainable.
            if not self.metadata.get("logs_excerpt"):
                self.metadata["logs_excerpt"] = _diagnostic_tail(str(e), 1200)
            self.metadata["reason"] = "沙箱构建/启动失败：" + _diagnostic_tail(str(e), 500)
            logger.warning("沙箱启动失败: %s", e)
        return self

    def __exit__(self, *exc) -> None:
        unregister_cleanup_callback(self.scan_id, self._cleanup_token)
        self._cleanup_token = None
        self._cleanup()

    # ---------- 内部 ----------
    def _start(self) -> None:
        if not self.code_root.exists() or not self.code_root.is_dir():
            raise RuntimeError(f"code_root 不存在或不是目录: {self.code_root}")
        internal_port = int(self.metadata["port"])
        host_port = _free_port()
        base_url = f"http://127.0.0.1:{host_port}"
        image_tag = self.metadata["image"]
        self._build_deadline = time.monotonic() + max(0, self.build_timeout)

        if self.launch_plan.get("runtime_kind") == "native_cli":
            self.metadata["status"] = NOT_WEB_TARGET
            self.metadata["reason"] = (
                "项目被识别为原生 CLI/系统软件，不存在可自动健康检查的 HTTP 服务；"
                "HTTP 项目沙箱不适用，已保留静态验证与函数级 Harness 结果。"
            )
            self.metadata["diagnostics"].append(
                f"non-web runtime detected from {self.launch_plan.get('source_evidence') or 'project structure'}"
            )
            return

        configured_dockerfile = _safe_project_dockerfile(
            self.code_root, self.launch_plan.get("dockerfile"))
        project_dockerfile = configured_dockerfile is not None
        has_dockerfile = project_dockerfile and self.trust_project_container_config
        run_command = self.launch_plan.get("run_command") or self.launch_plan.get("command")
        compose = self.launch_plan.get("compose")

        if project_dockerfile and not self.trust_project_container_config:
            self.metadata["diagnostics"].append(
                "ignored untrusted project Dockerfile; using generated restricted Dockerfile"
            )

        # 0) 多服务项目：若检测到 docker-compose，优先按项目既定方式编排启动
        #    （单容器无法提供 DB/Redis 等依赖服务，这是真实开源项目动态验证失败的高频原因）。
        if compose and (self.code_root / compose).exists():
            policy = _validate_compose_policy(
                self.code_root / compose, code_root=self.code_root, env=self.env,
            )
            if not policy["allowed"]:
                self.metadata["status"] = UNSAFE_PROJECT_CONFIG
                self.metadata["reason"] = "项目 docker-compose 被安全策略阻止：" + policy["reason"]
                self.metadata["diagnostics"].extend(policy["checks"])
                return
            if not self.trust_project_container_config:
                self.metadata["diagnostics"].append(
                    "compose configuration auto-approved by restricted policy; direct project Dockerfile remains disabled"
                )
            self.metadata["diagnostics"].append(f"using docker compose file: {compose}")
            # `-p` 只能隔离 Compose 自动生成的名称。项目若写死
            # container_name / networks.*.name / host ports，仍会和现有靶场冲突。
            # 生成一次性覆写配置，保留服务依赖但移除这些跨项目全局名称。
            isolated_compose = self._prepare_isolated_compose(
                compose, self.launch_plan.get("port")
            )
            self.metadata["container_start_attempted"] = True
            self._run_compose(isolated_compose, self.launch_plan.get("port"))
            return

        # 1) 启动预检：既没有项目自带 Dockerfile，也没识别到启动命令 —— 无法自动容器化。
        #    直接如实返回 launch_not_detected（附手动步骤），避免生成 CMD 为空的坏容器
        #    再报出不可诊断的 "no command specified"（旧 bug 根因）。
        if not has_dockerfile and not run_command:
            self.metadata["status"] = LAUNCH_NOT_DETECTED
            steps = self.launch_plan.get("manual_steps") or []
            hint = "；".join(steps) if steps else "未在项目中识别到 Web 服务的启动方式"
            compose_note = (
                "（检测到 docker-compose，属多服务编排，当前单容器沙箱不自动编排；"
                "请先手动 `docker compose up`，再用 url 模式指定 base_url）"
                if compose else ""
            )
            self.metadata["reason"] = (
                f"无法自动识别项目启动方式：{hint}{compose_note}。"
                "可在动态验证选项中手动提供启动命令（run_command），"
                "或改用 url 模式指定一个已运行的授权靶场 base_url。"
                "界面输入框中的灰色文字只是示例 placeholder，不会作为实际命令提交。"
            )
            logger.info("沙箱预检未通过（不构建）：%s", self.metadata["reason"])
            return

        # 未安装 docker SDK / 引擎不可用时抛异常 -> sandbox_start_failed
        self._client = get_docker_client()

        # 1) 构建镜像：优先项目 Dockerfile，否则生成临时 Dockerfile
        if not has_dockerfile:
            command_policy = _validate_generated_launch_plan(self.launch_plan)
            if not command_policy["allowed"]:
                self.metadata["status"] = UNSAFE_PROJECT_CONFIG
                self.metadata["reason"] = "自动启动命令被安全策略阻止：" + command_policy["reason"]
                self.metadata["diagnostics"].extend(command_policy["checks"])
                return
            dockerfile = build_dockerfile(self.launch_plan, internal_port)
            dockerfile_name = self._next_generated_dockerfile_name()
            (self.code_root / dockerfile_name).write_text(dockerfile, encoding="utf-8")
            self._generated_dockerfile_name = dockerfile_name
            self.metadata["diagnostics"].append(f"generated {dockerfile_name} from launch_plan")
        else:
            dockerfile_name = configured_dockerfile
            self.metadata["diagnostics"].append("using project Dockerfile")
        self.metadata["dockerfile"] = dockerfile_name

        try:
            self.metadata["image_build_attempted"] = True
            built = run_managed_command(
                self.scan_id,
                ["docker", "build", "--file", str(dockerfile_name), "--tag", image_tag,
                 "--rm", "--force-rm", "."],
                cwd=self.code_root,
                env=self._compose_subprocess_env(),
                timeout=self.build_timeout,
                deadline=self._build_deadline,
                phase="image_build",
            )
            if built.returncode != 0:
                raise RuntimeError(built.stderr or built.stdout or "docker build 失败")
        except FileNotFoundError as e:
            raise RuntimeError("docker CLI 不可用，无法执行受管沙箱构建") from e
        except Exception as e:  # noqa: BLE001
            if isinstance(e, (SandboxCommandTimeout, SandboxCommandCancelled)):
                raise
            msg = str(e).lower()
            if any(k in msg for k in ("pip install", "npm install", "composer",
                                      "could not find", "no matching distribution")):
                raise _DependencyError(str(e)) from e
            raise

        # 2) 启动容器（注入默认监听环境变量，确保服务绑定 0.0.0.0 可被端口映射访问）
        run_env = {
            "APP_HOST": "0.0.0.0", "HOST": "0.0.0.0", "FLASK_RUN_HOST": "0.0.0.0",
            "PORT": str(internal_port), "FLASK_RUN_PORT": str(internal_port),
            **self.env,
        }
        self.metadata["container_start_attempted"] = True
        self._container = self._client.containers.run(
            image=image_tag, detach=True, remove=False,
            ports={f"{internal_port}/tcp": host_port},
            environment=run_env, mem_limit="512m",
            pids_limit=256,
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
        )
        self.metadata["container_id"] = self._container.id[:12]
        self._register_cancel_cleanup()

        # 3) 健康检查
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if self._wait_single_container_healthy(health_url):
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "health_check": "passed",
                "status": STARTED, "reason": "",
            })
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"容器已启动但 {self.health_timeout}s 内健康检查未通过"
                f"（health_path={self.metadata['health_path']}，容器端口 {internal_port}）："
                "可能应用未监听 0.0.0.0、实际端口与探测端口不一致、启动过慢或已崩溃，"
                "详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._logs()

    def _wait_single_container_healthy(self, health_url: str) -> bool:
        deadline = time.monotonic() + self.health_timeout
        while time.monotonic() < deadline:
            if is_cancelled(self.scan_id):
                raise SandboxCommandCancelled(
                    "scan cancellation requested", phase="health_check"
                )
            remaining = max(1, min(3, int(deadline - time.monotonic()) + 1))
            if _wait_healthy(health_url, remaining):
                return True
        return False

    def _logs(self) -> str:
        if not self._container:
            return ""
        try:
            self._container.reload()
            return self._container.logs().decode("utf-8", errors="ignore")[-3000:]
        except Exception:  # noqa: BLE001
            return ""

    def runtime_logs(self) -> str:
        """返回运行中容器/Compose 的最新日志，供动态判据做请求前后差分。

        仅作为已运行本地沙箱的辅助证据，不能单独把日志出现当成漏洞确认；调用方仍须
        保存对应 HTTP 请求、良性基线和漏洞类型专用判据。
        """
        return self._compose_logs() if self._compose_project else self._logs()

    # ---------- docker compose 多服务编排 ----------
    def _compose_subprocess_env(self) -> dict:
        """Return one consistent, unlogged environment for every Compose subprocess."""
        environment = os.environ.copy()
        environment.update(self.env)
        return environment

    def _run_compose(self, compose_file: str, port_hint) -> None:
        """用 `docker compose up` 启动多服务项目，探测对外发布端口并健康检查。

        失败时如实返回状态与 reason，绝不造假复现结果。退出时 `docker compose down` 清理。
        """
        project = "aax" + (re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:20] or "scan")
        self._compose_project = project
        self._compose_file = str(self.code_root / compose_file)
        self.metadata["mode"] = "docker_compose"
        self.metadata["compose_project"] = project
        # Docker Desktop 的内部代理在 Compose 并发拉取多个镜像时容易出现 auth.docker.io
        # EOF。先解析镜像清单并逐个顺序预拉取，既能复用缓存，也避免并发鉴权风暴。
        self._prefetch_compose_images(project)

        # 只有确有 build 型服务的镜像拉不到、必须本地构建时才加 --build；否则用已拉取/缓存
        # 的官方镜像（如 DVWA），避免无谓本地重建触发构建期错误（apt-get 失败等）。
        up_cmd = ["docker", "compose", "-p", project, "-f", self._compose_file, "up", "-d"]
        if self._compose_needs_build:
            up_cmd.append("--build")
        up_cmd += ["--pull", "never"]
        self.metadata["launch_command"] = (
            f"docker compose -f {compose_file} up -d"
            + (" --build" if self._compose_needs_build else "") + " --pull never")
        proc = None
        for attempt in range(1, 4):
            try:
                proc = run_managed_command(
                    self.scan_id, up_cmd, cwd=self.code_root,
                    env=self._compose_subprocess_env(), timeout=self.build_timeout,
                    deadline=self._build_deadline, phase="compose_up",
                )
            except FileNotFoundError as e:
                raise RuntimeError("docker compose CLI 不可用（需 Docker Compose v2）") from e
            except (SandboxCommandTimeout, SandboxCommandCancelled) as e:
                self.metadata["compose_ps"] = self._compose_ps()
                self.metadata["logs_excerpt"] = self._compose_logs()
                self.metadata["last_exception"] = f"{type(e).__name__}: {e}"
                raise
            err = (proc.stderr or proc.stdout or "").strip()
            if proc.returncode == 0 or not _transient_pull_failure(err) or attempt == 3:
                break
            self.metadata["diagnostics"].append(
                f"compose image pull transient failure; retry {attempt}/3: {_diagnostic_tail(err, 240)}"
            )
            time.sleep(attempt * 2)

        if proc is None or proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            self.metadata["compose_ps"] = self._compose_ps()
            self.metadata["logs_excerpt"] = self._compose_logs()
            low = err.lower()
            if any(k in low for k in ("pip install", "npm install", "could not find",
                                      "no matching distribution", "failed to solve")):
                raise _DependencyError(err)
            raise RuntimeError(_diagnostic_tail(err) or "docker compose up 失败")

        # `up -d` 已创建资源；后续 inventory/端口/健康检查期间也必须可立即取消回收。
        self._register_cancel_cleanup()

        inventory = self._compose_inventory()
        self.metadata["compose_containers"] = inventory
        self.metadata["container_ids"] = [
            str(item.get("id")) for item in inventory if item.get("id")
        ]

        # 探测对外发布的 HTTP 端口
        host_port = self._compose_published_port(project, port_hint)
        if not host_port:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["reason"] = (
                "docker compose 已启动，但未找到对外发布的 HTTP 端口，无法探测："
                "请在 compose 文件里为 Web 服务映射端口（ports: '<host>:<container>'）。"
            )
            self.metadata["logs_excerpt"] = self._compose_logs()
            return

        scheme = _scheme_for_port(self._compose_selected_target_port, self.launch_plan)
        base_url = f"{scheme}://127.0.0.1:{host_port}"
        self.metadata["scheme"] = scheme
        self.metadata["selected_service_port"] = self._compose_selected_target_port
        self.metadata["health_url"] = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        # 多服务 compose 首启动依赖 DB/迁移，动辄数分钟；用更长的 compose 专用超时，
        # 避免把“仍在启动”误判为“沙箱健康检查失败”。
        compose_health_timeout = max(self.health_timeout,
                                     int(getattr(settings, "sandbox_compose_health_timeout", 300)))
        # 边等健康边盯目标容器是否已崩溃退出：容器 exit(1) 后再干等满超时是纯浪费，
        # 且真实原因（启动 traceback）远比“Ns 内未通过健康检查”有用。
        crash = self._compose_target_crash_reason()
        if crash:
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = crash
            self.metadata["logs_excerpt"] = self._compose_logs()
            self.metadata["compose_ps"] = self._compose_ps()
            return
        healthy, attempts = self._wait_compose_healthy(
            base_url, compose_health_timeout,
            crash_probe=self._compose_target_crash_reason,
            cancel_probe=lambda: is_cancelled(self.scan_id),
        )
        self.metadata["health_attempts"] = attempts
        crash = crash or self._compose_target_crash_reason()
        if healthy:
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "port": host_port,
                "health_check": "passed", "status": STARTED, "reason": "",
            })
        elif crash:
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = crash
            self.metadata["logs_excerpt"] = self._compose_logs()
            self.metadata["compose_ps"] = self._compose_ps()
            return
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"docker compose 服务已启动但 {compose_health_timeout}s 内健康检查未通过"
                f"（探测端口 {host_port}，health_path={self.metadata['health_path']}）："
                "可能 Web 服务尚未就绪、端口映射不对或依赖服务未启动，详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._compose_logs()

    def _prefetch_compose_images(self, project: str) -> None:
        """顺序准备 Compose 镜像；已存在的镜像直接复用，瞬时网络错误自动重试。"""
        # `image` and `build` may intentionally coexist: `image` names the result
        # of the local build. Pulling that name first turns valid projects such as
        # VAmPI into a false sandbox_start_failed when the tag is not published.
        locally_built = self._compose_locally_built_images(project)
        cmd = ["docker", "compose", "-p", project, "-f", self._compose_file,
               "config", "--images"]
        proc = run_managed_command(
            self.scan_id, cmd, cwd=self.code_root,
            env=self._compose_subprocess_env(), timeout=60,
            deadline=self._build_deadline, phase="compose_config",
        )
        if proc.returncode != 0:
            raise RuntimeError("无法解析 Compose 镜像清单：" + _diagnostic_tail(proc.stderr or proc.stdout))
        images = list(dict.fromkeys(
            line.strip() for line in (proc.stdout or "").splitlines() if line.strip()
        ))
        self.metadata["diagnostics"].append(f"compose images discovered: {len(images)}")

        needs_build = False
        for index, image in enumerate(images, start=1):
            is_build_service = image in locally_built
            # build 型服务且是**裸名**（无 registry 路径，如 vampi_docker:latest 或
            # proj-service）：这类只可能是本地构建产物，仓库里不存在，直接本地构建、不试拉。
            if is_build_service and "/" not in image:
                needs_build = True
                self.metadata["diagnostics"].append(
                    f"compose image {index}/{len(images)} will be built locally: {image}"
                )
                continue
            # 1) 已缓存直接复用
            cached = run_managed_command(
                self.scan_id, ["docker", "image", "inspect", image],
                cwd=self.code_root, env=self._compose_subprocess_env(), timeout=30,
                deadline=self._build_deadline, phase="image_inspect",
            )
            if cached.returncode == 0:
                self.metadata["diagnostics"].append(
                    f"compose image {index}/{len(images)} cached: {image}"
                )
                continue

            # 2) 尝试拉取——**声明了 build 的服务也先试拉**：像 DVWA 这类
            #    `image: ghcr.io/...` + `build: .` 共存的项目，官方镜像可直接拉下来用，
            #    避免每次都本地重建、build 在 apt-get 阶段挂掉。拉不到才本地构建。
            pull_timeout = min(self.build_timeout,
                               int(getattr(settings, "sandbox_image_pull_timeout", 600)))
            last_error = ""
            for attempt in range(1, 4):
                try:
                    pulled = run_managed_command(
                        self.scan_id, ["docker", "pull", image], cwd=self.code_root,
                        env=self._compose_subprocess_env(), timeout=pull_timeout,
                        deadline=self._build_deadline, phase="image_pull",
                    )
                except FileNotFoundError as e:
                    raise RuntimeError("docker CLI 不可用，无法拉取 Compose 镜像") from e
                except (SandboxCommandTimeout, SandboxCommandCancelled):
                    raise
                if pulled.returncode == 0:
                    self.metadata["diagnostics"].append(
                        f"compose image {index}/{len(images)} pulled: {image}"
                    )
                    last_error = ""
                    break
                last_error = (pulled.stderr or pulled.stdout or "").strip()
                if not _transient_pull_failure(last_error) or attempt == 3:
                    break
                time.sleep(attempt * 2)

            if last_error:
                if is_build_service:
                    # build 型服务拉不到镜像是正常的（如 VAmPI 的 vampi_docker 未发布）——
                    # 交给 compose 本地构建，不算失败。但**必须带上真实拉取错误**：像
                    # DVWA 的 ghcr 官方镜像其实可拉、只是慢/瞬时失败，若无脑回退本地构建会挂在
                    # apt-get，并把根因（拉取超时/网络）伪装成 dependency_install_failed。
                    needs_build = True
                    self.metadata["diagnostics"].append(
                        f"compose image {index}/{len(images)} 无法拉取，改本地构建: {image} "
                        f"（拉取失败原因: {_diagnostic_tail(last_error, 200)}）"
                    )
                else:
                    raise RuntimeError(
                        f"拉取 Compose 镜像失败 ({index}/{len(images)} {image})："
                        + _diagnostic_tail(last_error)
                    )
        self._compose_needs_build = needs_build

    def _compose_locally_built_images(self, project: str) -> set[str]:
        """Return explicit image tags produced by services that declare ``build``.

        Failure to parse is deliberately non-fatal: Compose remains the source of
        truth and the existing prefetch path still handles genuinely pullable images.
        """
        try:
            import yaml
            compose_text = Path(self._compose_file).read_text(encoding="utf-8", errors="ignore")
            data = yaml.safe_load(compose_text) or {}
            services = data.get("services") or {}
            images: set[str] = set()
            for name, service in services.items():
                if not isinstance(service, dict) or service.get("build") is None:
                    continue
                explicit = str(service.get("image") or "").strip()
                if explicit:
                    images.add(explicit)
                else:
                    # Compose names an unnamed build image <project>-<service>.
                    # ``config --images`` returns that generated tag, which is still
                    # a local build output and must never be sent to docker pull.
                    images.add(f"{project}-{str(name).lower()}")
            # Keep a conservative text fallback as a second source. Test and
            # plugin environments can replace YAML loaders, while Compose's
            # common top-level service form remains unambiguous here.
            for match in re.finditer(
                r"(?ms)^  ([A-Za-z0-9_.-]+):\s*\n((?:    .*?(?:\n|$))*)",
                compose_text,
            ):
                name, body = match.group(1), match.group(2)
                if not re.search(r"(?m)^    build\s*:", body):
                    continue
                image_match = re.search(r"(?m)^    image\s*:\s*['\"]?([^\s'\"]+)", body)
                images.add(image_match.group(1) if image_match else f"{project}-{name.lower()}")
            return images
        except Exception as exc:  # noqa: BLE001
            self.metadata["diagnostics"].append(
                f"compose local-build image detection skipped: {type(exc).__name__}"
            )
            self.metadata["compose_ps"] = self._compose_ps()
            return set()

    def _compose_published_port(self, project: str, port_hint) -> int | None:
        """解析 `docker compose ps --format json`，返回一个对外发布的 TCP 端口。

        兼容两种输出：整体 JSON 数组，或每行一个 JSON 对象（不同 compose 版本）。
        优先匹配 port_hint（容器内目标端口），否则取第一个已发布端口。
        """
        try:
            cmd = ["docker", "compose", "-p", project]
            if self._compose_file:
                cmd += ["-f", self._compose_file]
            cmd += ["ps", "--format", "json"]
            proc = subprocess.run(
                cmd,
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
        except Exception:  # noqa: BLE001
            return None
        raw = (proc.stdout or "").strip()
        if not raw:
            return None
        services: list = []
        try:
            parsed = _json.loads(raw)
            services = parsed if isinstance(parsed, list) else [parsed]
        except Exception:  # noqa: BLE001
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    services.append(_json.loads(line))
                except Exception:  # noqa: BLE001
                    continue
        published: list[dict] = []
        for svc in services:
            for pub in (svc.get("Publishers") or []):
                pp = pub.get("PublishedPort")
                if pp and str(pub.get("Protocol", "tcp")) == "tcp":
                    published.append({
                        "service": str(svc.get("Service") or svc.get("Name") or "").lower(),
                        "target": int(pub.get("TargetPort") or 0),
                        "host": int(pp),
                    })
        if not published:
            return None
        if port_hint:
            for item in published:
                if item["target"] == int(port_hint) or item["host"] == int(port_hint):
                    self._compose_selected_target_port = item["target"]
                    return item["host"]

        # 多服务 Compose 不能取“第一个已发布端口”：它可能是 Postgres、Mailhog 或 MCP。
        # 优先选择名称像 Web/API/Gateway 的服务，再参考常见 HTTP 端口。
        web_words = ("web", "gateway", "frontend", "api", "nginx", "proxy")
        common_http = {80, 443, 3000, 5000, 8000, 8080, 8081, 8888}
        published.sort(key=lambda item: (
            0 if any(word in item["service"] for word in web_words) else 1,
            # 同一个 Web 服务同时映射 80/443 时，优先未加密 HTTP；否则不能把
            # httpx 的 http:// 请求误送到 TLS 端口（crAPI 的 8443 就是该反例）。
            0 if item["target"] == 80 else 1 if item["target"] in common_http else 2,
            item["host"],
        ))
        self.metadata["diagnostics"].append(
            "compose published ports: "
            + ", ".join(f"{item['service']}:{item['host']}->{item['target']}" for item in published[:12])
        )
        self._compose_selected_target_port = published[0]["target"]
        return published[0]["host"]

    def _prepare_isolated_compose(self, compose_file: str, port_hint) -> str:
        """生成一次性 Compose 配置，避免不可信项目配置占用全局 Docker 名称。

        原始 Compose 只读不修改。覆写版移除 ``container_name``、顶层网络的
        显式 ``name`` 与所有固定宿主端口；然后仅为最可能的 Web 服务创建一个
        随机宿主端口映射。这样既能保持服务间依赖，也不会碰用户已运行的靶场。
        """
        try:
            import yaml
            source = self.code_root / compose_file
            data = yaml.safe_load(source.read_text(encoding="utf-8", errors="ignore")) or {}
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"无法生成隔离 Compose 配置: {exc}") from exc

        services = data.get("services") or {}
        if not isinstance(services, dict) or not services:
            raise RuntimeError("Compose 未定义 services，无法生成隔离配置")

        web_service, target_port = _select_compose_web_service(services, port_hint)
        if not web_service or not target_port:
            raise RuntimeError("Compose 中无法识别可发布的 Web 服务端口")

        # A target Compose may intentionally ship secure and vulnerable variants
        # (VAmPI), or unrelated developer tools. Start only the selected HTTP service
        # and its declared dependency closure; this preserves required DB/queue
        # services while avoiding unrelated containers, image builds and state bleed.
        selected_services = _compose_dependency_closure(services, web_service)
        # 通用规则（不针对任何具体项目）：多服务 Web 部署常把浏览器/API 流量经一个单独
        # 命名的网关/反向代理转发，而该网关未必写进 depends_on。当所选目标或任一服务看起来
        # 是 web/前端/网关/鉴权/身份类时，一并保留同族服务，避免漏起真正对外的入口。
        _WEB_FAMILY = ("gateway", "proxy", "nginx", "web", "frontend", "api", "identity", "auth")
        target_is_web = any(tok in web_service.lower() for tok in _WEB_FAMILY)
        has_gateway = any(
            any(tok in str(name).lower() for tok in ("gateway", "proxy", "nginx"))
            for name in services
        )
        if target_is_web or has_gateway:
            selected_services.update(
                name for name in services
                if any(tok in str(name).lower() for tok in _WEB_FAMILY)
            )
        if len(selected_services) < len(services):
            skipped = sorted(set(services) - selected_services)
            data["services"] = {name: services[name] for name in selected_services}
            services = data["services"]
            self.metadata["diagnostics"].append(
                "isolated compose omitted unrelated services: " + ", ".join(skipped)
            )

        self._precheck_compose_environment_files(services, source.parent)

        removed_names = 0
        removed_ports = 0
        for service in services.values():
            if not isinstance(service, dict):
                continue
            if service.pop("container_name", None) is not None:
                removed_names += 1
            if service.pop("ports", None) is not None:
                removed_ports += 1

        networks = data.get("networks") or {}
        if isinstance(networks, dict):
            for network in networks.values():
                if isinstance(network, dict) and network.pop("name", None) is not None:
                    self.metadata["diagnostics"].append("removed fixed Compose network name")

        services[web_service]["ports"] = [f"127.0.0.1::{target_port}"]
        self._compose_web_service = web_service
        suffix = re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:12] or "scan"
        generated_name = f"docker-compose.auditagentx.{suffix}.yml"
        # Keep the isolated file next to the source Compose file. Compose resolves
        # relative build contexts, env_file, configs and bind mounts relative to this
        # directory; relocating it to repository root breaks nested deployments.
        target = (self.code_root / compose_file).parent / generated_name
        target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        self._generated_compose_file_name = str(target.relative_to(self.code_root))
        self.metadata["diagnostics"].append(
            f"isolated compose generated: removed container_name={removed_names}, "
            f"fixed ports={removed_ports}, exposed {web_service}:*->{target_port}"
        )
        return str(target.relative_to(self.code_root))

    def _precheck_compose_environment_files(self, services: dict, compose_dir: Path) -> None:
        """Validate selected services' env_file entries and isolate safe sample copies."""
        generated: list[dict] = []
        missing: list[str] = []
        optional_missing: list[str] = []

        for service in services.values():
            if not isinstance(service, dict) or "env_file" not in service:
                continue
            original = service.get("env_file")
            entries = original if isinstance(original, list) else [original]
            rewritten = []
            for entry in entries:
                long_syntax = isinstance(entry, dict)
                raw_path = entry.get("path") if long_syntax else entry
                required = entry.get("required", True) is not False if long_syntax else True
                relative_name, source_path = self._safe_compose_env_path(raw_path, compose_dir)

                replacement = None
                if source_path.is_file():
                    replacement = str(raw_path)
                elif not required:
                    optional_missing.append(relative_name)
                    replacement = str(raw_path)
                else:
                    sample = self._find_compose_env_sample(source_path)
                    if sample is None:
                        missing.append(relative_name)
                        replacement = str(raw_path)
                    else:
                        if self._compose_environment_temp_dir is None:
                            safe_scan_id = re.sub(r"[^A-Za-z0-9_.-]", "", self.scan_id)[:16] or "scan"
                            self._compose_environment_temp_dir = Path(tempfile.mkdtemp(
                                prefix=f"auditagentx-{safe_scan_id}-env-"
                            ))
                        artifact = self._compose_environment_temp_dir / f"{len(generated)}-{source_path.name}"
                        shutil.copyfile(sample, artifact)
                        replacement = str(artifact.resolve())
                        generated.append({
                            "sample_source": sample.relative_to(self.code_root).as_posix(),
                            "temporary_artifact_generated": True,
                        })

                if long_syntax:
                    updated = dict(entry)
                    updated["path"] = replacement
                    rewritten.append(updated)
                else:
                    rewritten.append(replacement)

            service["env_file"] = rewritten if isinstance(original, list) else rewritten[0]

        if missing:
            missing = sorted(set(missing))
            precheck = {
                "status": "failed",
                "failure_code": "missing_env_file",
                "missing_env_files": missing,
            }
            self.metadata["environment_precheck"] = precheck
            raise _ComposeEnvironmentError(
                "missing_env_file", missing,
                "Compose 必需环境文件缺失，且同目录未找到安全样例文件：" + ", ".join(missing),
            )

        self.metadata["environment_precheck"] = {
            "status": "generated_from_sample" if generated else "passed",
            "generated_files": generated,
            "optional_missing_env_files": sorted(set(optional_missing)),
        }

    def _safe_compose_env_path(self, value, compose_dir: Path) -> tuple[str, Path]:
        raw = str(value or "").strip()
        normalized = raw.replace("\\", "/")
        parts = normalized.split("/")
        if (not normalized or normalized.startswith(("/", "~"))
                or re.match(r"^[A-Za-z]:/", normalized)
                or ".." in parts or "$" in normalized):
            self.metadata["environment_precheck"] = {
                "status": "failed", "failure_code": "unsafe_env_file_path"
            }
            raise _ComposeEnvironmentError(
                "unsafe_env_file_path", [],
                "Compose env_file 路径不安全；拒绝绝对路径、路径穿越或动态路径",
            )
        candidate = (compose_dir / Path(*parts)).resolve()
        try:
            relative = candidate.relative_to(self.code_root).as_posix()
        except ValueError as exc:
            self.metadata["environment_precheck"] = {
                "status": "failed", "failure_code": "unsafe_env_file_path"
            }
            raise _ComposeEnvironmentError(
                "unsafe_env_file_path", [], "Compose env_file 路径位于 code_root 外，已拒绝"
            ) from exc
        return relative, candidate

    def _find_compose_env_sample(self, missing: Path) -> Path | None:
        names = [missing.name + ".sample", missing.name + ".example"]
        if missing.name == ".env":
            names.extend(["env.sample", "env.example"])
        for name in dict.fromkeys(names):
            candidate = missing.parent / name
            if candidate.is_file():
                resolved = candidate.resolve()
                try:
                    resolved.relative_to(self.code_root)
                except ValueError:
                    continue
                return resolved
        return None

    def _compose_logs(self) -> str:
        if not (self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f",
                 self._compose_file, "logs", "--no-color", "--tail", "50"],
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
            return (proc.stdout or proc.stderr or "")[-1500:]
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _wait_compose_healthy(base_url: str, timeout: int,
                              crash_probe=None, cancel_probe=None) -> tuple[bool, list[dict]]:
        """轮询直到就绪或超时；就绪判据复用 _wait_healthy（2xx–4xx 即服务已在处理 HTTP，
        且可被测试注入）。每隔几秒调 crash_probe 检查目标容器是否已崩溃退出，崩溃则立即
        停止等待（不干等满超时），由调用方带真实日志报 sandbox_start_failed。

        循环同时受**墙钟 deadline** 与**迭代次数上限**双重约束：前者保证生产环境不超时，
        后者保证测试把 time.sleep patch 成 no-op 时也能有限次退出，不忙等满超时。"""
        import httpx
        base = base_url.rstrip("/")
        attempts: list[dict] = []
        extra_paths = ("/health", "/actuator/health", "/identity/health_check")
        deadline = time.time() + timeout
        next_crash_check = 0.0
        for _ in range(int(timeout) + 5):
            if cancel_probe is not None and cancel_probe():
                raise SandboxCommandCancelled(
                    "scan cancellation requested", phase="health_check"
                )
            if time.time() >= deadline:
                break
            now = time.time()
            if crash_probe is not None and now >= next_crash_check:
                if crash_probe():
                    return False, attempts or [{"note": "target container exited during startup"}]
                next_crash_check = now + 4.0
            # 主路径：复用 _wait_healthy（根路径，短超时，可被测试注入其返回值）
            if _wait_healthy(base + "/", 3):
                return True, [{"url": base + "/", "status": "healthy"}]
            # 备用健康路径：根路径不可健康检查的项目（真实 HTTP，2xx–4xx 即就绪）
            round_attempts = []
            for path in extra_paths:
                url = base + path
                try:
                    resp = httpx.get(url, timeout=3, trust_env=False, follow_redirects=False)
                    round_attempts.append({"url": url, "status": resp.status_code})
                    if 200 <= resp.status_code < 500:
                        return True, round_attempts
                except httpx.HTTPError as exc:
                    round_attempts.append({"url": url, "error": type(exc).__name__})
            attempts = round_attempts or attempts
            time.sleep(1)
        return False, attempts

    def _compose_target_crash_reason(self) -> "str | None":
        """目标 Web 服务容器是否已异常退出。是则返回含真实启动错误的原因，否则 None。

        用 `compose ps --format json` 读各服务状态：目标服务（或任一构建型服务）处于
        exited 且退出码非 0，说明应用启动即崩溃（如上游依赖未锁版本导致 import 失败）——
        应立刻带真实 traceback 报 sandbox_start_failed，而不是干等满健康超时。
        """
        if not (self._compose_project and self._compose_file):
            return None
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f", self._compose_file,
                 "ps", "--all", "--format", "json"],
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20,
                env=self._compose_subprocess_env())
        except Exception:  # noqa: BLE001
            return None
        out = (proc.stdout or "").strip()
        if not out:
            return None
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(_json.loads(line))
            except Exception:  # noqa: BLE001  某些版本输出单个 JSON 数组
                try:
                    rows.extend(_json.loads(line))
                except Exception:  # noqa: BLE001
                    pass
        target = (self._compose_web_service or "").lower()
        for row in rows:
            if not isinstance(row, dict):
                continue
            svc = str(row.get("Service") or row.get("Name") or "").lower()
            state = str(row.get("State") or "").lower()
            exit_code = row.get("ExitCode")
            is_target = (target and target in svc) or True  # 任一服务崩溃都值得暴露
            if is_target and state == "exited" and exit_code not in (0, None):
                svc_logs = self._service_logs(row.get("Service") or row.get("Name") or "")
                tail = _diagnostic_tail(svc_logs) or (svc_logs[-400:] if svc_logs else "")
                return (f"目标容器 {svc or '?'} 启动即退出(exit={exit_code})——应用自身崩溃"
                        f"（常见：上游依赖未锁版本/缺环境变量/迁移失败）。真实错误：{tail}")
        return None

    def _service_logs(self, service: str) -> str:
        if not (service and self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f", self._compose_file,
                 "logs", "--no-color", "--tail", "40", str(service)],
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20,
                env=self._compose_subprocess_env())
            return (proc.stdout or proc.stderr or "")[-2000:]
        except Exception:  # noqa: BLE001
            return ""

    def _compose_ps(self) -> str:
        if not (self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f", self._compose_file,
                 "ps", "--all"], cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
            return (proc.stdout or proc.stderr or "")[-1200:]
        except Exception:  # noqa: BLE001
            return ""

    def _compose_inventory(self) -> list[dict]:
        """Capture stable container identity before teardown for audit evidence."""
        if not (self._compose_project and self._compose_file):
            return []
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f",
                 self._compose_file, "ps", "--all", "--format", "json"],
                cwd=str(self.code_root), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
                env=self._compose_subprocess_env())
            raw = (proc.stdout or "").strip()
            if not raw:
                return []
            try:
                parsed = _json.loads(raw)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except Exception:  # noqa: BLE001
                rows = []
                for line in raw.splitlines():
                    try:
                        rows.append(_json.loads(line))
                    except Exception:  # noqa: BLE001
                        continue
            return [{
                "id": row.get("ID") or row.get("Id"),
                "name": row.get("Name"),
                "service": row.get("Service"),
                "image": row.get("Image"),
                "state": row.get("State"),
                "exit_code": row.get("ExitCode"),
            } for row in rows if isinstance(row, dict)]
        except Exception as exc:  # noqa: BLE001
            self.metadata["diagnostics"].append(
                f"compose inventory capture failed: {type(exc).__name__}"
            )
            return []

    def _cleanup(self) -> None:
        with self._cleanup_lock:
            if self._cleanup_done:
                return
            self._cleanup_done = True
            self.metadata["cleanup_attempted"] = True
            cleanup_ok = True
            if self._container is not None:
                try:
                    self._container.remove(force=True)
                except Exception as e:  # noqa: BLE001
                    cleanup_ok = False
                    logger.warning("清理容器失败: %s", e)
            if self._compose_project and self._compose_file:
                try:
                    proc = subprocess.run(
                        ["docker", "compose", "-p", self._compose_project, "-f",
                         self._compose_file, "down", "-v"],
                        cwd=str(self.code_root), capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=30,
                        env=self._compose_subprocess_env())
                    if proc.returncode != 0:
                        cleanup_ok = False
                        self.metadata["diagnostics"].append(
                            "compose cleanup failed: " + _diagnostic_tail(proc.stderr or proc.stdout, 240)
                        )
                except Exception as e:  # noqa: BLE001
                    cleanup_ok = False
                    logger.warning("清理 compose 项目失败: %s", e)
            tmp = self.code_root / self._generated_dockerfile_name if self._generated_dockerfile_name else None
            if tmp and tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
            generated_compose = (self.code_root / self._generated_compose_file_name
                                 if self._generated_compose_file_name else None)
            if generated_compose and generated_compose.exists():
                try:
                    generated_compose.unlink()
                except OSError:
                    pass
            if self._compose_environment_temp_dir is not None:
                try:
                    shutil.rmtree(self._compose_environment_temp_dir)
                except OSError:
                    cleanup_ok = False
                self._compose_environment_temp_dir = None
            self.metadata["cleanup_succeeded"] = cleanup_ok

    def _register_cancel_cleanup(self) -> None:
        if self._cleanup_token is None and not self._cleanup_done:
            self._cleanup_token = register_cleanup_callback(self.scan_id, self._cleanup)

    def _next_generated_dockerfile_name(self) -> str:
        stem = "Dockerfile.auditagentx"
        suffix = re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:12] or "scan"
        candidate = f"{stem}.{suffix}"
        index = 1
        while (self.code_root / candidate).exists():
            index += 1
            candidate = f"{stem}.{suffix}.{index}"
        return candidate


class _DependencyError(Exception):
    """依赖安装失败的内部异常。"""


class _ComposeEnvironmentError(Exception):
    """Structured Compose env_file preflight failure raised before Docker is touched."""

    def __init__(self, failure_code: str, missing_env_files: list[str], reason: str) -> None:
        super().__init__(reason)
        self.failure_code = failure_code
        self.missing_env_files = missing_env_files


def _select_compose_web_service(services: dict, port_hint) -> tuple[str | None, int | None]:
    """从原始 Compose 中选择一个适合动态 HTTP 验证的服务与容器端口。

    不信任原有的宿主发布端口：它可能已被另一个靶场占用。仅读取容器目标端口，
    并偏好名字像 Web/API 的服务和 80/8080 等 HTTP 端口。
    """
    web_words = ("web", "gateway", "frontend", "api", "nginx", "proxy")
    common_http = (80, 8080, 8000, 8001, 5000, 3000)
    candidates: list[tuple[tuple, str, int]] = []
    fallback_candidates: list[tuple[tuple, str, int]] = []
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        ports = service.get("ports") or []
        targets: list[int] = []
        for port in ports:
            target = _compose_port_target(port)
            if target:
                targets.append(target)
        # 无 ports 但明确 expose 的项目也可作为单一 HTTP 服务。
        for port in service.get("expose") or []:
            try:
                targets.append(int(str(port).split("/")[0]))
            except (TypeError, ValueError):
                pass
        for target in dict.fromkeys(targets):
            score = (
                0 if any(word in str(name).lower() for word in web_words) else 1,
                _vulnerable_service_priority(name, service),
                0 if port_hint and target == int(port_hint) else 1,
                0 if target in common_http else 1,
                common_http.index(target) if target in common_http else target,
                str(name),
            )
            candidates.append((score, str(name), target))
        # 有些 Compose 只依赖 Dockerfile EXPOSE 或服务默认端口，不写 ports。
        # 隔离覆写正是要补一个随机宿主端口，因此对明显的 Web 服务可以采用启动
        # 计划的端口；没有计划时用 HTTP 的保守默认 80。
        if not targets and any(word in str(name).lower() for word in web_words):
            target = int(port_hint) if port_hint else 80
            fallback_candidates.append(((0, 0, 0 if target in common_http else 1,
                                         common_http.index(target) if target in common_http else target,
                                         str(name)), str(name), target))
    if not candidates:
        candidates = fallback_candidates
    if not candidates:
        return None, None
    candidates.sort(key=lambda item: item[0])
    _, name, target = candidates[0]
    return name, target


def _vulnerable_service_priority(name: str, service: dict) -> int:
    """Prefer an explicitly vulnerable target when an educational Compose ships both modes.

    VAmPI intentionally publishes secure and vulnerable instances on the same container
    port. Choosing the lexical first service silently turns an authorized vulnerability
    verification campaign into a scan of the secure variant.
    """
    if "vulnerable" in str(name).lower():
        return 0
    values = service.get("environment") or []
    if isinstance(values, dict):
        values = [f"{key}={value}" for key, value in values.items()]
    return 0 if any(str(item).replace(" ", "").lower() in {"vulnerable=1", "vuln=1"}
                    for item in values) else 1


def _compose_dependency_closure(services: dict, root: str) -> set[str]:
    """Return ``root`` plus declared depends_on services, without following arbitrary links."""
    selected: set[str] = set()
    pending = [root]
    while pending:
        name = pending.pop()
        if name in selected or name not in services:
            continue
        selected.add(name)
        definition = services.get(name) or {}
        dependencies = definition.get("depends_on") if isinstance(definition, dict) else []
        if isinstance(dependencies, dict):
            pending.extend(str(item) for item in dependencies)
        elif isinstance(dependencies, list):
            pending.extend(str(item) for item in dependencies)
    return selected


def _compose_port_target(value) -> int | None:
    """解析 Compose 短/长端口语法的容器目标端口。"""
    if isinstance(value, dict):
        try:
            return int(value.get("target"))
        except (TypeError, ValueError):
            return None
    raw = str(value or "").strip()
    if not raw:
        return None
    raw = raw.rsplit("/", 1)[0]
    try:
        return int(raw.rsplit(":", 1)[-1])
    except ValueError:
        return None


def _scheme_for_port(target_port: int | None, launch_plan: dict | None = None) -> str:
    configured = str((launch_plan or {}).get("scheme") or "").lower()
    if configured in {"http", "https"}:
        return configured
    return "https" if int(target_port or 0) in {443, 8443, 9443} else "http"


@contextmanager
def docker_project_sandbox(code_root: Path, launch_plan: dict | None = None,
                           *, env: dict | None = None, scan_id: str | None = None,
                           trust_project_container_config: bool = False):
    """便捷上下文管理器，yield DockerProjectRunner 实例。"""
    runner = DockerProjectRunner(
        code_root, launch_plan, env=env, scan_id=scan_id,
        trust_project_container_config=trust_project_container_config,
    )
    with runner:
        yield runner


_SAFE_DYNAMIC_BIND_DEFAULT_RE = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(:-|-)([^${}]+)\}$"
)


def _compose_short_volume_source(value) -> str:
    """Extract a short-syntax volume source without splitting ``:-`` in ${...}."""
    raw = str(value or "").strip()
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        return raw  # absolute Windows paths are rejected by the normal policy
    depth = 0
    for index, char in enumerate(raw):
        if char == "{" and index and raw[index - 1] == "$":
            depth += 1
        elif char == "}" and depth:
            depth -= 1
        elif char == ":" and depth == 0:
            return raw[:index]
    return raw


def _validate_compose_policy(path: Path, *, code_root: Path | None = None,
                             env: dict | None = None) -> dict:
    """Reject Compose capabilities and host paths that escape the project root."""
    root = Path(code_root or path.parent).resolve()
    compose_path = Path(path).resolve()
    try:
        compose_path.relative_to(root)
    except ValueError:
        return {
            "allowed": False,
            "reason": "compose file is outside code_root",
            "checks": ["compose file is outside code_root"],
        }
    try:
        import yaml
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception as exc:  # noqa: BLE001
        return {"allowed": False, "reason": f"无法安全解析 Compose: {exc}", "checks": []}

    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        return {"allowed": False, "reason": "Compose 未定义 services", "checks": []}

    blocked: list[str] = []
    compose_dir = compose_path.parent
    explicit_env = env or {}

    def validate_host_path(value, label: str, *, base: Path = compose_dir,
                           named_volume_allowed: bool = False) -> Path | None:
        raw = str(value or "").strip()
        if not raw:
            blocked.append(f"{label}: empty or unresolved host path")
            return None
        normalized = raw.replace("\\", "/")
        if named_volume_allowed and "$" not in raw and _is_compose_named_volume(raw):
            return None
        if "$" in raw:
            match = _SAFE_DYNAMIC_BIND_DEFAULT_RE.fullmatch(raw)
            if not match:
                blocked.append(f"{label}: dynamic host path is not allowed")
                return None
            name, operator, default = match.groups()
            # Exact full-match plus this guard excludes mixed text, multiple
            # variables, :? forms and nested substitutions without reading .env.
            if not default or "${" in default:
                blocked.append(f"{label}: dynamic host path default is unsafe")
                return None
            provided = explicit_env.get(name)
            effective = default if provided is None or (operator == ":-" and provided == "") else str(provided)
            raw = effective
            normalized = raw.replace("\\", "/")
        if ("{{" in raw or "}}" in raw or raw.startswith("~") or "$" in raw):
            blocked.append(f"{label}: dynamic host path is not allowed")
            return None
        if (normalized.startswith("/") or raw.startswith("\\")
                or re.match(r"^[A-Za-z]:", raw)):
            blocked.append(f"{label}: absolute host path is not allowed")
            return None
        if ".." in normalized.split("/") or ":" in normalized:
            blocked.append(f"{label}: host path escapes code_root")
            return None
        candidate = (base / Path(*normalized.split("/"))).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            blocked.append(f"{label}: host path escapes code_root")
            return None
        return candidate

    dangerous_keys = {"privileged", "devices", "cap_add", "pid", "ipc", "uts", "userns_mode"}
    for name, service in services.items():
        if not isinstance(service, dict):
            blocked.append(f"service {name}: invalid definition")
            continue
        for key in dangerous_keys:
            value = service.get(key)
            if value not in (None, False, [], ""):
                blocked.append(f"service {name}: forbidden {key}")
        if str(service.get("network_mode") or "").lower() == "host":
            blocked.append(f"service {name}: forbidden network_mode=host")
        for volume in service.get("volumes") or []:
            if isinstance(volume, dict):
                source = volume.get("source") or ""
                volume_type = str(volume.get("type") or "").lower()
                named_allowed = volume_type == "volume" or (
                    not volume_type and _is_compose_named_volume(str(source))
                )
            else:
                raw = str(volume or "")
                source = _compose_short_volume_source(raw)
                named_allowed = _is_compose_named_volume(source)
            if "docker.sock" in str(source).lower():
                blocked.append(f"service {name} volume: docker.sock is forbidden")
            else:
                validate_host_path(
                    source, f"service {name} host volume", named_volume_allowed=named_allowed,
                )

        build = service.get("build")
        if build is not None:
            if isinstance(build, str):
                context_value = build
                dockerfile_value = None
            elif isinstance(build, dict):
                context_value = build.get("context", ".")
                dockerfile_value = build.get("dockerfile")
            else:
                blocked.append(f"service {name} build: invalid definition")
                context_value = None
                dockerfile_value = None
            context_path = None
            if context_value is not None:
                context_path = validate_host_path(context_value, f"service {name} build.context")
            if dockerfile_value is not None:
                validate_host_path(
                    dockerfile_value, f"service {name} build.dockerfile",
                    base=context_path or compose_dir,
                )

        env_files = service.get("env_file")
        if env_files is not None:
            for entry in env_files if isinstance(env_files, list) else [env_files]:
                value = entry.get("path") if isinstance(entry, dict) else entry
                validate_host_path(value, f"service {name} env_file")

    for section in ("configs", "secrets"):
        definitions = data.get(section) or {}
        if not isinstance(definitions, dict):
            blocked.append(f"{section}: invalid definition")
            continue
        for name, definition in definitions.items():
            if isinstance(definition, dict) and "file" in definition:
                validate_host_path(definition.get("file"), f"{section}.{name}.file")
    return {
        "allowed": not blocked,
        "reason": "; ".join(blocked) if blocked else "",
        "checks": blocked or ["compose policy passed"],
    }


def _is_compose_named_volume(value: str) -> bool:
    raw = str(value or "").strip()
    return bool(raw and "/" not in raw and "\\" not in raw and not raw.startswith("."))


def _validate_generated_launch_plan(plan: dict) -> dict:
    """只允许已知的依赖安装器和 Web 服务启动命令进入 Docker build/CMD。"""
    from backend.dynamic.launch_detector import README_INSTALL_PATTERNS, README_RUN_PATTERNS

    install = str(plan.get("install_command") or "").strip()
    run = str(plan.get("run_command") or plan.get("command") or "").strip()
    workdir = _safe_workdir(plan.get("working_dir"))
    checks: list[str] = []
    normalized_run = run.replace("{port}", str(plan.get("port") or 8000))
    if install and not any(pattern.fullmatch(install) for pattern in README_INSTALL_PATTERNS):
        checks.append(f"unapproved install_command: {install[:160]}")
    if normalized_run and not any(pattern.fullmatch(normalized_run) for pattern in README_RUN_PATTERNS):
        checks.append(f"unapproved run_command: {run[:160]}")
    raw_workdir = str(plan.get("working_dir") or ".")
    if ".." in raw_workdir.replace("\\", "/").split("/"):
        checks.append(f"unsafe working_dir: {raw_workdir[:160]}")
    elif raw_workdir not in {"", "."} and not workdir:
        checks.append(f"invalid working_dir: {raw_workdir[:160]}")
    return {
        "allowed": not checks,
        "reason": "; ".join(checks),
        "checks": checks or ["generated launch command policy passed"],
    }

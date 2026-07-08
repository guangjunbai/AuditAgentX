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
import re
import subprocess
from contextlib import contextmanager
from pathlib import Path

from backend.verifier.app_runner import _free_port, _wait_healthy, get_docker_client

logger = logging.getLogger(__name__)

# 沙箱状态
STARTED = "started"
SANDBOX_START_FAILED = "sandbox_start_failed"
HEALTH_CHECK_FAILED = "health_check_failed"
DEPENDENCY_INSTALL_FAILED = "dependency_install_failed"
LAUNCH_NOT_DETECTED = "launch_not_detected"   # 预检：无法自动识别启动方式，未尝试构建


def _first_line(text: str, limit: int = 200) -> str:
    """取错误信息的首个有效行，便于生成可读 reason。"""
    for line in str(text).splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return str(text)[:limit]


def build_dockerfile(launch_plan: dict, port: int) -> str:
    """SandboxBuilder：按 launch_plan 生成最小 Dockerfile（无项目 Dockerfile 时）。"""
    framework = (launch_plan.get("framework") or "").lower()
    install = launch_plan.get("install_command")
    run = launch_plan.get("run_command") or launch_plan.get("command") or ""
    run = run.replace("{port}", str(port))

    if "node" in framework or "express" in framework:
        install = install or "npm install"
        return (
            "FROM node:20-slim\n"
            "WORKDIR /app\n"
            "COPY package*.json ./\n"
            f"RUN {install}\n"
            "COPY . .\n"
            f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "php" in framework:
        return (
            "FROM php:8.2-cli\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
            + (f"RUN {install}\n" if install else "")
            + f"EXPOSE {port}\n"
            f"CMD {_cmd_json(run)}\n"
        )
    if "spring" in framework or "java" in framework:
        return (
            "FROM eclipse-temurin:17-jdk\n"
            "WORKDIR /app\n"
            "COPY . /app\n"
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
        f"RUN {install} || pip install --no-cache-dir flask fastapi uvicorn\n"
        f"EXPOSE {port}\n"
        f"CMD {_cmd_json(run)}\n"
    )


def _cmd_json(run_command: str) -> str:
    """把 run_command 转成 Dockerfile CMD 的 JSON 数组形式。"""
    parts = run_command.split()
    return "[" + ", ".join(f'"{p}"' for p in parts) + "]"


class DockerProjectRunner:
    """上下文管理器：进入返回 self（含 base_url / metadata），退出清理容器。"""

    def __init__(self, code_root: Path, launch_plan: dict | None = None,
                 *, env: dict | None = None, scan_id: str | None = None,
                 build_timeout: int = 600, health_timeout: int = 40) -> None:
        self.code_root = Path(code_root)
        self.launch_plan = launch_plan or {}
        self.env = env or {}
        self.scan_id = scan_id or "adhoc"
        self.build_timeout = build_timeout
        self.health_timeout = health_timeout

        self.base_url: str | None = None
        self.metadata: dict = {
            "mode": "docker_project",
            "image": f"auditagentx-{re.sub(r'[^a-z0-9]', '', self.scan_id.lower())[:20] or 'scan'}",
            "container_id": None,
            "base_url": None,
            "port": self.launch_plan.get("port") or 8000,
            "health_path": self.launch_plan.get("health_path") or "/",
            "health_check": "failed",
            "launch_command": (self.launch_plan.get("run_command")
                               or self.launch_plan.get("command")),
            "logs_excerpt": "",
            "status": SANDBOX_START_FAILED,
            "reason": "",
        }
        self._client = None
        self._container = None
        # docker compose 编排（多服务项目）时记录，供清理使用
        self._compose_project: str | None = None
        self._compose_file: str | None = None

    def __enter__(self) -> "DockerProjectRunner":
        try:
            self._start()
        except _DependencyError as e:
            self.metadata["status"] = DEPENDENCY_INSTALL_FAILED
            self.metadata["logs_excerpt"] = str(e)[:800]
            self.metadata["reason"] = "镜像构建时依赖安装失败：" + _first_line(str(e))
            logger.warning("沙箱依赖安装失败: %s", e)
        except Exception as e:  # noqa: BLE001
            self.metadata["status"] = SANDBOX_START_FAILED
            self.metadata["logs_excerpt"] = str(e)[:800]
            self.metadata["reason"] = "沙箱构建/启动失败：" + _first_line(str(e))
            logger.warning("沙箱启动失败: %s", e)
        return self

    def __exit__(self, *exc) -> None:
        self._cleanup()

    # ---------- 内部 ----------
    def _start(self) -> None:
        internal_port = int(self.metadata["port"])
        host_port = _free_port()
        base_url = f"http://127.0.0.1:{host_port}"
        image_tag = self.metadata["image"]

        has_dockerfile = (self.code_root / "Dockerfile").exists()
        run_command = self.launch_plan.get("run_command") or self.launch_plan.get("command")
        compose = self.launch_plan.get("compose")

        # 0) 多服务项目：若检测到 docker-compose，优先按项目既定方式编排启动
        #    （单容器无法提供 DB/Redis 等依赖服务，这是真实开源项目动态验证失败的高频原因）。
        if compose and (self.code_root / compose).exists():
            self._run_compose(compose, self.launch_plan.get("port"))
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
            )
            logger.info("沙箱预检未通过（不构建）：%s", self.metadata["reason"])
            return

        # 未安装 docker SDK / 引擎不可用时抛异常 -> sandbox_start_failed
        self._client = get_docker_client()

        # 1) 构建镜像：优先项目 Dockerfile，否则生成临时 Dockerfile
        if not has_dockerfile:
            dockerfile = build_dockerfile(self.launch_plan, internal_port)
            (self.code_root / "Dockerfile.auditagentx").write_text(dockerfile, encoding="utf-8")
            dockerfile_name = "Dockerfile.auditagentx"
        else:
            dockerfile_name = "Dockerfile"

        try:
            self._client.images.build(
                path=str(self.code_root), dockerfile=dockerfile_name,
                tag=image_tag, rm=True, forcerm=True,
            )
        except Exception as e:  # noqa: BLE001
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
        self._container = self._client.containers.run(
            image=image_tag, detach=True, remove=False,
            ports={f"{internal_port}/tcp": host_port},
            environment=run_env, mem_limit="512m",
        )
        self.metadata["container_id"] = self._container.id[:12]

        # 3) 健康检查
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if _wait_healthy(health_url, self.health_timeout):
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

    def _logs(self) -> str:
        if not self._container:
            return ""
        try:
            return self._container.logs().decode("utf-8", errors="ignore")[-1500:]
        except Exception:  # noqa: BLE001
            return ""

    # ---------- docker compose 多服务编排 ----------
    def _run_compose(self, compose_file: str, port_hint) -> None:
        """用 `docker compose up` 启动多服务项目，探测对外发布端口并健康检查。

        失败时如实返回状态与 reason，绝不造假复现结果。退出时 `docker compose down` 清理。
        """
        project = "aax" + (re.sub(r"[^a-z0-9]", "", self.scan_id.lower())[:20] or "scan")
        self._compose_project = project
        self._compose_file = str(self.code_root / compose_file)
        self.metadata["mode"] = "docker_compose"
        self.metadata["launch_command"] = f"docker compose -f {compose_file} up -d --build"

        up_cmd = ["docker", "compose", "-p", project, "-f", self._compose_file,
                  "up", "-d", "--build"]
        try:
            proc = subprocess.run(up_cmd, cwd=str(self.code_root), capture_output=True,
                                  text=True, timeout=self.build_timeout)
        except FileNotFoundError as e:
            raise RuntimeError("docker compose CLI 不可用（需 Docker Compose v2）") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"docker compose up 超时（>{self.build_timeout}s）") from e

        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            low = err.lower()
            if any(k in low for k in ("pip install", "npm install", "could not find",
                                      "no matching distribution", "failed to solve")):
                raise _DependencyError(err)
            raise RuntimeError(err[:500] or "docker compose up 失败")

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

        base_url = f"http://127.0.0.1:{host_port}"
        health_url = base_url.rstrip("/") + (self.metadata["health_path"] or "/")
        if _wait_healthy(health_url, self.health_timeout):
            self.base_url = base_url
            self.metadata.update({
                "base_url": base_url, "port": host_port,
                "health_check": "passed", "status": STARTED, "reason": "",
            })
        else:
            self.metadata["status"] = HEALTH_CHECK_FAILED
            self.metadata["health_check"] = "failed"
            self.metadata["reason"] = (
                f"docker compose 服务已启动但 {self.health_timeout}s 内健康检查未通过"
                f"（探测端口 {host_port}，health_path={self.metadata['health_path']}）："
                "可能 Web 服务尚未就绪、端口映射不对或依赖服务未启动，详见 logs_excerpt。"
            )
        self.metadata["logs_excerpt"] = self._compose_logs()

    def _compose_published_port(self, project: str, port_hint) -> int | None:
        """解析 `docker compose ps --format json`，返回一个对外发布的 TCP 端口。

        兼容两种输出：整体 JSON 数组，或每行一个 JSON 对象（不同 compose 版本）。
        优先匹配 port_hint（容器内目标端口），否则取第一个已发布端口。
        """
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", project, "ps", "--format", "json"],
                cwd=str(self.code_root), capture_output=True, text=True, timeout=30)
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
        published: list[tuple] = []
        for svc in services:
            for pub in (svc.get("Publishers") or []):
                pp = pub.get("PublishedPort")
                if pp and str(pub.get("Protocol", "tcp")) == "tcp":
                    published.append((pub.get("TargetPort"), int(pp)))
        if not published:
            return None
        if port_hint:
            for target, host in published:
                if target == int(port_hint):
                    return host
        return published[0][1]

    def _compose_logs(self) -> str:
        if not (self._compose_project and self._compose_file):
            return ""
        try:
            proc = subprocess.run(
                ["docker", "compose", "-p", self._compose_project, "-f",
                 self._compose_file, "logs", "--no-color", "--tail", "50"],
                cwd=str(self.code_root), capture_output=True, text=True, timeout=30)
            return (proc.stdout or "")[-1500:]
        except Exception:  # noqa: BLE001
            return ""

    def _cleanup(self) -> None:
        if self._container is not None:
            try:
                self._container.remove(force=True)
            except Exception as e:  # noqa: BLE001
                logger.warning("清理容器失败: %s", e)
        # compose 编排：down 清理所有服务与卷
        if self._compose_project and self._compose_file:
            try:
                subprocess.run(
                    ["docker", "compose", "-p", self._compose_project, "-f",
                     self._compose_file, "down", "-v"],
                    cwd=str(self.code_root), capture_output=True, text=True, timeout=60)
            except Exception as e:  # noqa: BLE001
                logger.warning("清理 compose 项目失败: %s", e)
        # 清理临时 Dockerfile
        tmp = self.code_root / "Dockerfile.auditagentx"
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


class _DependencyError(Exception):
    """依赖安装失败的内部异常。"""


@contextmanager
def docker_project_sandbox(code_root: Path, launch_plan: dict | None = None,
                           *, env: dict | None = None, scan_id: str | None = None):
    """便捷上下文管理器，yield DockerProjectRunner 实例。"""
    runner = DockerProjectRunner(code_root, launch_plan, env=env, scan_id=scan_id)
    with runner:
        yield runner

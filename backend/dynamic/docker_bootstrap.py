"""Docker 引擎自启：项目启动时确保 Docker 可用。

动态验证（沙箱靶场、Harness 的 Docker-first 执行）依赖 Docker 引擎在线。
本模块在后端启动时检测引擎状态；若未就绪且配置允许，则自动拉起 Docker
Desktop（Windows/macOS）或尝试启动 daemon（Linux），并轮询等待就绪。

设计原则：
- 尽力而为，**绝不抛异常**，任何失败都只记日志、返回状态，不拖垮后端启动。
- 平台自适应；Docker 未安装 / 平台不支持自启时优雅跳过。
"""
from __future__ import annotations

import logging
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from backend.config import settings

logger = logging.getLogger(__name__)


# Windows 下 Docker Desktop 的常见安装位置
_WINDOWS_DOCKER_DESKTOP_CANDIDATES = [
    r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
    r"C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe",
]


def engine_ready(host: str = "", timeout: int = 5) -> bool:
    """通过 docker SDK ping 引擎，判断是否在线。任何异常都视为不可用。"""
    client = None
    try:
        # host 参数表示调用方明确覆盖；未传时必须复用 app_runner 的平台适配。
        # 不能在这里直接读取 settings.docker_host 后构造 DockerClient：Windows
        # 环境里若残留 unix:///var/run/docker.sock，app_runner 会正确忽略并改用
        # named pipe，而旧实现会硬连 Linux socket，导致 Docker 明明在线却永远 False。
        if host:
            import docker  # 延迟导入：未装 SDK 时不影响后端启动
            client = docker.DockerClient(base_url=host, timeout=timeout)
        else:
            from backend.verifier.app_runner import get_docker_client
            client = get_docker_client()
        return bool(client.ping())
    except Exception:  # noqa: BLE001
        return False
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


def _resolve_docker_desktop_path() -> Optional[str]:
    """定位 Docker Desktop 可执行文件；找不到返回 None。"""
    configured = (settings.docker_desktop_path or "").strip()
    if configured:
        return configured if Path(configured).exists() else None
    for cand in _WINDOWS_DOCKER_DESKTOP_CANDIDATES:
        if Path(cand).exists():
            return cand
    return None


def _launch_engine() -> tuple[bool, str]:
    """按平台拉起 Docker 引擎/Desktop。返回 (是否成功发出启动命令, 说明)。"""
    system = platform.system()
    try:
        if system == "Windows":
            exe = _resolve_docker_desktop_path()
            if not exe:
                return False, "not_installed"
            # 分离启动，不阻塞、不继承控制台
            flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
            subprocess.Popen([exe], creationflags=flags, close_fds=True)
            return True, f"launched: {exe}"
        if system == "Darwin":
            subprocess.Popen(["open", "-a", "Docker"], close_fds=True)
            return True, "launched: open -a Docker"
        if system == "Linux":
            # 优先 Docker Desktop（若装了），否则尝试启动 daemon（需相应权限）
            if shutil.which("systemctl"):
                subprocess.Popen(
                    ["systemctl", "start", "docker"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True,
                )
                return True, "launched: systemctl start docker"
            return False, "unsupported"
        return False, "unsupported"
    except Exception as exc:  # noqa: BLE001
        return False, f"launch_error: {exc}"


def ensure_docker_running(
    autostart: Optional[bool] = None,
    timeout: Optional[int] = None,
    poll_interval: Optional[int] = None,
) -> dict:
    """确保 Docker 引擎在线。

    返回状态字典：``status`` 取值
      - ``already_running``：启动前就已就绪
      - ``started``：本次自启成功并已就绪
      - ``start_timeout``：已拉起但在超时内未就绪
      - ``start_failed`` / ``not_installed`` / ``unsupported``：无法自启
      - ``disabled``：配置关闭了自启
    """
    if autostart is None:
        autostart = settings.docker_autostart
    if timeout is None:
        timeout = settings.docker_start_timeout
    if poll_interval is None:
        poll_interval = max(1, settings.docker_poll_interval)

    if engine_ready():
        logger.info("Docker 引擎已就绪，无需自启。")
        return {"status": "already_running"}

    if not autostart:
        logger.warning("Docker 引擎未就绪，且 docker_autostart=False，跳过自启。")
        return {"status": "disabled"}

    ok, detail = _launch_engine()
    if not ok:
        logger.warning("Docker 引擎未就绪且无法自启：%s", detail)
        return {"status": detail if detail in ("not_installed", "unsupported") else "start_failed",
                "detail": detail}

    logger.info("已拉起 Docker（%s），等待引擎就绪（最长 %ds）...", detail, timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if engine_ready():
            elapsed = round(timeout - (deadline - time.time()), 1)
            logger.info("Docker 引擎已就绪（耗时约 %ss）。", elapsed)
            return {"status": "started", "elapsed": elapsed, "detail": detail}
        time.sleep(poll_interval)

    logger.warning("Docker 已拉起但 %ds 内引擎仍未就绪；动态验证将按不可用降级。", timeout)
    return {"status": "start_timeout", "detail": detail}


# 函数级 Harness 的固定沙箱镜像（预装 flask/fastapi 等，供 test-client 入口级确认）
_DEFAULT_HARNESS_IMAGE = "auditagentx-harness-python:latest"


def _harness_dockerfile_dir() -> Path:
    # backend/dynamic/docker_bootstrap.py -> 项目根/docker/harness
    return Path(__file__).resolve().parents[2] / "docker" / "harness"


def ensure_harness_image(build_if_missing: bool = True) -> dict:
    """确保函数级 Harness 的固定沙箱镜像可用，并把 settings.harness_sandbox_image
    指向它——让 **test-client 入口级动态确认开箱即用**。

    此前 harness_sandbox_image 默认空，导致 build_route_testclient_harness 因"无镜像"
    直接返回 None、主力路径被 gate 关，deep 扫描只能到函数级/机理级。本函数在 Docker
    就绪后自动接上：
      - 已显式配置：尊重用户配置，不覆盖；
      - 镜像已构建：直接指向它（秒级）；
      - 缺失且 build_if_missing：按 docker/harness/Dockerfile 构建（首次耗时数分钟）。
    绝不抛异常；任何失败只记日志并返回状态，动态验证据此诚实降级。
    """
    configured = (settings.harness_sandbox_image or "").strip()
    if configured:
        return {"status": "configured", "image": configured}
    if not engine_ready():
        return {"status": "docker_unavailable"}
    try:
        from backend.verifier.app_runner import get_docker_client
        client = get_docker_client()
    except Exception as exc:  # noqa: BLE001
        return {"status": "docker_client_error", "detail": repr(exc)[:160]}
    # 1) 镜像已存在 -> 直接启用
    try:
        client.images.get(_DEFAULT_HARNESS_IMAGE)
        settings.harness_sandbox_image = _DEFAULT_HARNESS_IMAGE
        logger.info("检测到固定 Harness 镜像 %s，已启用入口级动态确认。", _DEFAULT_HARNESS_IMAGE)
        return {"status": "detected", "image": _DEFAULT_HARNESS_IMAGE}
    except Exception:  # noqa: BLE001  ImageNotFound 等一律走构建/降级
        pass
    if not build_if_missing:
        return {"status": "missing"}
    dockerfile_dir = _harness_dockerfile_dir()
    if not (dockerfile_dir / "Dockerfile").exists():
        return {"status": "dockerfile_missing", "path": str(dockerfile_dir)}
    try:
        logger.info("首次构建固定 Harness 镜像 %s（预装 flask/fastapi 等，耗时数分钟）...",
                    _DEFAULT_HARNESS_IMAGE)
        client.images.build(path=str(dockerfile_dir), tag=_DEFAULT_HARNESS_IMAGE, rm=True)
        settings.harness_sandbox_image = _DEFAULT_HARNESS_IMAGE
        logger.info("固定 Harness 镜像构建完成，已启用入口级动态确认。")
        return {"status": "built", "image": _DEFAULT_HARNESS_IMAGE}
    except Exception as exc:  # noqa: BLE001
        logger.warning("构建 Harness 镜像失败（动态验证降级为函数级/机理级）: %s", repr(exc)[:200])
        return {"status": "build_failed", "detail": repr(exc)[:180]}

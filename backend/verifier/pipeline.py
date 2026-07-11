"""漏洞利用 + 动态验证流水线（PDF 模块③ + 动态检测的总装配）。

对一批已确认漏洞：
  1) ExploitAgent 生成利用方案（利用代码 / 触发位置 / 利用路径 / 验证方法）
  2) 若开启动态验证：启动靶场一次，逐条发送载荷、采集运行时证据、判定可复现
  3) EvidenceCollector 汇总证据链，回填到 finding 上
"""
from __future__ import annotations

import logging
import copy
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager, nullcontext
from typing import Any, Callable

from pathlib import Path

from backend.config import settings
from backend.agents.exploit_agent import (
    ExploitAgent,
    build_authorization_workflow_poc,
    build_confirmed_http_poc,
)
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.harness_verifier import HarnessVerifier
from backend.verifier.evidence_collector import EvidenceCollector
from backend.verifier import exploit_templates as tpl
from backend.verifier import app_runner
from backend.dynamic.endpoint_extractor import candidate_attack_surfaces, candidate_endpoints
from backend.dynamic.authorization_planner import plan_authorization_workflow
from backend.dynamic.strategy import HTTP, BOTH, NOT_APPLICABLE, resolve_strategy, is_dynamic_applicable
from backend.dynamic.target_guard import validate_dynamic_base_url
from backend.verifier.context_classifier import apply_context_to_finding, classify_finding_context

logger = logging.getLogger(__name__)


def _emit_progress(callback, phase: str, *, completed: int = 0, total: int = 0,
                   detail: str = "", **extra) -> None:
    """发布动态 campaign 的可观测进度；回调失败绝不能中断漏洞验证。"""
    if callback is None:
        return
    payload = {"phase": phase, "completed": completed, "total": total,
               "detail": detail, **extra}
    try:
        callback(payload)
    except Exception as exc:  # noqa: BLE001
        logger.debug("动态进度回调失败（忽略）: %s", exc)


def _parallel_map(items: list, fn: Callable[[Any], Any], workers: int, *,
                  default: Any = None) -> list:
    """按输入顺序并发执行 fn；单个任务失败返回 default，不影响其余任务。

    workers<=1 或 items 很少时退化为串行，避免线程池无谓开销。
    """
    n = len(items)
    if n == 0:
        return []

    def _safe(it):
        try:
            return fn(it)
        except Exception as exc:  # noqa: BLE001
            logger.warning("并行任务失败，使用默认值: %s", exc)
            return default

    workers = max(1, min(int(workers), n))
    if workers == 1:
        return [_safe(it) for it in items]

    results: list = [default] * n
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_safe, it): idx for idx, it in enumerate(items)}
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
    return results

# HTTP 动态验证的严重级门槛：critical/high/medium 均可（low 多为噪声，排除）。
# 注意：此门槛只约束 HTTP 探测；函数级 Harness 不受此限（走 is_dynamic_applicable），
# 因此 Docker/靶场不可用时，medium 的 needs_review 仍可由 Harness 定性。
_DYNAMIC_SEVERITIES = {"critical", "high", "medium"}
@contextmanager
def _resolve_target(dynamic_target: dict, code_root: Path | None = None):
    """根据配置解析目标，统一 yield (base_url, endpoints, sandbox_metadata, runtime_log_supplier)。

    dynamic_target 支持四种模式：
      {"mode": "url",   "base_url": "http://...", "endpoints": [...]}   已运行的授权靶场
      {"mode": "local", "command": [...], "cwd": "...", "endpoints": [...]}  本机子进程（隔离环境）
      {"mode": "docker","image": "...", "build_context": "...", "internal_port": 80}  现成镜像
      {"mode": "docker_project", "launch_plan": {...}}  Docker-first：从 code_root 构建并启动项目
    sandbox_metadata：仅 docker_project 模式返回沙箱元信息（含失败状态），其余为 None。
    """
    mode = (dynamic_target or {}).get("mode")
    endpoints = (dynamic_target or {}).get("endpoints")
    if mode == "url":
        yield validate_dynamic_base_url(dynamic_target.get("base_url")), endpoints, None, None
    elif mode == "local":
        if not settings.enable_local_dynamic_runner:
            raise RuntimeError("local dynamic runner is disabled; use docker_project or explicitly enable it")
        with app_runner.LocalAppRunner(
            dynamic_target["command"], dynamic_target.get("cwd", "."),
            env=dynamic_target.get("env"),
        ) as base_url:
            yield base_url, endpoints, None, None
    elif mode == "docker":
        try:
            with app_runner.DockerAppRunner(
                dynamic_target["image"],
                internal_port=dynamic_target.get("internal_port", 80),
                build_context=dynamic_target.get("build_context"),
            ) as base_url:
                yield base_url, endpoints, {
                    "status": "started",
                    "mode": "docker",
                    "image": dynamic_target["image"],
                    "internal_port": dynamic_target.get("internal_port", 80),
                    "health_check": "ready",
                }, None
        except app_runner.DockerTargetStartError as exc:
            # 普通 docker 模式也必须像 docker_project 一样失败闭合：容器未健康时
            # 不得把随机端口继续交给 DynamicVerifier，再伪装成 payload_not_matched。
            yield None, endpoints, dict(exc.metadata), None
    elif mode == "docker_project":
        # Docker-first Deep Mode：从 GitHub 项目 code_root 构建并启动容器
        from backend.dynamic.launch_detector import detect_launch
        from backend.dynamic.docker_bootstrap import ensure_docker_running
        from backend.verifier.docker_project_runner import DockerProjectRunner
        engine_state = None
        if dynamic_target.get("auto_start_docker"):
            # 后端启动时已有异步预热；扫描开始时再同步确认一次，避免用户刚打开
            # Docker Desktop 就立即发起 Deep 扫描时发生竞态。
            engine_state = ensure_docker_running()
        # 以自动探测为基底，用户显式提供的字段覆盖之（未提供的保留探测结果）——
        # 避免前端只填了 {health_path:"/"} 就把探测到的 run_command/framework 整个抹掉。
        detected = detect_launch(code_root)
        user_plan = dynamic_target.get("launch_plan") or {}
        launch_plan = {**detected, **{k: v for k, v in user_plan.items() if v not in (None, "")}}
        if not endpoints and code_root is not None:
            endpoints = candidate_attack_surfaces(code_root)
        with DockerProjectRunner(code_root, launch_plan,
                                 env=dynamic_target.get("env"),
                                 scan_id=dynamic_target.get("scan_id"),
                                 trust_project_container_config=bool(
                                     dynamic_target.get("trust_project_container_config", False)
                                 )) as sandbox:
            sandbox.metadata["docker_autostart_requested"] = bool(
                dynamic_target.get("auto_start_docker")
            )
            sandbox.metadata["docker_engine"] = engine_state or {"status": "not_requested"}
            if (sandbox.metadata.get("status") == "launch_not_detected"
                    and (engine_state or {}).get("status") in {"already_running", "started"}):
                sandbox.metadata["reason"] += (
                    " Docker 引擎已经就绪；未创建容器的原因是被测项目缺少可识别的 Web "
                    "启动命令，而不是 Docker Desktop 故障。"
                )
            yield sandbox.base_url, endpoints, sandbox.metadata, sandbox.runtime_logs
    else:
        yield None, endpoints, None, None


class ExploitPipeline:
    def __init__(self, scan_id: str | None = None) -> None:
        self.scan_id = scan_id
        self.exploit_agent = ExploitAgent(scan_id=scan_id)
        self.dynamic = DynamicVerifier()
        self.harness = HarnessVerifier(scan_id=scan_id)
        # 并发度：利用生成与 Harness 并行；HTTP 探测因共享靶场固定串行
        self._exploit_workers = int(getattr(settings, "dynamic_exploit_workers", 4))
        self._harness_workers = int(getattr(settings, "dynamic_harness_workers", 4))
        self._max_candidates = int(getattr(settings, "max_dynamic_candidates", 20))

    @staticmethod
    def _select_candidates(findings: list[dict], max_candidates: int) -> list[dict]:
        """挑选动态验证候选：confirmed 全量优先，needs_review 中「动态可验证」的次之。

        逻辑要点（修复 deep≈quick 的核心）：
          - 不再只取 status==confirmed。deep 模式经 VerifyAgent 静态复核后，绝大多数
            finding 被保守降级为 needs_review——它们恰恰是最该用运行时证据来定性的对象。
          - needs_review 仅纳入 is_dynamic_applicable 为真的类型（排除硬编码密钥/弱加密等
            static-only 类型，这些没有运行时触发点，动态验证无意义）。
          - 预算上限：confirmed 全部保留，剩余名额（max_candidates - len(confirmed)）用于
            needs_review，避免超大项目对全部漏洞逐条跑动态验证。max_candidates<=0 表示不限。
        """
        for finding in findings:
            if "dynamic_applicable" not in finding:
                apply_context_to_finding(finding)

        confirmed = [
            f for f in findings
            if f.get("status") == "confirmed"
            and f.get("dynamic_applicable") is not False
            and is_dynamic_applicable(f.get("type"))
        ]
        needs_review = [
            f for f in findings
            if f.get("status") == "needs_review"
            and f.get("dynamic_applicable") is not False
            and is_dynamic_applicable(f.get("type"))
        ]
        selected = confirmed + needs_review
        if max_candidates and max_candidates > 0:
            return selected[:max_candidates]
        return selected

    def run(self, findings: list[dict], *, enable_exploit: bool = True,
            enable_dynamic: bool = False, dynamic_target: dict | None = None,
            enable_harness: bool = False, code_root: Path | None = None,
            max_candidates: int | None = None, on_progress=None) -> list[dict]:
        """就地为候选漏洞附加利用方案 + 动态验证 + 证据链，返回同一列表。

        候选 = confirmed（全量）+ needs_review 中动态可验证者（受预算上限约束）。
        """
        self._code_root = str(code_root) if code_root else None
        budget = self._max_candidates if max_candidates is None else int(max_candidates)
        candidates = self._select_candidates(findings, budget)
        _emit_progress(on_progress, "candidate_selection", completed=len(candidates), total=len(candidates),
                       detail=f"已选择 {len(candidates)} 个可动态验证候选", budget=budget)
        if not candidates:
            _emit_progress(on_progress, "completed", completed=0, total=0,
                           detail="没有适合动态验证的候选")
            return findings

        # 动态验证目标只启动一次，复用给所有漏洞
        target_ctx = (_resolve_target(dynamic_target or {}, code_root)
                      if enable_dynamic else nullcontext((None, None, None)))
        with target_ctx as resolved:
            # 兼容 2/3 元组（旧）与 4 元组（含 Docker 实时日志供应器）。
            if isinstance(resolved, tuple) and len(resolved) == 4:
                base_url, endpoints, sandbox_meta, runtime_log_supplier = resolved
            elif isinstance(resolved, tuple) and len(resolved) == 3:
                base_url, endpoints, sandbox_meta = resolved
                runtime_log_supplier = None
            elif isinstance(resolved, tuple):
                base_url, endpoints = resolved
                sandbox_meta = None
                runtime_log_supplier = None
            else:
                base_url, endpoints, sandbox_meta, runtime_log_supplier = None, None, None, None
            auto_endpoints = False
            if enable_dynamic and not endpoints and code_root is not None:
                endpoints = candidate_attack_surfaces(code_root)
                auto_endpoints = True
            # 沙箱启动失败时的状态（供 HTTP 验证跳过时使用真实原因）
            sandbox_fail_status = None
            if sandbox_meta and sandbox_meta.get("status") != "started":
                sandbox_fail_status = sandbox_meta.get("status")  # sandbox_start_failed / health_check_failed / dependency_install_failed
            if enable_dynamic:
                logger.info("动态验证目标: %s (sandbox=%s)", base_url or "（无）",
                            sandbox_meta.get("status") if sandbox_meta else "none")
                _emit_progress(
                    on_progress, "environment_ready", completed=1, total=1,
                    detail=(sandbox_meta or {}).get("reason") or ("动态靶场就绪" if base_url else "动态靶场不可用，将保留 Harness 回退"),
                    target_status=(sandbox_meta or {}).get("status") or ("started" if base_url else "not_available"),
                    base_url=base_url or "",
                )

            # ---- 阶段 A：利用生成（并行，纯 LLM、逐条独立、不碰共享靶场）----
            _emit_progress(on_progress, "exploit_generation", completed=0, total=len(candidates),
                           detail="正在生成利用计划")
            disposable_target = bool(
                sandbox_meta and sandbox_meta.get("status") == "started"
                and sandbox_meta.get("mode") in {"docker", "docker_project"}
            ) or bool((dynamic_target or {}).get("allow_stateful_workflows"))
            exploits = _parallel_map(
                candidates, lambda f: self._gen_exploit(
                    f, enable_exploit and not bool(sandbox_fail_status), endpoints=endpoints,
                    disposable_target=disposable_target,
                ),
                self._exploit_workers, default=None)
            exploits = [e if e else {} for e in exploits]  # 每条独立 dict，避免别名共享
            _emit_progress(on_progress, "exploit_generation", completed=len(candidates), total=len(candidates),
                           detail="利用计划生成完成")

            # ---- 阶段 B：HTTP 动态探测（串行，共享同一靶场，避免有状态载荷互相污染）----
            dyn_results: list = [None] * len(candidates)
            if enable_dynamic:
                _emit_progress(on_progress, "http_verification", completed=0, total=len(candidates),
                               detail="正在对本地项目靶场执行 HTTP 验证")
                for i, f in enumerate(candidates):
                    dyn_results[i] = self._http_verify(
                        f, exploits[i], base_url, endpoints,
                        sandbox_meta, sandbox_fail_status, auto_endpoints, runtime_log_supplier)
                    _emit_progress(
                        on_progress, "http_verification", completed=i + 1, total=len(candidates),
                        detail=(dyn_results[i] or {}).get("reason") or "HTTP 验证完成",
                        finding_type=f.get("type"),
                        reproduction_status=(dyn_results[i] or {}).get("reproduction_status"),
                    )

            # ---- 阶段 C：Fuzzing Harness（并行，函数级独立，每任务独立实例避免共享态竞争）----
            if enable_harness and code_root is not None:
                _emit_progress(on_progress, "harness_verification", completed=0, total=len(candidates),
                               detail="正在运行受控目标函数 Harness")
                harness_lock = threading.Lock()
                harness_done = [0]

                def _harness_with_progress(f):
                    result = self._run_harness(f, code_root)
                    with harness_lock:
                        harness_done[0] += 1
                        _emit_progress(
                            on_progress, "harness_verification", completed=harness_done[0],
                            total=len(candidates),
                            detail=(result or {}).get("reason") or "Harness 完成",
                            finding_type=f.get("type"), verdict=(result or {}).get("verdict"),
                        )
                    return result

                harness_results = _parallel_map(
                    candidates, _harness_with_progress,
                    self._harness_workers, default=None)
            else:
                harness_results = [None] * len(candidates)

            # ---- 汇总（串行）：裁决 + 证据链回填到每条 finding ----
            _emit_progress(on_progress, "evidence_assembly", completed=0, total=len(candidates),
                           detail="正在汇总运行时证据")
            for i, f in enumerate(candidates):
                self._assemble(f, exploits[i], dyn_results[i], harness_results[i], sandbox_meta)
                _emit_progress(on_progress, "evidence_assembly", completed=i + 1, total=len(candidates),
                               detail="证据链已写入", finding_type=f.get("type"))
        _emit_progress(
            on_progress, "completed", completed=len(candidates), total=len(candidates),
            detail="动态验证 campaign 完成",
            target_status=(sandbox_meta or {}).get("status")
            or ("started" if base_url else "not_available"),
        )
        return findings

    # ------------------------------------------------------------------ #
    # 分阶段执行的内部方法（配合并行/串行编排）                            #
    # ------------------------------------------------------------------ #
    def _gen_exploit(self, f: dict, enable_exploit: bool, *, endpoints=None,
                     disposable_target: bool = False) -> dict:
        """阶段 A：生成利用方案并补齐模板注入点（可并行）。"""
        template = tpl.match_template(f.get("type"))
        workflow = plan_authorization_workflow(
            f, endpoints if isinstance(endpoints, list) else [],
            disposable=disposable_target, seed=getattr(self, "scan_id", None) or "adhoc",
        )
        # 手动复核/ACP 链路可能已经生成了利用方案。动态阶段必须复用该制品，
        # 否则不仅会重复消耗一次 LLM/API，还可能用第二次生成的载荷覆盖已审计内容。
        existing = f.get("_exploit")
        if isinstance(existing, dict) and existing:
            exploit = dict(existing)
        elif workflow:
            # 业务逻辑漏洞优先使用 OpenAPI 约束的确定性工作流，避免为每条 BOLA
            # 调用 LLM，也避免模型猜测凭据/路由后自行宣判成功。
            exploit = ExploitAgent._fallback(f, template)
        else:
            exploit = (self.exploit_agent.run(f) if enable_exploit
                       else ExploitAgent._fallback(f, template))
        # LLM/既有制品可能只给出 payload。用确定性模板补齐利用代码、触发位置和验证方法，
        # 这样低 API/离线模式仍满足“自动形成漏洞利用代码”，同时不覆盖目标特定字段。
        fallback = ExploitAgent._fallback(f, template)
        for key, value in fallback.items():
            if value not in (None, "", [], {}):
                exploit.setdefault(key, value)
        strategy = resolve_strategy(f.get("type"))
        if template:
            # DeepAudit 的专用 PoC 模板思路可以借鉴，但 LLM 失败/离线时也必须给出
            # 可执行、可审计的确定性载荷；否则所谓 Deep 模式实际上不会发出任何验证请求。
            exploit.setdefault("vuln_type", f.get("type"))
            exploit.setdefault("payloads", list(template.payloads))
            exploit.setdefault("success_indicators", list(template.success_indicators))
            exploit.setdefault("_injection_points", template.injection_points)
        if strategy.get("param_hint"):
            exploit.setdefault("_injection_points", strategy.get("param_hint"))
        if strategy.get("http_method"):
            exploit.setdefault("http_method", strategy.get("http_method"))
        if workflow:
            exploit["vuln_type"] = f.get("type") or "BOLA"
            exploit["authorization_workflow"] = workflow
            exploit["exploit_code"] = build_authorization_workflow_poc(
                workflow, "pending framework-side confirmation")
            exploit["verification_method"] = (
                "在一次性本地沙箱中执行 owner control 与跨身份双次读取；"
                "仅由 DynamicVerifier 的 owner/secret 不变量裁决")
            exploit["attack_vector"] = "OpenAPI 约束的多身份对象级授权工作流"
            exploit["payloads"] = []
        return exploit

    def _http_verify(self, f: dict, exploit: dict, base_url, endpoints,
                     sandbox_meta, sandbox_fail_status, auto_endpoints,
                     runtime_log_supplier=None) -> dict:
        """阶段 B：对共享靶场做 HTTP 动态探测（必须串行）。仅返回 dyn_result，不改 finding。"""
        scoped_endpoints = _surfaces_for_finding(f, endpoints)
        should_run, skip_status, skip_reason = _should_run_dynamic_verify(
            f, exploit, base_url, scoped_endpoints)
        # 沙箱启动失败：适合 HTTP 验证的漏洞用真实沙箱失败状态，而非泛化 not_executed
        if sandbox_fail_status and skip_status == "not_executed" and not base_url:
            strat = resolve_strategy(f.get("type"))
            if strat.get("strategy") in {HTTP, BOTH}:
                skip_status = sandbox_fail_status
                sb_reason = (sandbox_meta or {}).get("reason") or ""
                skip_reason = (
                    f"Docker 沙箱未就绪（{sandbox_fail_status}）：{sb_reason}"
                    if sb_reason else
                    f"Docker 沙箱未就绪（{sandbox_fail_status}），未执行 HTTP 动态验证"
                )
        if should_run:
            dyn_result = self.dynamic.verify(
                base_url, exploit, scoped_endpoints,
                runtime_log_supplier=runtime_log_supplier,
            ).__dict__
        else:
            dyn_result = _dynamic_skip_result(skip_status, skip_reason)
        if auto_endpoints:
            dyn_result.setdefault("logs", []).append(
                "未手动提供 endpoint，已使用源码路由自动提取候选入口")
            dyn_result["candidate_endpoints"] = [
                item.get("path") if isinstance(item, dict) else item for item in (scoped_endpoints or [])
            ]
            if scoped_endpoints is not endpoints and len(scoped_endpoints or []) < len(endpoints or []):
                dyn_result.setdefault("logs", []).append(
                    "已按 finding 文件位置绑定到最近的源码路由，跳过同文件无关入口")
        if sandbox_meta:
            dyn_result["sandbox"] = sandbox_meta
        return dyn_result

    def _run_harness(self, f: dict, code_root: Path) -> dict | None:
        """阶段 C：函数级 Harness 验证（可并行）。用独立实例避免 HarnessVerifier 内部共享态竞争。"""
        return HarnessVerifier(scan_id=self.scan_id).run(f, code_root)

    def _assemble(self, f: dict, exploit: dict, dyn_result, harness_result, sandbox_meta) -> None:
        """汇总阶段：把 HTTP / Harness 结果落到 finding，套用裁决与回退，构建证据链。"""
        context = classify_finding_context(f)
        apply_context_to_finding(f, context)
        allow_confirmed = bool(context.get("allow_confirmed", True))
        # HTTP 复现裁决：可复现 -> 升级为 confirmed（needs_review 借运行时证据定性）
        if dyn_result is not None:
            if dyn_result.get("reproducible"):
                if allow_confirmed:
                    f["confidence"] = max(f.get("confidence", 0.5), 0.98)
                    f["verified"] = True
                    f["dynamically_verified"] = True
                    f["dynamic_method"] = "http_dynamic"
                    f["status"] = "confirmed"  # 运行时可复现 -> 确认
                else:
                    dyn_result["blocked_reproducible"] = True
                    dyn_result["reproducible"] = False
                    dyn_result["reproduction_status"] = "dynamic_confirmed_blocked_by_context"
                    f["status"] = "needs_review"
                    f["verified"] = False
                    f["dynamically_verified"] = False
                    f["runtime_verification_status"] = "dynamic_confirmed_blocked_by_context"
                    dyn_result.setdefault("logs", []).append(
                        "动态复现被上下文降级阻断，不能自动升级 confirmed")
            f["runtime_verification_status"] = dyn_result.get("reproduction_status")
            if dyn_result.get("reproducible") and not allow_confirmed:
                f["runtime_verification_status"] = "dynamic_confirmed_blocked_by_context"

        # Harness 裁决：严格区分「真实目标函数确认」与「模板机理确认」
        hv = (harness_result or {}).get("verdict")
        # HTTP endpoint 复现是最强的运行时证据：同入口基线、攻击请求与专用 oracle
        # 已齐全。后续 Harness 仅能补充证据，绝不能以函数级/模板级上限覆盖它。
        http_confirmed = bool(dyn_result and dyn_result.get("reproducible"))
        if hv == "target_confirmed":
            blockers = _harness_target_blockers(harness_result)
            if allow_confirmed and not blockers:
                # 真实目标函数 + 危险 sink 被攻击输入触发 -> 视为动态确认
                f["confidence"] = max(f.get("confidence", 0.5), 0.97)
                f["verified"] = True
                f["dynamically_verified"] = True
                if not http_confirmed:
                    f["dynamic_method"] = "target_harness"
                f["status"] = "confirmed"  # 目标函数级 Harness 触发 -> 确认
                if not http_confirmed:
                    f["runtime_verification_status"] = "harness_target_confirmed"
                if dyn_result is not None and not dyn_result.get("reproducible"):
                    dyn_result["harness_confirmed"] = True
                    dyn_result["reason"] = ((dyn_result.get("reason") or "")
                                            + "（HTTP 未复现，但目标函数级 Harness 已触发该漏洞）")
                    dyn_result.setdefault("logs", []).append(
                        "回退：目标函数级 Harness 已复现漏洞，见 harness 证据")
            else:
                harness_result["blocked_verdict"] = "target_confirmed"
                harness_result["verdict"] = "target_blocked"
                harness_result["dynamically_triggered"] = False
                harness_result["confirmed_blockers"] = blockers or f.get("confirmed_blockers") or []
                # Harness 证据不足只能否定该 Harness 的确认资格，不能推翻已经由
                # 独立 HTTP baseline/attack 对照得到的真实 endpoint 复现结论。
                if not (dyn_result and dyn_result.get("reproducible")):
                    f["status"] = "needs_review"
                    f["verified"] = False
                    f["dynamically_verified"] = False
                    f["runtime_verification_status"] = "harness_target_blocked"
                    f["confirmed_blockers"] = _dedupe(
                        list(f.get("confirmed_blockers") or []) + blockers)
                    f["downgrade_reason"] = f.get("downgrade_reason") or "; ".join(blockers)
        elif hv == "function_reproduced":
            f["function_mechanism_verified"] = True
            f["function_unit_reproduced"] = True
            if not http_confirmed:
                f["confidence"] = min(max(f.get("confidence", 0.5), 0.85), 0.85)
                f["status"] = "needs_review"
                f["verified"] = False
                f["dynamically_verified"] = False
                f["runtime_verification_status"] = "function_reproduced"
                reason = (harness_result.get("reason") or
                          "function unit reproduced but no real entrypoint reachability was proven")
                f["confirmed_blockers"] = _dedupe(
                    list(f.get("confirmed_blockers") or []) + [reason])
                f["downgrade_reason"] = f.get("downgrade_reason") or reason
            if dyn_result is not None and not dyn_result.get("reproducible"):
                dyn_result.setdefault("logs", []).append(
                    "目标函数单元已触发，但缺少真实入口可达性证据，不升级动态确认")
        elif hv == "mechanism_confirmed":
            # 模板 Harness 只证明「漏洞类型机理」，不等价真实可利用 -> 不标记完全动态确认，
            # 也不升级 status（维持 needs_review/原状）。机理级贡献的置信度上限 0.75。
            f["function_mechanism_verified"] = True
            mech_conf = min(float(harness_result.get("confidence") or 0.75), 0.75)
            if not http_confirmed:
                f["confidence"] = min(max(f.get("confidence", 0.5), mech_conf), 0.75)
            if (not http_confirmed and f.get("status") == "confirmed"
                    and not f.get("dynamically_verified")):
                f["status"] = "needs_review"
                f["verified"] = False
                reason = "mechanism_confirmed is mechanism-only and cannot keep a weak confirmed verdict"
                f["confirmed_blockers"] = _dedupe(list(f.get("confirmed_blockers") or []) + [reason])
                f["downgrade_reason"] = f.get("downgrade_reason") or reason
            if not (dyn_result and dyn_result.get("reproducible")):
                f["dynamically_verified"] = False
            if not (dyn_result and dyn_result.get("reproducible")):
                f["runtime_verification_status"] = "harness_mechanism_confirmed"
            if dyn_result is not None and not dyn_result.get("reproducible"):
                dyn_result.setdefault("logs", []).append(
                    "模板 Harness 只证明漏洞机理，仍需 source-to-sink 或 HTTP 复现确认")
                if not dyn_result.get("reason"):
                    dyn_result["reason"] = "模板 Harness 只证明漏洞机理，仍需 HTTP/真实函数复现确认"
        elif hv == "synthetic_demo_only":
            # LLM 玩具程序：只执行了它自己重写的“相似漏洞”，未触及项目真实目标代码。
            # 必须明确标注、绝不晋级、不计入真实动态复现；也不据此下调有独立静态证据的候选。
            f["synthetic_demo_only"] = True
            if harness_result is not None:
                harness_result["counts_as_real_reproduction"] = False
            if not (dyn_result and dyn_result.get("reproducible")):
                f["dynamically_verified"] = False
                f["runtime_verification_status"] = "harness_synthetic_demo_only"
        elif hv in {"unsafe_harness_blocked", "sandbox_failed", "not_reproduced"}:
            if f.get("status") == "confirmed" and not (dyn_result and dyn_result.get("reproducible")):
                f["status"] = "needs_review"
                f["verified"] = False
                f["dynamically_verified"] = False
                f["runtime_verification_status"] = hv
                reason = harness_result.get("reason") or f"{hv} cannot support dynamic confirmation"
                f["confirmed_blockers"] = _dedupe(list(f.get("confirmed_blockers") or []) + [reason])
                f["downgrade_reason"] = f.get("downgrade_reason") or reason

        # HTTP 确认后，用实际命中的 method/path/transport/param/payload 重建精确利用代码，
        # 取代通用模板端点，确保报告里的代码可复现且与证据记录一一对应。
        if dyn_result and dyn_result.get("reproducible") and dyn_result.get("confirmed_record"):
            if (dyn_result.get("oracle") == "cross_identity_owner_secret_replay"
                    and exploit.get("authorization_workflow")):
                exploit["exploit_code"] = build_authorization_workflow_poc(
                    exploit["authorization_workflow"], dyn_result.get("matched_indicator") or "")
                exploit["verification_method"] = (
                    "重放 owner control 与跨身份双次读取，并校验 owner/secret 不变量")
            else:
                exploit["exploit_code"] = build_confirmed_http_poc(
                    dyn_result["confirmed_record"], dyn_result.get("matched_indicator") or "",
                    exploit.get("setup_requests") or [],
                )
                exploit["verification_method"] = "重放框架侧 confirmed_record，并匹配动态成功判据"
            exploit.setdefault(
                "trigger_location",
                f"{f.get('file')}:{f.get('start_line') or f.get('line')}",
            )
        f["_exploit"] = _redact_exploit_for_storage(exploit)
        f["_dynamic"] = dyn_result
        f["_harness"] = harness_result
        f["_sandbox"] = sandbox_meta
        f.setdefault("_verify", {})
        f["_verify"].update({
            "context": f.get("context"),
            "risk_modifier": f.get("risk_modifier"),
            "downgrade_reason": f.get("downgrade_reason"),
            "confirmed_blockers": f.get("confirmed_blockers") or [],
            "dynamic_applicable": f.get("dynamic_applicable"),
        })
        if harness_result:
            harness_result.setdefault("harness_kind", harness_result.get("harness_source"))
            harness_result.setdefault("confirmed_blockers", f.get("confirmed_blockers") or [])
        f["_evidence"] = EvidenceCollector.build(
            f.get("_verify", {}), exploit=exploit, dynamic=dyn_result,
            poc_result=f.get("_poc"), harness=harness_result,
            sandbox=sandbox_meta,
        )

        # 补项 1+3：仅在**真实动态确认**后，据真实确认记录生成专属 PoC 文件，
        # 并把不可变复现元数据（源码 commit / 镜像摘要 / 时间 / PoC hash / 请求响应 hash）
        # 写入证据链——让报告成为可审计证据，而非 Agent 自然语言描述。
        if f.get("dynamically_verified"):
            try:
                from backend.verifier.poc_writer import generate_poc_file
                out_dir = settings.data_path / "scans" / (self.scan_id or "adhoc") / "pocs"
                poc = generate_poc_file(f, f["_evidence"], out_dir,
                                        code_root=getattr(self, "_code_root", None))
                if poc:
                    f["_evidence"]["poc_file"] = {"path": poc["path"], "sha256": poc["sha256"]}
                    f["_evidence"]["reproduction_metadata"] = poc["reproduction_metadata"]
                    f["_poc_file"] = poc["path"]
            except Exception as exc:  # noqa: BLE001  PoC 生成失败不影响确认结论
                logger.warning("PoC 文件生成失败（不影响确认）: %s", exc)


def _should_run_dynamic_verify(finding: dict, exploit: dict,
                               base_url: str | None,
                               endpoints: list[str] | None) -> tuple[bool, str, str]:
    if not base_url:
        return False, "not_executed", "未配置本地授权靶场 base_url，未执行动态 HTTP 探测"

    strategy = resolve_strategy(finding.get("type"))
    if strategy.get("strategy") == NOT_APPLICABLE:
        return False, "not_runtime_verifiable", strategy.get("reason") or "漏洞类型不适合动态验证"
    if strategy.get("strategy") not in {HTTP, BOTH}:
        return False, "not_runtime_verifiable", strategy.get("reason") or "漏洞类型不适合 HTTP 动态验证"

    severity = str(finding.get("severity") or "low").lower()
    if severity not in _DYNAMIC_SEVERITIES:
        return False, "not_runtime_verifiable", "仅对 Medium/High/Critical 漏洞执行 HTTP 动态验证（Low 级排除）"

    if not endpoints:
        return False, "not_runtime_verifiable", "未提供明确 endpoint，避免对无入口漏洞进行猜测式动态验证"

    if exploit.get("authorization_workflow"):
        return True, "", ""

    if not exploit.get("payloads"):
        return False, "not_runtime_verifiable", "ExploitAgent 未生成可执行 payload"

    if not exploit.get("_injection_points"):
        return False, "not_runtime_verifiable", "缺少明确参数注入点，未执行动态 HTTP 探测"

    return True, "", ""


def _dynamic_skip_result(status: str, reason: str) -> dict:
    return {
        "verified": False,
        "reproducible": False,
        "reproduction_status": status,
        "matched_indicator": "",
        "confirmed_record": None,
        "records": [],
        "logs": [reason],
        "skipped": True,
        "reason": reason,
        "error": "",
    }


def _surfaces_for_finding(finding: dict, endpoints):
    """把 finding 绑定到同文件中最近的前置路由装饰器，降低无关探针与状态污染。"""
    if not isinstance(endpoints, list) or not endpoints or not all(
        isinstance(item, dict) for item in endpoints
    ):
        return endpoints
    verify = finding.get("_verify") or {}
    call_path = verify.get("call_path") or []
    source_locations = [
        (hop.get("file"), hop.get("line")) for hop in call_path
        if isinstance(hop, dict) and str(hop.get("stage") or "").lower() in {
            "source", "entrypoint", "route",
        }
    ]
    locations = source_locations + [(
        finding.get("file"), finding.get("start_line") or finding.get("line"),
    )]
    for raw_file, raw_line in locations:
        file_path = str(raw_file or "").replace("\\", "/").lstrip("./")
        try:
            finding_line = int(raw_line or 0)
        except (TypeError, ValueError):
            continue
        if not file_path or finding_line <= 0:
            continue
        same_file = [
            item for item in endpoints
            if str(item.get("file") or "").replace("\\", "/").lstrip("./") == file_path
            and int(item.get("line") or 0) > 0
            and int(item.get("line") or 0) <= finding_line
        ]
        if same_file:
            nearest_line = max(int(item.get("line") or 0) for item in same_file)
            return [item for item in same_file if int(item.get("line") or 0) == nearest_line]
    return endpoints


def _harness_target_blockers(harness: dict | None) -> list[str]:
    h = harness or {}
    blockers: list[str] = []
    if not h.get("function_extracted"):
        blockers.append("function_extracted=false: target project function was not extracted")
    if not h.get("target_function_called"):
        blockers.append("target_function_called=false: harness did not prove real target invocation")
    if h.get("verification_level") != "entrypoint_reproduced":
        blockers.append("verification_level is not entrypoint_reproduced")
    if not h.get("entrypoint_reachable"):
        blockers.append("entrypoint_reachable=false: no real entrypoint-to-function flow was proven")
    if h.get("harness_source") == "template":
        blockers.append("template harness is mechanism-only")
    return blockers


def _dedupe(items: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item)
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _redact_exploit_for_storage(exploit: dict) -> dict:
    """持久化前移除认证前置步骤中的凭据；运行阶段仍使用内存中的原值。"""
    stored = copy.deepcopy(exploit)
    sensitive = re.compile(r"password|passwd|secret|token|api[_-]?key|authorization|cookie", re.I)
    for step in stored.get("setup_requests") or []:
        if not isinstance(step, dict):
            continue
        for field in ("values", "json", "data", "params"):
            values = step.get(field)
            if not isinstance(values, dict):
                continue
            for key in list(values):
                if sensitive.search(str(key)):
                    values[key] = "<redacted>"
    workflow = stored.get("authorization_workflow")
    for step in (workflow.get("steps") if isinstance(workflow, dict) else []) or []:
        if not isinstance(step, dict):
            continue
        for field in ("values", "headers"):
            values = step.get(field)
            if not isinstance(values, dict):
                continue
            for key in list(values):
                if sensitive.search(str(key)):
                    values[key] = "<redacted>"
    headers = stored.get("request_headers")
    if isinstance(headers, dict):
        for key in list(headers):
            if sensitive.search(str(key)):
                headers[key] = "<redacted>"
    return stored

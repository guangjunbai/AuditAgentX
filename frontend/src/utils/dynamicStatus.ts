export type StatusTone = "success" | "warning" | "danger" | "info";

export type StatusMeta = {
  label: string;
  tone: StatusTone;
  trustworthyPositive: boolean;
};

const HTTP_STATUS: Record<string, StatusMeta> = {
  dynamic_confirmed: { label: "HTTP 端到端复现", tone: "success", trustworthyPositive: true },
  dynamic_confirmed_blocked_by_context: { label: "HTTP 命中，但上下文禁止确认", tone: "warning", trustworthyPositive: false },
  not_reproduced: { label: "已执行，未获得复现证据", tone: "warning", trustworthyPositive: false },
  inconclusive: { label: "已执行，但证据不足", tone: "warning", trustworthyPositive: false },
  blocked: { label: "请求被认证、授权或协议阻断", tone: "warning", trustworthyPositive: false },
  setup_failed: { label: "前置初始化或认证失败", tone: "danger", trustworthyPositive: false },
  invalid_baseline: { label: "基线无效，不能判断漏洞", tone: "danger", trustworthyPositive: false },
  target_unready: { label: "目标业务尚未就绪", tone: "danger", trustworthyPositive: false },
  not_executed: { label: "未进入 HTTP 验证", tone: "info", trustworthyPositive: false },
  not_runtime_verifiable: { label: "HTTP 动态验证不适用", tone: "info", trustworthyPositive: false },
  not_web_target: { label: "非 Web 目标，HTTP 不适用", tone: "info", trustworthyPositive: false },
  connection_failed: { label: "目标连接失败", tone: "danger", trustworthyPositive: false },
  request_timeout: { label: "请求超时，无法判定", tone: "warning", trustworthyPositive: false },
  endpoint_not_found: { label: "入口不可达", tone: "warning", trustworthyPositive: false },
  payload_not_matched: { label: "载荷未命中专用判据", tone: "warning", trustworthyPositive: false },
  launch_not_detected: { label: "未识别项目启动方式", tone: "danger", trustworthyPositive: false },
  unsafe_project_config: { label: "项目容器配置被安全策略阻止", tone: "warning", trustworthyPositive: false },
  sandbox_start_failed: { label: "项目沙箱启动失败", tone: "danger", trustworthyPositive: false },
  health_check_failed: { label: "项目沙箱健康检查失败", tone: "danger", trustworthyPositive: false },
  dependency_install_failed: { label: "依赖安装失败", tone: "danger", trustworthyPositive: false },
};

const HARNESS_STATUS: Record<string, StatusMeta> = {
  target_confirmed: { label: "Harness 真实入口级复现", tone: "success", trustworthyPositive: true },
  harness_confirmed: { label: "Harness 真实入口级复现", tone: "success", trustworthyPositive: true },
  function_reproduced: { label: "真实函数单元复现（非端到端）", tone: "warning", trustworthyPositive: false },
  mechanism_confirmed: { label: "仅漏洞机理验证（非项目复现）", tone: "info", trustworthyPositive: false },
  synthetic_demo_only: { label: "未形成项目级 Harness 证据", tone: "info", trustworthyPositive: false },
  target_blocked: { label: "Harness 命中但证据门槛未满足", tone: "warning", trustworthyPositive: false },
  not_reproduced: { label: "Harness 已执行，未触发目标 sink", tone: "warning", trustworthyPositive: false },
  inconclusive: { label: "Harness 已执行，但无法判定", tone: "warning", trustworthyPositive: false },
  sandbox_failed: { label: "Harness 沙箱失败", tone: "danger", trustworthyPositive: false },
  unsafe_harness_blocked: { label: "Harness 被安全策略阻止", tone: "warning", trustworthyPositive: false },
  not_applicable: { label: "Harness 不适用", tone: "info", trustworthyPositive: false },
  not_executed: { label: "Harness 未执行", tone: "info", trustworthyPositive: false },
};

const EVIDENCE_LEVEL: Record<string, StatusMeta> = {
  http_reproduced: { label: "HTTP 端到端证据", tone: "success", trustworthyPositive: true },
  target_harness: { label: "Harness 入口级证据", tone: "success", trustworthyPositive: true },
  function_unit_reproduced: { label: "函数单元证据", tone: "warning", trustworthyPositive: false },
  mechanism_only: { label: "机理级证据", tone: "info", trustworthyPositive: false },
  blocked: { label: "被阻断，未完成验证", tone: "warning", trustworthyPositive: false },
  inconclusive: { label: "证据不足", tone: "warning", trustworthyPositive: false },
  not_reproduced: { label: "有效执行但未复现", tone: "warning", trustworthyPositive: false },
  not_executed: { label: "无运行时证据", tone: "info", trustworthyPositive: false },
};

function fallback(status: unknown, prefix: string): StatusMeta {
  const value = String(status || "").trim();
  return {
    label: value ? `${prefix}：${value}` : `${prefix}状态未知`,
    tone: "info",
    trustworthyPositive: false,
  };
}

export function httpWasExecuted(runtime: any): boolean {
  const records = [
    ...(Array.isArray(runtime?.records) ? runtime.records : []),
    ...(Array.isArray(runtime?.confirmation_records) ? runtime.confirmation_records : []),
  ];
  return records.some((record: any) => {
    const role = String(record?.role || "").toLowerCase();
    return ["attack", "confirmation", "authorization_attack"].includes(role)
      && Boolean(record?.url && record?.method)
      && (record?.status_code !== undefined || record?.status !== undefined || record?.error);
  });
}

function isConfirmedFinding(finding: any): boolean {
  return String(finding?.status || "").toLowerCase() === "confirmed";
}

function confirmedStaticMeta(): StatusMeta {
  return {
    label: "确定漏洞（HTTP 未新增复现证据）",
    tone: "success",
    trustworthyPositive: true,
  };
}

export function runtimeStatusMeta(runtime: any, finding?: any): StatusMeta {
  const status = String(runtime?.reproduction_status || "not_executed").toLowerCase();
  if (runtime?.reproducible === true && status === "dynamic_confirmed") return HTTP_STATUS.dynamic_confirmed;
  if (isConfirmedFinding(finding) && status === "not_reproduced") return confirmedStaticMeta();
  if (status === "not_executed" && httpWasExecuted(runtime)) {
    return { label: "状态不一致：已有 HTTP 请求但标记为未执行", tone: "danger", trustworthyPositive: false };
  }
  return HTTP_STATUS[status] || fallback(status, "HTTP");
}

export function harnessStatusMeta(harness: any): StatusMeta {
  const verdict = String(harness?.verdict || "not_executed").toLowerCase();
  return HARNESS_STATUS[verdict] || fallback(verdict, "Harness");
}

export function evidenceLevelMeta(verification: any, finding?: any): StatusMeta {
  const level = String(verification?.evidence_level || "not_executed").toLowerCase();
  if (isConfirmedFinding(finding) && level === "not_reproduced") return confirmedStaticMeta();
  return EVIDENCE_LEVEL[level] || fallback(level, "证据等级");
}

export function httpExecutionLabel(runtime: any): string {
  if (httpWasExecuted(runtime)) return "已发送攻击/确认请求";
  if (Array.isArray(runtime?.setup_records) && runtime.setup_records.length > 0) return "仅执行了前置步骤，未发送攻击请求";
  return "没有发送攻击请求";
}

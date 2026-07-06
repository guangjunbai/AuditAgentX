export type AuditHistoryRecord = {
  scanId: string;
  projectId?: string;
  projectName?: string;
  sourceType?: string;
  target?: string;
  status?: string;
  progress?: number;
  findingCount?: number;
  highCount?: number;
  verifiedCount?: number;
  createdAt: string;
  updatedAt: string;
};

const KEY = "auditagentx.history.v1";

export function readHistory(): AuditHistoryRecord[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(normalizeHistoryRecord) : [];
  } catch {
    return [];
  }
}

export function saveHistory(records: AuditHistoryRecord[]) {
  localStorage.setItem(KEY, JSON.stringify(records.slice(0, 50)));
}

export function upsertHistory(record: Partial<AuditHistoryRecord> & { scanId: string }) {
  const now = new Date().toISOString();
  const records = readHistory();
  const index = records.findIndex((item) => item.scanId === record.scanId);
  const existing = index >= 0 ? records[index] : undefined;
  const next: AuditHistoryRecord = {
    scanId: record.scanId,
    projectId: record.projectId ?? existing?.projectId,
    projectName: record.projectName ?? existing?.projectName ?? record.projectId ?? existing?.projectId ?? record.scanId,
    sourceType: record.sourceType ?? existing?.sourceType,
    target: record.target ?? existing?.target,
    status: record.status ?? existing?.status,
    progress: record.progress ?? existing?.progress,
    findingCount: record.findingCount ?? existing?.findingCount,
    highCount: record.highCount ?? existing?.highCount,
    verifiedCount: record.verifiedCount ?? existing?.verifiedCount,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  if (index >= 0) records.splice(index, 1);
  records.unshift(next);
  saveHistory(records);
  window.dispatchEvent(new CustomEvent("audit-history-updated"));
}

export function removeHistory(scanId: string) {
  saveHistory(readHistory().filter((item) => item.scanId !== scanId));
  window.dispatchEvent(new CustomEvent("audit-history-updated"));
}

export function clearHistory() {
  saveHistory([]);
  window.dispatchEvent(new CustomEvent("audit-history-updated"));
}

function normalizeHistoryRecord(record: AuditHistoryRecord): AuditHistoryRecord {
  const projectNameLooksLikeId = /^proj_[a-z0-9]+$/i.test(record.projectName || "");
  const projectId = record.projectId || (projectNameLooksLikeId ? record.projectName : undefined);
  const projectName = projectNameLooksLikeId
    ? deriveProjectName(record.target) || record.projectName
    : record.projectName;
  return { ...record, projectId, projectName };
}

function deriveProjectName(target?: string) {
  if (!target) return "";
  const clean = target.replace(/\.git$/i, "").replace(/[\\/]+$/, "");
  const parts = clean.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] || "";
}

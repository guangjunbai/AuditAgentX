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
    return Array.isArray(parsed) ? parsed : [];
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
  const next: AuditHistoryRecord = {
    scanId: record.scanId,
    projectId: record.projectId,
    projectName: record.projectName || record.scanId,
    sourceType: record.sourceType,
    target: record.target,
    status: record.status,
    progress: record.progress,
    findingCount: record.findingCount,
    highCount: record.highCount,
    verifiedCount: record.verifiedCount,
    createdAt: index >= 0 ? records[index].createdAt : now,
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

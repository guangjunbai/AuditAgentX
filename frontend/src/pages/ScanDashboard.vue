<template>
  <section class="dashboard-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Workbench</p>
        <h1>分析工作台</h1>
        <p>静态分析、动态分析和可利用漏洞代码分标签展示，支持历史记录回看。</p>
      </div>
      <el-button type="primary" @click="router.push('/projects/new')">新建审计</el-button>
    </div>

    <el-card shadow="never" class="query-card">
      <div class="query-row">
        <el-input v-model="scanId" placeholder="输入 scan_id 或从历史记录打开" clearable />
        <el-button type="primary" :loading="loading" @click="load">查询</el-button>
        <el-button @click="router.push('/history')">历史记录</el-button>
      </div>
    </el-card>

    <div v-if="status" class="summary-grid">
      <el-card shadow="never" class="summary-card">
        <span>任务状态</span><strong>{{ status.status }}</strong><small>{{ status.current_stage || "-" }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>扫描进度</span><strong>{{ status.progress }}%</strong><el-progress :percentage="status.progress" :show-text="false" />
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>漏洞总数</span><strong>{{ findings.length }}</strong><small>高危 {{ highCount }} / 已验证 {{ verifiedCount }}</small>
      </el-card>
      <el-card shadow="never" class="summary-card">
        <span>报告</span><strong>HTML</strong><el-button text type="primary" @click="genReport">生成报告</el-button>
      </el-card>
    </div>

    <el-alert
      v-if="status?.status === 'failed'"
      type="error"
      show-icon
      :closable="false"
      class="error-alert"
      :title="status.error || '扫描任务失败，请检查仓库地址、网络、分支或本地路径。'"
    />

    <el-card v-if="status" shadow="never" class="tabs-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="静态分析" name="static">
          <div class="tab-intro">
            <h2>静态分析结果</h2>
            <p>来自自定义规则、Semgrep、Gitleaks 等工具及候选漏洞归一化结果。</p>
          </div>
          <el-table :data="staticFindings" stripe empty-text="暂无静态分析结果">
            <el-table-column prop="type" label="类型" min-width="150" />
            <el-table-column label="严重级" width="110">
              <template #default="scope"><el-tag :type="severityType(scope.row.severity)">{{ scope.row.severity }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="file" label="文件" min-width="220" show-overflow-tooltip />
            <el-table-column prop="line" label="行" width="80" />
            <el-table-column prop="confidence" label="置信度" width="100" />
            <el-table-column prop="status" label="状态" width="120" />
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">详情</el-button></template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="动态分析" name="dynamic">
          <div class="tab-intro">
            <h2>动态验证结果</h2>
            <p>展示已执行动态验证的漏洞、命中特征、响应状态和验证结论。</p>
          </div>
          <el-table :data="dynamicRows" stripe empty-text="暂无动态验证结果，可在漏洞详情中执行按需验证">
            <el-table-column prop="type" label="漏洞类型" min-width="150" />
            <el-table-column prop="file" label="位置" min-width="220" show-overflow-tooltip />
            <el-table-column label="验证结论" width="120">
              <template #default="scope">
                <el-tag :type="scope.row.runtime?.reproducible ? 'success' : 'warning'">
                  {{ scope.row.runtime?.reproducible ? "可复现" : "未复现" }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="命中特征" min-width="150">
              <template #default="scope">{{ scope.row.runtime?.matched_indicator || "-" }}</template>
            </el-table-column>
            <el-table-column label="状态码" width="90">
              <template #default="scope">{{ scope.row.runtime?.response_status || "-" }}</template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="scope"><el-button type="primary" link @click="openFinding(scope.row.finding_id)">证据链</el-button></template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="可利用漏洞代码" name="exploit">
          <div class="tab-intro">
            <h2>可利用漏洞代码</h2>
            <p>仅展示本地授权靶场用途的 PoC / exploit 代码骨架和触发路径。</p>
          </div>
          <el-empty v-if="exploitRows.length === 0" description="暂无利用代码。可进入漏洞详情执行动态验证或启用 exploit 配置后重新扫描。" />
          <div v-else class="exploit-list">
            <article v-for="row in exploitRows" :key="row.finding_id" class="exploit-card">
              <div class="exploit-head">
                <div>
                  <h3>{{ row.type }}</h3>
                  <p>{{ row.exploit?.trigger_location || row.file }}</p>
                </div>
                <el-button type="primary" link @click="openFinding(row.finding_id)">查看详情</el-button>
              </div>
              <p class="exploit-path">{{ row.exploit?.exploit_path }}</p>
              <pre><code>{{ row.exploit?.exploit_code }}</code></pre>
            </article>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { FindingApi, ReportApi, ScanApi } from "../api";
import { upsertHistory } from "../api/history";

const route = useRoute();
const router = useRouter();
const scanId = ref((route.query.scanId as string) || "");
const activeTab = ref((route.query.tab as string) || "static");
const loading = ref(false);
const status = ref<any>(null);
const findings = ref<any[]>([]);
const evidenceMap = ref<Record<string, any>>({});

const highCount = computed(() => findings.value.filter((item) => ["high", "critical"].includes(String(item.severity).toLowerCase())).length);
const verifiedCount = computed(() => findings.value.filter((item) => item.verified).length);
const staticFindings = computed(() => findings.value);
const dynamicRows = computed(() => findings.value
  .map((item) => ({ ...item, runtime: evidenceMap.value[item.finding_id]?.runtime }))
  .filter((item) => item.runtime));
const exploitRows = computed(() => findings.value
  .map((item) => ({ ...item, exploit: evidenceMap.value[item.finding_id]?.exploit }))
  .filter((item) => item.exploit?.exploit_code));

async function load() {
  if (!scanId.value) {
    ElMessage.warning("请输入 scan_id");
    return;
  }
  loading.value = true;
  try {
    const { data } = await ScanApi.get(scanId.value);
    status.value = data;
    const { data: f } = await ScanApi.findings(scanId.value);
    findings.value = f.findings;
    await loadEvidence();
    upsertHistory({
      scanId: scanId.value,
      projectId: data.project_id,
      projectName: data.project_id,
      status: data.status,
      progress: data.progress,
      findingCount: findings.value.length,
      highCount: highCount.value,
      verifiedCount: verifiedCount.value,
    });
  } finally {
    loading.value = false;
  }
}

async function loadEvidence() {
  const pairs = await Promise.all(findings.value.map(async (finding) => {
    try {
      const { data } = await FindingApi.evidence(finding.finding_id);
      return [finding.finding_id, data.evidence];
    } catch {
      return [finding.finding_id, null];
    }
  }));
  evidenceMap.value = Object.fromEntries(pairs.filter(([, evidence]) => evidence));
}

async function genReport() {
  const { data } = await ReportApi.create({ scan_id: scanId.value, format: "html" });
  window.open(ReportApi.download(data.report_id));
  ElMessage.success("报告已生成");
}

function openFinding(id: string) { router.push(`/findings/${id}`); }
function severityType(severity: string) {
  const s = String(severity).toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "warning";
  return "success";
}

onMounted(() => { if (scanId.value) load(); });
</script>

<style scoped>
.dashboard-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.query-card, .tabs-card, .summary-card { border-radius: 16px; }
.query-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 12px; }
.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
.summary-card span { display: block; color: #667085; font-size: 13px; }
.summary-card strong { display: block; margin: 6px 0; font-size: 26px; color: #162235; }
.summary-card small { color: #667085; }
.error-alert { border-radius: 12px; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; color: #162235; }
.tab-intro p { margin: 6px 0 0; color: #667085; }
.exploit-list { display: grid; gap: 16px; }
.exploit-card { border: 1px solid #dce6f0; border-radius: 14px; padding: 16px; background: #fbfdff; }
.exploit-head { display: flex; justify-content: space-between; gap: 16px; }
.exploit-head h3 { margin: 0; }
.exploit-head p, .exploit-path { color: #667085; margin: 6px 0 12px; }
pre { background: #101828; color: #d7e3f1; padding: 14px; border-radius: 12px; overflow: auto; }
@media (max-width: 980px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 680px) { .query-row, .summary-grid { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>

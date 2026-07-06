<template>
  <section class="create-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">New Audit</p>
        <h1>新建审计项目</h1>
        <p>输入 Git 仓库或本地代码目录，选择静态分析、动态验证和利用代码生成配置。</p>
      </div>
      <el-button @click="router.push('/history')">查看历史</el-button>
    </div>

    <div class="create-grid">
      <el-card class="panel-card" shadow="never">
        <template #header>目标项目</template>
        <el-form :model="form" label-position="top">
          <el-form-item label="项目名称">
            <el-input v-model="form.name" placeholder="例如 demo_flask_app" />
          </el-form-item>
          <el-form-item label="来源类型">
            <el-segmented v-model="form.source_type" :options="sourceOptions" />
          </el-form-item>
          <el-form-item label="仓库 URL" v-if="form.source_type === 'git'">
            <el-input v-model="form.url" placeholder="https://github.com/owner/repo" />
          </el-form-item>
          <el-form-item label="本地路径" v-else>
            <el-input v-model="form.local_path" placeholder="examples/vulnerable_projects/demo_flask_app" />
          </el-form-item>
          <el-form-item label="分支" v-if="form.source_type === 'git'">
            <el-input v-model="form.branch" placeholder="留空则使用仓库默认分支；填错会自动回退" />
          </el-form-item>
        </el-form>
      </el-card>

      <el-card class="panel-card" shadow="never">
        <template #header>分析配置</template>
        <div class="switch-list">
          <div class="switch-row">
            <div><b>静态分析</b><p>调用 custom / Semgrep / Gitleaks 等工具生成候选漏洞。</p></div>
            <el-switch v-model="analysis.static" disabled />
          </div>
          <div class="switch-row">
            <div><b>LLM 审计与验证</b><p>启用 AuditAgent 和 VerifyAgent 进行语义分析和误报过滤。</p></div>
            <el-switch v-model="analysis.llm" />
          </div>
          <div class="switch-row">
            <div><b>动态分析</b><p>对本地授权靶场执行动态验证，保存运行时证据。</p></div>
            <el-switch v-model="analysis.dynamic" />
          </div>
          <div class="switch-row">
            <div><b>可利用代码</b><p>为已验证漏洞生成本地授权 PoC / 利用代码骨架。</p></div>
            <el-switch v-model="analysis.exploit" />
          </div>
        </div>

        <el-alert
          v-if="analysis.dynamic"
          type="warning"
          show-icon
          :closable="false"
          title="动态分析仅面向本地授权靶场，不会也不应攻击真实第三方系统。"
          class="notice"
        />

        <el-form v-if="analysis.dynamic" :model="dynamic" label-position="top" class="dynamic-form">
          <el-form-item label="动态目标 Base URL">
            <el-input v-model="dynamic.base_url" placeholder="http://127.0.0.1:8080" />
          </el-form-item>
          <el-form-item label="端点列表">
            <el-input v-model="dynamic.endpoints" placeholder="/user,/search" />
          </el-form-item>
        </el-form>

        <el-button type="primary" size="large" :loading="submitting" class="submit-btn" @click="submit">
          创建并开始扫描
        </el-button>
      </el-card>
    </div>
  </section>
</template>

<script setup lang="ts">
import { reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { ProjectApi, ScanApi } from "../api";
import { upsertHistory } from "../api/history";

const router = useRouter();
const submitting = ref(false);

const sourceOptions = [
  { label: "Git 仓库", value: "git" },
  { label: "本地目录", value: "local" },
];

const form = reactive({
  name: "maccms10",
  source_type: "git",
  url: "https://github.com/magicblack/maccms10",
  local_path: "examples/vulnerable_projects/demo_flask_app",
  branch: "",
});

const analysis = reactive({ static: true, llm: true, dynamic: true, exploit: true });
const dynamic = reactive({ base_url: "http://127.0.0.1:8080", endpoints: "/user" });

async function submit() {
  if (!form.name.trim()) {
    ElMessage.warning("请填写项目名称");
    return;
  }
  submitting.value = true;
  try {
    const payload = {
      ...form,
      branch: form.source_type === "git" ? (form.branch.trim() || null) : form.branch,
      url: form.url.trim(),
      local_path: form.local_path.trim(),
    };
    const { data: proj } = await ProjectApi.create(payload);
    const enabledAgents = analysis.llm ? ["audit", "verify"] : [];
    if (analysis.exploit) enabledAgents.push("exploit");

    const options: any = {
      enable_poc: false,
      enable_exploit: analysis.exploit,
      enable_dynamic: analysis.dynamic,
    };
    if (analysis.dynamic) {
      options.dynamic_target = {
        mode: "url",
        base_url: dynamic.base_url,
        endpoints: dynamic.endpoints.split(",").map((item) => item.trim()).filter(Boolean),
      };
    }

    const { data: scan } = await ScanApi.create({
      project_id: proj.project_id,
      scan_type: analysis.dynamic ? "full" : "static",
      enabled_tools: ["custom", "semgrep", "gitleaks"],
      enabled_agents: enabledAgents,
      options,
    });

    upsertHistory({
      scanId: scan.scan_id,
      projectId: proj.project_id,
      projectName: form.name,
      sourceType: form.source_type,
      target: form.source_type === "git" ? form.url : form.local_path,
      status: "queued",
      progress: 0,
      findingCount: 0,
    });

    ElMessage.success(`扫描任务已创建：${scan.scan_id}`);
    router.push({ path: "/scans", query: { scanId: scan.scan_id } });
  } catch (error: any) {
    const message = error?.response?.data?.detail || error?.message || "创建扫描任务失败";
    ElMessage.error(String(message));
  } finally {
    submitting.value = false;
  }
}
</script>

<style scoped>
.create-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.create-grid { display: grid; grid-template-columns: minmax(0, 1fr) 420px; gap: 18px; align-items: start; }
.panel-card { border-radius: 16px; }
.switch-list { display: flex; flex-direction: column; gap: 14px; }
.switch-row { display: flex; justify-content: space-between; gap: 16px; padding: 14px; border: 1px solid #e4ebf3; border-radius: 12px; background: #fbfdff; }
.switch-row p { margin: 4px 0 0; color: #667085; font-size: 13px; line-height: 1.5; }
.notice { margin-top: 14px; }
.dynamic-form { margin-top: 14px; }
.submit-btn { width: 100%; margin-top: 18px; }
@media (max-width: 980px) { .create-grid { grid-template-columns: 1fr; } }
@media (max-width: 720px) { .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>

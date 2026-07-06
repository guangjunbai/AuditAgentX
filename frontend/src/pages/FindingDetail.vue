<template>
  <section class="detail-page">
    <div class="page-title-row">
      <div>
        <p class="eyebrow">Finding</p>
        <h1>{{ detail?.type || "漏洞详情" }}</h1>
        <p v-if="detail">{{ detail.file }}:{{ detail.start_line }} · {{ detail.severity }}</p>
      </div>
      <el-button @click="router.back()">返回</el-button>
    </div>

    <el-card v-if="detail" shadow="never" class="panel-card">
      <el-descriptions :column="3" border>
        <el-descriptions-item label="类型">{{ detail.type }}</el-descriptions-item>
        <el-descriptions-item label="严重级">{{ detail.severity }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ detail.verification.status }}</el-descriptions-item>
        <el-descriptions-item label="文件位置">{{ detail.file }}:{{ detail.start_line }}</el-descriptions-item>
        <el-descriptions-item label="置信度">{{ detail.verification.confidence }}</el-descriptions-item>
        <el-descriptions-item label="已验证">{{ detail.verification.verified ? "是" : "否" }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card v-if="detail" shadow="never" class="panel-card">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="静态分析" name="static">
          <div class="tab-intro"><h2>静态代码证据</h2><p>展示漏洞位置、代码片段、source/sink 和修复建议。</p></div>
          <pre class="code-block"><code>{{ detail.vulnerable_code || "暂无代码片段" }}</code></pre>
          <el-descriptions :column="2" border class="evidence-desc">
            <el-descriptions-item label="Source">{{ detail.source || evidence?.source || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="Sink">{{ detail.sink || evidence?.sink || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="数据流" :span="2">
              <pre class="mini-pre">{{ JSON.stringify(detail.data_flow?.length ? detail.data_flow : evidence?.data_flow, null, 2) }}</pre>
            </el-descriptions-item>
            <el-descriptions-item label="修复建议" :span="2">{{ detail.fix_suggestion || "建议结合漏洞类型进行输入校验、参数化查询或最小权限加固。" }}</el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>

        <el-tab-pane label="动态分析" name="dynamic">
          <div class="tab-intro"><h2>动态验证</h2><p>仅对本地授权靶场发起验证请求，保存响应摘要和命中特征。</p></div>
          <div class="verify-panel">
            <el-input v-model="verifyForm.base_url" placeholder="http://127.0.0.1:8080" />
            <el-input v-model="verifyForm.endpoints" placeholder="/user,/search" />
            <el-button type="primary" :loading="verifying" @click="runVerify">执行动态验证</el-button>
          </div>
          <el-alert type="warning" show-icon :closable="false" title="动态验证仅限本地授权靶场，不要对真实第三方系统使用。" />
          <el-descriptions v-if="evidence?.runtime" :column="2" border class="evidence-desc">
            <el-descriptions-item label="验证结论">{{ evidence.runtime.reproducible ? "可复现" : "未复现" }}</el-descriptions-item>
            <el-descriptions-item label="命中特征">{{ evidence.runtime.matched_indicator || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="请求 URL">{{ evidence.runtime.request?.url || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="状态码">{{ evidence.runtime.response_status || "N/A" }}</el-descriptions-item>
            <el-descriptions-item label="Payload" :span="2"><code>{{ evidence.runtime.request?.payload || "N/A" }}</code></el-descriptions-item>
            <el-descriptions-item label="响应摘要" :span="2"><pre class="mini-pre">{{ evidence.runtime.response_excerpt || "N/A" }}</pre></el-descriptions-item>
          </el-descriptions>

          <div v-if="evidence?.harness" class="harness-block">
            <h3>Fuzzing Harness 动态验证（DeepAudit 式）</h3>
            <p class="harness-note">对目标函数 mock 危险 sink + 恶意 payload 隔离测试，跑通触发才判可利用。</p>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="验证结论">
                <el-tag :type="evidence.harness.dynamically_triggered ? 'success' : 'info'">
                  {{ verdictLabel(evidence.harness.verdict) }}
                </el-tag>
              </el-descriptions-item>
              <el-descriptions-item label="动态触发">{{ evidence.harness.dynamically_triggered ? "已触发" : "未触发" }}</el-descriptions-item>
              <el-descriptions-item label="执行后端">{{ evidence.harness.execution_backend || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="触发细节">{{ evidence.harness.trigger_detail || "N/A" }}</el-descriptions-item>
            </el-descriptions>
            <pre class="code-block"><code>{{ evidence.harness.harness_code || "暂无 Harness 代码" }}</code></pre>
          </div>

          <el-empty v-if="!evidence?.runtime && !evidence?.harness" description="暂无动态验证结果" />
        </el-tab-pane>

        <el-tab-pane label="可利用漏洞代码" name="exploit">
          <div class="tab-intro"><h2>可利用漏洞代码</h2><p>展示 ExploitAgent 生成的本地授权 PoC 骨架和利用路径。</p></div>
          <el-empty v-if="!evidence?.exploit" description="暂无利用代码，执行动态验证或启用 exploit 扫描后生成。" />
          <div v-else class="exploit-block">
            <el-descriptions :column="2" border>
              <el-descriptions-item label="触发位置">{{ evidence.exploit.trigger_location || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="攻击向量">{{ evidence.exploit.attack_vector || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="利用路径" :span="2">{{ evidence.exploit.exploit_path || "N/A" }}</el-descriptions-item>
              <el-descriptions-item label="验证方法" :span="2">{{ evidence.exploit.verification_method || "N/A" }}</el-descriptions-item>
            </el-descriptions>
            <pre class="code-block"><code>{{ evidence.exploit.exploit_code || "暂无代码" }}</code></pre>
          </div>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { FindingApi } from "../api";

const route = useRoute();
const router = useRouter();
const activeTab = ref("static");
const detail = ref<any>(null);
const evidence = ref<any>(null);
const verifying = ref(false);
const verifyForm = reactive({ base_url: "http://127.0.0.1:8080", endpoints: "/user", timeout: 10 });

const VERDICT_LABELS: Record<string, string> = {
  confirmed_dynamic: "动态确认可利用",
  not_reproduced: "未复现",
  inconclusive: "无法判定",
};
function verdictLabel(v: string) {
  return VERDICT_LABELS[v] || v || "N/A";
}

async function load() {
  const id = route.params.id as string;
  detail.value = (await FindingApi.detail(id)).data;
  evidence.value = (await FindingApi.evidence(id)).data.evidence;
}

async function runVerify() {
  const id = route.params.id as string;
  verifying.value = true;
  try {
    const endpoints = verifyForm.endpoints.split(",").map((item) => item.trim()).filter(Boolean);
    const { data } = await FindingApi.verify(id, { mode: "url", base_url: verifyForm.base_url, endpoints, timeout: verifyForm.timeout });
    ElMessage.success(data.reproducible ? "动态验证成功，漏洞可复现" : data.message);
    activeTab.value = data.reproducible ? "dynamic" : activeTab.value;
    await load();
  } finally {
    verifying.value = false;
  }
}

onMounted(load);
</script>

<style scoped>
.detail-page { display: flex; flex-direction: column; gap: 18px; }
.page-title-row { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; }
.page-title-row h1 { margin: 0; color: #162235; }
.page-title-row p { margin: 6px 0 0; color: #667085; }
.eyebrow { margin: 0; color: #2f80ed; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
.panel-card { border-radius: 16px; }
.tab-intro { margin-bottom: 16px; }
.tab-intro h2 { margin: 0; }
.tab-intro p { color: #667085; margin: 6px 0 0; }
.code-block { background: #101828; color: #d7e3f1; padding: 16px; border-radius: 12px; overflow: auto; }
.mini-pre { margin: 0; padding: 10px; background: #f6f8fa; border-radius: 8px; }
.evidence-desc { margin-top: 16px; }
.harness-block { margin-top: 20px; }
.harness-block h3 { margin: 0 0 4px; color: #162235; }
.harness-note { color: #667085; margin: 0 0 12px; font-size: 13px; }
.verify-panel { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; gap: 12px; margin-bottom: 14px; }
.exploit-block { display: grid; gap: 16px; }
@media (max-width: 760px) { .verify-panel { grid-template-columns: 1fr; } .page-title-row { align-items: flex-start; flex-direction: column; } }
</style>

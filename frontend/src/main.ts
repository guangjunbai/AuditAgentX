import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";
import App from "./App.vue";

import HomeView from "./pages/HomeView.vue";
import ProjectCreate from "./pages/ProjectCreate.vue";
import ScanDashboard from "./pages/ScanDashboard.vue";
import FindingDetail from "./pages/FindingDetail.vue";
import ReportView from "./pages/ReportView.vue";
import HistoryView from "./pages/HistoryView.vue";
import AnalyticsView from "./pages/AnalyticsView.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: HomeView },
    { path: "/projects/new", component: ProjectCreate },
    { path: "/scans", component: ScanDashboard },
    { path: "/findings/:id", component: FindingDetail },
    { path: "/reports/:scanId", component: ReportView },
    { path: "/history", component: HistoryView },
    { path: "/analytics", component: AnalyticsView },
  ],
});

createApp(App).use(router).use(ElementPlus).mount("#app");

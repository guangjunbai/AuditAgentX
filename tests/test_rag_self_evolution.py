"""RAG 自进化闭环测试（Q2）。

核心诚信保证：只有**独立可信标签**（人工 / 动态确认）才录入知识库；
Agent 自报 / needs_review 一律拒录，避免"循环自欺"把知识库喂脏。
学到的知识必须能被检索并合并进后续复核。
"""
import pytest

import backend.rag.retriever as R
from backend.rag import feedback_learner as FL


@pytest.fixture
def learned_dir(tmp_path, monkeypatch):
    """把 RAG 反馈目录重定向到临时目录，避免污染真实 data/。"""
    monkeypatch.setattr(R, "feedback_dir", lambda: tmp_path)
    R.load_default_items.cache_clear()
    yield tmp_path
    R.load_default_items.cache_clear()


def test_unreliable_labels_are_rejected(learned_dir):
    """防自我感动：Agent 自报 / needs_review / 未验证的判断一律不录入。"""
    f = {"type": "Command Injection", "evidence": {"source": "request.args", "sink": "os.system"}}
    assert FL.ingest_feedback(f, "true_positive", "agent_self_report") is False
    assert FL.ingest_feedback(f, "true_positive", "needs_review") is False
    assert FL.ingest_feedback(f, "true_positive", "llm_only") is False
    assert not (learned_dir / "learned_feedback.json").exists()


def test_reliable_true_positive_is_learned_and_retrievable(learned_dir):
    """可信动态确认的 TP 录入知识库，并能在后续检索中被合并进复核。"""
    f = _canonical_dynamic_finding("http_dynamic")
    assert FL.ingest_feedback(f, "true_positive", "dynamic_confirmed") is True
    assert (learned_dir / "learned_feedback.json").exists()

    R.load_default_items.cache_clear()
    res = R.SecurityKnowledgeRetriever().retrieve(candidate={"type": "Command Injection"})
    top = res["top_result"]
    assert top.get("learned_feedback_applied") is True
    assert any("确认的真实漏洞" in c for c in top.get("verification_checks", []))


def _canonical_dynamic_finding(method: str, *, status: str = "confirmed",
                               final_verdict: str = "dynamic_confirmed",
                               dynamically_verified: bool = True,
                               entrypoint_confirmed: bool = True) -> dict:
    return {
        "type": "Command Injection",
        "status": status,
        "evidence": {
            "source": "request.args.get(cmd)",
            "sink": "os.system",
            "verification": {
                "dynamically_verified": dynamically_verified,
                "entrypoint_confirmed": entrypoint_confirmed,
                "dynamic_method": method,
                "final_verdict": final_verdict,
            },
        },
    }


@pytest.mark.parametrize("method,final_verdict", [
    ("http_dynamic", "dynamic_confirmed"),
    ("target_harness", "harness_confirmed"),
])
def test_canonical_http_and_target_harness_confirmations_enter_rag(
        learned_dir, method, final_verdict):
    """Only endpoint-confirmed HTTP and target-entrypoint Harness results may teach RAG."""
    finding = _canonical_dynamic_finding(method, final_verdict=final_verdict)

    assert FL.is_canonical_dynamic_confirmation(finding) is True
    assert FL.ingest_dynamic_confirmation(finding) is True
    assert (learned_dir / "learned_feedback.json").exists()


@pytest.mark.parametrize("finding", [
    _canonical_dynamic_finding("http_dynamic", status="false_positive"),
    _canonical_dynamic_finding("function_harness", final_verdict="needs_review"),
    _canonical_dynamic_finding("static_confirmation", final_verdict="statically_verified",
                               dynamically_verified=False),
    _canonical_dynamic_finding("target_harness", final_verdict="needs_review",
                               dynamically_verified=False),
    _canonical_dynamic_finding("http_dynamic", final_verdict="needs_review",
                               entrypoint_confirmed=False),
], ids=["false-positive", "function-only", "static-only", "mechanism-only", "blocked"])
def test_static_function_mechanism_and_blocked_results_never_enter_rag(learned_dir, finding):
    """The gate rejects non-confirmed, function-only, static-only, mechanism, and blocked evidence."""
    assert FL.is_canonical_dynamic_confirmation(finding) is False
    assert FL.ingest_dynamic_confirmation(finding) is False
    assert not (learned_dir / "learned_feedback.json").exists()


def test_reliable_false_positive_signal_is_merged_into_verification(learned_dir):
    """可信误报作为 false_positive_signal 录入，后续复核能拿到 -> 越用越少误报。"""
    fp = {"type": "SQL Injection", "status": "false_positive",
          "false_positive_reason": "使用了参数化查询", "context": "test_fixture",
          "evidence": {"sink": "cursor.execute"}}
    assert FL.ingest_feedback(fp, "false_positive", "verify_false_positive") is False
    assert FL.ingest_feedback(fp, "false_positive", "human") is True

    R.load_default_items.cache_clear()
    res = R.SecurityKnowledgeRetriever().retrieve(candidate={"type": "SQL Injection"})
    signals = res["top_result"].get("false_positive_signals", [])
    assert any("参数化查询" in s for s in signals)


def test_learn_from_scan_only_ingests_reliable_results(learned_dir):
    """扫描自进化：只从动态确认(TP)/明确误报(FP)学，needs_review/unverified 不学。"""
    findings = [
        {**_canonical_dynamic_finding("http_dynamic"), "type": "XSS"},
        {"type": "Open Redirect", "status": "confirmed", "dynamically_verified": True,
         "evidence": {"verification": {"final_verdict": "statically_verified"}}},
        {"type": "SSRF", "status": "needs_review"},          # 不该学
        {"type": "IDOR", "status": "unverified"},             # 不该学
        {"type": "Path Traversal", "status": "false_positive",
         "false_positive_reason": "secure_filename 已净化"},
    ]
    counts = FL.learn_from_scan(findings)
    assert counts["true_positive_ingested"] == 1
    assert counts["false_positive_ingested"] == 0

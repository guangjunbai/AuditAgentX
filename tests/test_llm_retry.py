"""LLM 调用健壮性测试（重试 / 不可重试 / json 降级），全部 mock，不触网。"""
import pytest

from backend.core.llm_client import LLMClient


class _FakeResp:
    def __init__(self, text):
        self.choices = [type("C", (), {"message": type("M", (), {"content": text})()})()]


class _FakeCompletions:
    def __init__(self, script):
        self.script = script          # 列表：每次调用弹一个；Exception 则抛，str 则返回
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return _FakeResp(item)


class _FakeClient:
    def __init__(self, script):
        self.chat = type("Chat", (), {"completions": _FakeCompletions(script)})()


def _client_with(script, monkeypatch):
    llm = LLMClient()
    fake = _FakeClient(script)
    monkeypatch.setattr(llm, "_get_client", lambda: fake)
    # 加速：退避设 0
    monkeypatch.setattr("backend.core.llm_client.settings.llm_retry_backoff", 0.0)
    monkeypatch.setattr("backend.core.llm_client.settings.llm_max_retries", 2)
    return llm, fake


def test_retries_then_succeeds(monkeypatch):
    llm, fake = _client_with([RuntimeError("temporary 500"), '{"ok": true}'], monkeypatch)
    out = llm.chat("sys", "user")
    assert out == '{"ok": true}'
    assert len(fake.chat.completions.calls) == 2   # 第一次失败 + 第二次成功


def test_auth_error_not_retried(monkeypatch):
    llm, fake = _client_with([RuntimeError("Error code: 403 - usage limit exceeded")], monkeypatch)
    with pytest.raises(RuntimeError):
        llm.chat("sys", "user")
    assert len(fake.chat.completions.calls) == 1   # 鉴权/额度错误不重试


def test_json_mode_downgrade(monkeypatch):
    # 第一次因 response_format 报错 -> 降级普通模式成功
    llm, fake = _client_with([RuntimeError("response_format not supported"), "plain text"], monkeypatch)
    out = llm.chat("sys", "user", json_mode=True)
    assert out == "plain text"
    calls = fake.chat.completions.calls
    assert "response_format" in calls[0]           # 第一次带 json
    assert "response_format" not in calls[1]        # 第二次降级去掉


def test_exhausts_retries_then_raises(monkeypatch):
    llm, fake = _client_with([RuntimeError("boom"), RuntimeError("boom"), RuntimeError("boom")], monkeypatch)
    with pytest.raises(RuntimeError):
        llm.chat("sys", "user")
    assert len(fake.chat.completions.calls) == 3   # 1 + 2 retries

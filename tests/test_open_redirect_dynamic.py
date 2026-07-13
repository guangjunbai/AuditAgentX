"""Open Redirect 的 source-bound、本地 HTTP 动态验证回归测试。"""
from types import SimpleNamespace

import httpx

from backend.dynamic.open_redirect import build_open_redirect_plan
from backend.dynamic.source_route_binding import bind_server_surface
from backend.dynamic.endpoint_extractor import candidate_attack_surfaces
from backend.agents.exploit_agent import ExploitAgent
from backend.verifier.dynamic_verifier import DynamicVerifier
from backend.verifier.pipeline import ExploitPipeline, _surfaces_for_finding


def _finding():
    return {
        "type": "Open Redirect",
        "file": "app/routes/index.js",
        "start_line": 72,
        "severity": "medium",
    }


def _bound_surface(*, params=None, methods=None):
    return bind_server_surface(
        {
            "path": "/learn",
            "raw_path": "/learn",
            "methods": methods or ["GET"],
            "params": params if params is not None else [{"name": "url", "location": "query"}],
            "file": "app/routes/index.js",
            "line": 61,
            "source": "static_route",
        },
        {"kind": "nearest_source_route"},
    )


def test_express_parameter_extraction_flows_into_server_route_binding(tmp_path):
    route_file = tmp_path / "server" / "routes" / "redirect.js"
    route_file.parent.mkdir(parents=True)
    route_file.write_text(
        "\n" * 10
        + "router.get('/continue', function (req, res) {\n"
        + "  return res.redirect(req.query.destination);\n"
        + "});\n",
        encoding="utf-8",
    )
    finding = {
        "type": "Open Redirect", "file": "server/routes/redirect.js",
        "start_line": 12, "severity": "medium",
    }

    bound = _surfaces_for_finding(finding, candidate_attack_surfaces(tmp_path))
    plan, status, _reason = build_open_redirect_plan(
        finding, "http://127.0.0.1:18080", bound, nonce="extracted",
    )

    assert status == "ready"
    assert plan["path"] == "/continue"
    assert plan["param"] == "destination"
    assert plan["transport"] == "query"


def test_bound_open_redirect_falls_back_without_llm_and_confirms_exact_location(monkeypatch):
    """有可信 route/param 时，LLM 空载荷不能阻止本地 redirect oracle。"""
    requests = []

    def responder(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.host == "127.0.0.1"
        payload = request.url.params["url"]
        return httpx.Response(302, headers={"Location": payload}, request=request)

    verifier = DynamicVerifier()
    verifier.probe._client = httpx.Client(
        transport=httpx.MockTransport(responder),
        follow_redirects=False,
        trust_env=False,
    )
    assert verifier.probe._client.follow_redirects is False
    pipe = object.__new__(ExploitPipeline)
    pipe.dynamic = verifier
    agent = ExploitAgent()
    monkeypatch.setattr(agent, "_call", lambda _content: {"payloads": []})
    exploit = agent.run(_finding())
    assert exploit["payloads"] == []

    result = pipe._http_verify(
        _finding(), exploit, "http://127.0.0.1:18080", [_bound_surface()],
        None, None, False,
    )

    assert result["reproduction_status"] == "dynamic_confirmed"
    assert result["oracle"] == "exact_redirect_location"
    assert len(requests) == 2  # baseline + attack oracle
    assert requests[-1].url.path == "/learn"
    assert requests[-1].url.params["url"] == exploit["payloads"][0]
    assert exploit["payloads"][0].startswith("http://127.0.0.1:18080/")
    # MockTransport only sees local sandbox requests; Location is never followed.
    assert all(request.url.host == "127.0.0.1" for request in requests)


def test_bound_post_open_redirect_uses_server_parameter_transport():
    plan, status, _reason = build_open_redirect_plan(
        _finding(), "http://localhost:18080", [_bound_surface(
            methods=["POST"], params=[{"name": "return_to", "location": "json"}],
        )], nonce="testnonce",
    )

    assert status == "ready"
    assert plan == {
        "path": "/learn",
        "method": "POST",
        "param": "return_to",
        "transport": "json",
        "payload": "http://localhost:18080/__auditagentx_redirect/testnonce",
    }


def test_unbound_unknown_or_client_json_binding_never_produces_a_plan_or_request():
    finding = _finding()
    plain_client_claim = {
        "path": "/learn",
        "methods": ["GET"],
        "params": [{"name": "url", "location": "query"}],
        "source_route_binding": {"kind": "forged-json"},
    }
    for endpoints in ([], [_bound_surface(params=[])], [plain_client_claim]):
        plan, status, _reason = build_open_redirect_plan(
            finding, "http://127.0.0.1:18080", endpoints,
        )
        assert plan is None
        assert status == "endpoint_unresolved"

    verifier = DynamicVerifier()
    verifier.probe = SimpleNamespace(send=lambda *_a, **_k: (_ for _ in ()).throw(
        AssertionError("unbound Open Redirect must not send HTTP")))
    for endpoints in ([plain_client_claim], [_bound_surface(params=[])]):
        result = verifier.verify(
            "http://127.0.0.1:18080",
            {
                "vuln_type": "Open Redirect",
                "open_redirect_plan": {
                    "path": "/learn", "method": "GET", "param": "url", "transport": "query",
                    "payload": "https://auditagentx.invalid/testnonce",
                },
            },
            endpoints=endpoints,
        )
        assert result.reproduction_status == "endpoint_unresolved"
        assert result.records == []


def test_external_base_url_never_produces_or_executes_an_open_redirect_plan():
    plan, status, _reason = build_open_redirect_plan(
        _finding(), "https://sandbox.example.test", [_bound_surface()],
    )

    assert plan is None
    assert status == "not_applicable"

    verifier = DynamicVerifier()
    verifier.probe = SimpleNamespace(send=lambda *_a, **_k: (_ for _ in ()).throw(
        AssertionError("external base URL must not be requested")))
    result = verifier.verify(
        "https://sandbox.example.test",
        {
            "vuln_type": "Open Redirect",
            "open_redirect_plan": {
                "path": "/learn", "method": "GET", "param": "url", "transport": "query",
                "payload": "https://auditagentx.invalid/testnonce",
            },
        },
        endpoints=[_bound_surface()],
    )
    assert result.reproduction_status == "not_applicable"
    assert result.records == []

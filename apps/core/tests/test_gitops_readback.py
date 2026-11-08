from __future__ import annotations

import base64
import hashlib
from typing import Any

import httpx
import pytest
from nope_core.gitops import GitHubUnavailable, verify_merged_rule

RULE = b"rules: []\n"


@pytest.mark.parametrize("response_kind", ["exact", "changed", "forbidden", "malformed"])
def test_readback_requires_exact_rule_at_exact_merge_commit(
    response_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[httpx.Request] = []

    def reply(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.url.host == "api.github.com"
        assert request.url.path == "/repos/acme/service/contents/config/.semgrep/nope-active.yml"
        assert request.url.params["ref"] == "a" * 40
        assert request.headers["authorization"] == "Bearer test-readonly-token"
        if response_kind == "forbidden":
            return httpx.Response(403)
        if response_kind == "malformed":
            return httpx.Response(200, json={"encoding": "none", "content": ""})
        content = RULE if response_kind == "exact" else b"different rule"
        return httpx.Response(200, json={"type": "file", "encoding": "base64",
                                        "content": base64.b64encode(content).decode("ascii")})

    factory = httpx.Client
    monkeypatch.setattr("nope_core.gitops.httpx.Client",
                        lambda **kw: factory(transport=httpx.MockTransport(reply), **kw))
    monkeypatch.setenv("GITHUB_TOKEN", "test-readonly-token")
    expected = hashlib.sha256(RULE).hexdigest()
    if response_kind == "exact":
        verify_merged_rule("acme/service", "a" * 40, expected)
    else:
        error: type[Exception] = GitHubUnavailable if response_kind == "forbidden" else ValueError
        with pytest.raises(error):
            verify_merged_rule("acme/service", "a" * 40, expected)
    assert len(requests) == 1


@pytest.mark.parametrize("payload", ["", "not policy", "[]", "unexpected: []", "rules: invalid"])
def test_sync_preserves_existing_policy_on_invalid_response(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    from nope_core.cli import sync_rules_to_file, verify_rules_sync

    output = tmp_path / "active.yml"
    output.write_text("rules: []\n", encoding="utf-8")
    factory = httpx.Client
    monkeypatch.setattr("nope_core.cli.httpx.Client", lambda **kw: factory(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=payload)), **kw))
    assert sync_rules_to_file(output, base_url="https://core.example") == 1
    assert verify_rules_sync(output, base_url="https://core.example") == 1
    assert output.read_text(encoding="utf-8") == "rules: []\n"

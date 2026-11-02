"""Tests for the LLM layer. No real network: every adapter uses httpx.MockTransport."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, Field
from typer.testing import CliRunner

from kalkan.cli import app
from kalkan.llm import (
    Budget,
    BudgetedProvider,
    BudgetExceeded,
    ConfigError,
    FakeProvider,
    LLMResponse,
    ProviderError,
    ProviderHTTPError,
    ProviderRefusal,
    build_provider,
    complete_json,
    resolve_settings,
)
from kalkan.llm.anthropic import AnthropicProvider
from kalkan.llm.config import parse_model_spec
from kalkan.llm.json_output import extract_json_object
from kalkan.llm.openai_compat import OpenAICompatProvider

SECRET = "sk-test-SECRET-key-123456789"
runner = CliRunner()


def _no_sleep(_: float) -> None:
    return None


def _anthropic_ok(text: str = "pong") -> dict[str, Any]:
    return {
        "model": "claude-opus-5-5",
        "stop_reason": "end_turn",
        "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": text}],
        "usage": {"input_tokens": 12, "output_tokens": 3},
    }


# ----- Anthropic --------------------------------------------------------------------------------


def test_anthropic_request_and_response() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_anthropic_ok())

    provider = AnthropicProvider(SECRET, "claude-opus-5-5", transport=httpx.MockTransport(handler))
    result = provider.complete("sys", "hello", max_tokens=100)
    assert result == LLMResponse(
        text="pong", input_tokens=12, output_tokens=3, model="claude-opus-5-5"
    )

    request = seen[0]
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == SECRET
    assert request.headers["anthropic-version"] == "2023-06-01"
    body = json.loads(request.content)
    assert body["system"] == "sys"
    assert body["messages"] == [{"role": "user", "content": "hello"}]
    assert "temperature" not in body
    assert body["fallbacks"] == "default"
    assert request.headers["anthropic-beta"] == "server-side-fallback-2026-07-01"


def test_anthropic_no_fallbacks_for_other_models() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_anthropic_ok())

    AnthropicProvider(SECRET, "claude-haiku-5-5", transport=httpx.MockTransport(handler)).complete(
        "s", "u", max_tokens=10
    )
    assert "fallbacks" not in json.loads(seen[0].content)
    assert "anthropic-beta" not in seen[0].headers


def test_anthropic_refusal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={**_anthropic_ok(), "stop_reason": "refusal"})

    provider = AnthropicProvider(SECRET, "claude-opus-5-5", transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderRefusal):
        provider.complete("s", "u", max_tokens=10)


def test_retries_on_429_and_5xx_then_succeeds() -> None:
    statuses = iter([429, 503, 200])
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        status = next(statuses)
        if status == 200:
            return httpx.Response(200, json=_anthropic_ok())
        return httpx.Response(
            status, headers={"retry-after": "1"}, json={"error": {"message": "busy"}}
        )

    provider = AnthropicProvider(
        SECRET, "m", transport=httpx.MockTransport(handler), sleep=delays.append
    )
    assert provider.complete("s", "u", max_tokens=10).text == "pong"
    assert delays == [1.0, 1.0]


def test_gives_up_after_retries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": {"message": "down"}})

    provider = AnthropicProvider(
        SECRET, "m", transport=httpx.MockTransport(handler), sleep=_no_sleep
    )
    with pytest.raises(ProviderHTTPError) as info:
        provider.complete("s", "u", max_tokens=10)
    assert info.value.status == 500


def test_errors_never_contain_the_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": f"invalid x-api-key {SECRET}"}})

    provider = AnthropicProvider(SECRET, "m", transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderHTTPError) as info:
        provider.complete("s", "u", max_tokens=10)
    assert SECRET not in str(info.value)
    assert "[REDACTED]" in str(info.value)
    assert SECRET not in repr(provider)


def test_network_error_is_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    provider = AnthropicProvider(
        SECRET, "m", transport=httpx.MockTransport(handler), sleep=_no_sleep
    )
    with pytest.raises(ProviderError, match="network error"):
        provider.complete("s", "u", max_tokens=10)


# ----- OpenAI-compatible ------------------------------------------------------------------------


def _chat_ok(text: str = "pong") -> dict[str, Any]:
    return {
        "model": "qwen2.5-coder:7b",
        "choices": [{"message": {"role": "assistant", "content": text}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 5},
    }


def test_openai_compat_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_chat_ok())

    provider = OpenAICompatProvider(
        "https://api.openai.com/v1/",
        "gpt-x",
        api_key=SECRET,
        transport=httpx.MockTransport(handler),
    )
    result = provider.complete("sys", "hi", max_tokens=50)
    assert result.text == "pong" and result.input_tokens == 20 and result.output_tokens == 5
    request = seen[0]
    assert str(request.url) == "https://api.openai.com/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {SECRET}"
    body = json.loads(request.content)
    assert body["temperature"] == 0
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert "response_format" not in body


def test_ollama_has_no_auth_header_and_uses_json_mode() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_chat_ok("{}"))

    provider = OpenAICompatProvider(
        "http://localhost:11434/v1", "qwen", name="ollama", transport=httpx.MockTransport(handler)
    )
    provider.complete("s", "u", max_tokens=10, json_schema={"type": "object"})
    assert "authorization" not in seen[0].headers
    assert json.loads(seen[0].content)["response_format"] == {"type": "json_object"}


def test_json_mode_falls_back_when_unsupported() -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        bodies.append(body)
        if "response_format" in body:
            return httpx.Response(400, json={"error": {"message": "response_format unsupported"}})
        return httpx.Response(200, json=_chat_ok("{}"))

    provider = OpenAICompatProvider("http://x/v1", "m", transport=httpx.MockTransport(handler))
    provider.complete("s", "u", max_tokens=10, json_schema={"type": "object"})
    provider.complete("s", "u", max_tokens=10, json_schema={"type": "object"})
    assert ["response_format" in b for b in bodies] == [True, False, False]


def test_openai_bad_shape() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"nope": 1})

    provider = OpenAICompatProvider("http://x/v1", "m", transport=httpx.MockTransport(handler))
    with pytest.raises(ProviderError):
        provider.complete("s", "u", max_tokens=10)


# ----- config -----------------------------------------------------------------------------------


def test_parse_model_spec_splits_on_first_colon() -> None:
    assert parse_model_spec("ollama:qwen2.5-coder:7b") == ("ollama", "qwen2.5-coder:7b")
    assert parse_model_spec("anthropic:claude-opus-5-5") == ("anthropic", "claude-opus-5-5")


@pytest.mark.parametrize("spec", ["qwen", "nope:model", "ollama:"])
def test_bad_model_specs(spec: str) -> None:
    with pytest.raises(ConfigError):
        parse_model_spec(spec)


def test_no_model_means_ai_off() -> None:
    assert resolve_settings(env={}) is None


def test_resolve_settings() -> None:
    env = {"KALKAN_MODEL": "ollama:qwen2.5-coder:7b"}
    s = resolve_settings(env=env)
    assert s is not None
    assert (s.provider, s.model, s.base_url) == (
        "ollama",
        "qwen2.5-coder:7b",
        "http://localhost:11434/v1",
    )

    s = resolve_settings(
        env={"KALKAN_MODEL": "anthropic:claude-opus-5-5", "ANTHROPIC_API_KEY": SECRET}
    )
    assert s is not None and s.api_key == SECRET
    assert SECRET not in repr(s) and SECRET not in s.describe()

    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        resolve_settings(env={"KALKAN_MODEL": "anthropic:x"})
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        resolve_settings(env={"KALKAN_MODEL": "openai:x"})
    with pytest.raises(ConfigError, match="base URL"):
        resolve_settings(env={"KALKAN_MODEL": "compat:x"})


def test_flags_override_env() -> None:
    env = {"KALKAN_MODEL": "ollama:a", "KALKAN_BASE_URL": "http://env/v1", "KALKAN_API_KEY": "k"}
    s = resolve_settings("compat:b", "http://flag/v1", env=env)
    assert s is not None
    assert (s.provider, s.model, s.base_url, s.api_key) == ("compat", "b", "http://flag/v1", "k")


def test_build_provider_types() -> None:
    a = resolve_settings(env={"KALKAN_MODEL": "anthropic:m", "ANTHROPIC_API_KEY": "k"})
    o = resolve_settings(env={"KALKAN_MODEL": "ollama:m"})
    assert a is not None and o is not None
    assert isinstance(build_provider(a), AnthropicProvider)
    provider = build_provider(o)
    assert isinstance(provider, OpenAICompatProvider) and provider.name == "ollama"


# ----- budget -----------------------------------------------------------------------------------


def test_budget_stops_when_reached() -> None:
    fake = FakeProvider(script=["a", "b", "c"], tokens_per_call=100)
    budget = Budget(max_tokens=150)
    provider = BudgetedProvider(fake, budget)
    provider.complete("s", "u", max_tokens=10)
    provider.complete("s", "u", max_tokens=10)
    assert budget.used == 200
    with pytest.raises(BudgetExceeded):
        provider.complete("s", "u", max_tokens=10)
    assert len(fake.calls) == 2


def test_budget_from_env_and_prices() -> None:
    budget = Budget.from_env(env={"KALKAN_MAX_TOKENS": "1000"})
    assert budget.max_tokens == 1000 and budget.cost_usd() is None
    priced = Budget.from_env(env={"KALKAN_PRICE_INPUT": "2", "KALKAN_PRICE_OUTPUT": "10"})
    assert priced.max_tokens == 60_000
    priced.charge(LLMResponse("x", input_tokens=1_000_000, output_tokens=100_000, model="m"))
    assert priced.cost_usd() == pytest.approx(3.0)


# ----- JSON output ------------------------------------------------------------------------------


class _Answer(BaseModel):
    verdict: str
    confidence: float = Field(ge=0, le=1)


def test_complete_json_happy_path() -> None:
    fake = FakeProvider(script=['Sure! ```json\n{"verdict": "ok", "confidence": 0.5}\n```'])
    answer, problems = complete_json(fake, "sys", "user", _Answer)
    assert answer == _Answer(verdict="ok", confidence=0.5)
    assert problems == []
    assert "JSON Schema" in fake.calls[0].system
    assert fake.calls[0].json_schema is not None


def test_complete_json_repairs_once() -> None:
    fake = FakeProvider(script=["not json at all", '{"verdict": "ok", "confidence": 0.9}'])
    answer, problems = complete_json(fake, "sys", "user", _Answer)
    assert answer is not None and answer.confidence == 0.9
    assert len(problems) == 1
    assert "not valid" in fake.calls[1].user


def test_complete_json_gives_up_after_repair() -> None:
    fake = FakeProvider(script=['{"verdict": "ok", "confidence": 7}', "{broken"])
    answer, problems = complete_json(fake, "sys", "user", _Answer)
    assert answer is None
    assert len(problems) == 2


def test_extract_json_object_skips_braces_in_prose() -> None:
    assert extract_json_object('use {braces} then {"a": 1}') == {"a": 1}
    with pytest.raises(ValueError):
        extract_json_object("nothing here")


# ----- doctor -----------------------------------------------------------------------------------


def test_doctor_without_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KALKAN_MODEL", raising=False)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "no-ai" in result.output


def test_doctor_bad_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("KALKAN_API_KEY", raising=False)
    result = runner.invoke(app, ["doctor", "--model", "anthropic:x"])
    assert result.exit_code == 2


def test_doctor_unreachable_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kalkan.llm.base.time.sleep", _no_sleep)
    result = runner.invoke(
        app, ["doctor", "--model", "compat:m", "--base-url", "http://127.0.0.1:9/v1"]
    )
    assert result.exit_code == 3
    assert "provider check failed" in result.output

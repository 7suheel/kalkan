"""Anthropic Messages API adapter (plain httpx, no SDK)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from kalkan.llm.base import (
    DEFAULT_TIMEOUT_S,
    LLMResponse,
    ProviderError,
    ProviderRefusal,
    as_dict,
    post_json,
)

ANTHROPIC_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models that accept server-side refusal fallbacks ("fallbacks": "default").
FALLBACK_MODELS = frozenset(
    {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
)


class AnthropicProvider:
    """Calls ``POST /v1/messages``.

    No sampling parameters are sent: current Claude models reject
    ``temperature``. Thinking blocks in the response are ignored; only text
    blocks are returned.
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        base_url: str = ANTHROPIC_BASE_URL,
        use_fallbacks: bool = True,
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._url = base_url.rstrip("/") + "/v1/messages"
        self._use_fallbacks = use_fallbacks and model in FALLBACK_MODELS
        self._client = httpx.Client(transport=transport, timeout=timeout)
        self._sleep = sleep or time.sleep

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self.model!r})"

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Send one request and return the concatenated text blocks."""
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self._use_fallbacks:
            headers["anthropic-beta"] = FALLBACK_BETA
            payload["fallbacks"] = "default"
        data = post_json(
            self._client, self._url, headers=headers, payload=payload, sleep=self._sleep
        )
        return _parse(data, self.model)


def _parse(data: dict[str, Any], requested_model: str) -> LLMResponse:
    if data.get("stop_reason") == "refusal":
        raise ProviderRefusal("the model declined to answer this request")
    content = data.get("content")
    if not isinstance(content, list):
        raise ProviderError("unexpected response: no content list")
    text = "".join(
        block.get("text", "")
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    )
    usage = as_dict(data.get("usage"))
    return LLMResponse(
        text=text,
        input_tokens=int(usage.get("input_tokens") or 0)
        + int(usage.get("cache_read_input_tokens") or 0)
        + int(usage.get("cache_creation_input_tokens") or 0),
        output_tokens=int(usage.get("output_tokens") or 0),
        model=str(data.get("model") or requested_model),
    )

"""OpenAI-compatible Chat Completions adapter.

Covers OpenAI, Ollama (``http://localhost:11434/v1``), OpenRouter and any
other endpoint that speaks ``POST /chat/completions``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from kalkan.llm.base import (
    DEFAULT_TIMEOUT_S,
    LLMResponse,
    ProviderError,
    ProviderHTTPError,
    ProviderRefusal,
    as_dict,
    check_endpoint,
    post_json,
)


class OpenAICompatProvider:
    """Calls ``POST {base_url}/chat/completions`` with temperature 0."""

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key: str | None = None,
        name: str = "compat",
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT_S,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self._api_key = api_key
        self._url = base_url.rstrip("/") + "/chat/completions"
        check_endpoint(base_url, has_key=bool(api_key))
        self._client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=False)
        self._sleep = sleep or time.sleep
        self._json_mode = True

    def __repr__(self) -> str:
        return f"OpenAICompatProvider(name={self.name!r}, model={self.model!r})"

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Send one request. Asks for JSON mode when a schema is given."""
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_schema is not None and self._json_mode:
            try:
                data = post_json(
                    self._client,
                    self._url,
                    headers=headers,
                    payload={**payload, "response_format": {"type": "json_object"}},
                    sleep=self._sleep,
                )
                return _parse(data, self.model)
            except ProviderHTTPError as exc:
                if exc.status != 400:
                    raise
                # Endpoint does not support JSON mode; ask in the prompt only.
                self._json_mode = False
        data = post_json(
            self._client, self._url, headers=headers, payload=payload, sleep=self._sleep
        )
        return _parse(data, self.model)


def _parse(data: dict[str, Any], requested_model: str) -> LLMResponse:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ProviderError("unexpected response: no choices")
    choice = choices[0]
    message = as_dict(choice.get("message"))
    if message.get("refusal"):
        raise ProviderRefusal("the model declined to answer this request")
    text = message.get("content")
    usage = as_dict(data.get("usage"))
    return LLMResponse(
        text=text if isinstance(text, str) else "",
        input_tokens=int(usage.get("prompt_tokens") or 0),
        output_tokens=int(usage.get("completion_tokens") or 0),
        model=str(data.get("model") or requested_model),
    )

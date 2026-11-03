"""Provider protocol, shared errors and the retrying HTTP helper.

Adapters talk to providers with plain httpx. Errors never include request
headers, so API keys cannot leak into messages or logs.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx

DEFAULT_TIMEOUT_S = 60.0
MAX_RETRIES = 3
_RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
_SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_\-]{8,}|Bearer\s+[A-Za-z0-9._\-]{8,})")


class ProviderError(RuntimeError):
    """Any failure while talking to an LLM provider."""


class ProviderHTTPError(ProviderError):
    """The provider answered with an error status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class ProviderRefusal(ProviderError):
    """The model declined to answer."""


class BudgetExceeded(ProviderError):
    """The per-run token budget is used up."""


class ConfigError(ValueError):
    """The LLM configuration is invalid (unknown provider, missing key...)."""


@dataclass(frozen=True)
class LLMResponse:
    """A completed model response."""

    text: str
    input_tokens: int
    output_tokens: int
    model: str

    @property
    def total_tokens(self) -> int:
        """Input plus output tokens."""
        return self.input_tokens + self.output_tokens


@runtime_checkable
class Provider(Protocol):
    """Anything that can complete a system + user prompt."""

    name: str
    model: str

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Return the model's answer to ``user`` under ``system`` instructions."""
        ...


def check_endpoint(url: str, has_key: bool) -> None:
    """Refuse endpoints that would leak a key: plain http to a remote host, or userinfo."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("invalid base URL; use http(s)://host/...")
    if parts.username or parts.password:
        raise ConfigError("put credentials in an API key variable, not in the base URL")
    host = parts.hostname
    local = host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
    if has_key and parts.scheme == "http" and not local:
        raise ConfigError("refusing to send an API key over plain http to a remote host")


def as_dict(value: object) -> dict[str, Any]:
    """Return ``value`` if it is a dict, else an empty dict (for loose JSON parsing)."""
    return value if isinstance(value, dict) else {}


def redact(text: str) -> str:
    """Remove anything that looks like an API key or bearer token."""
    return _SECRET_RE.sub("[REDACTED]", text)


def _error_message(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return redact(response.text[:200])
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return redact(err["message"][:300])
        if isinstance(err, str):
            return redact(err[:300])
    return redact(str(data)[:200])


def post_json(
    client: httpx.Client,
    url: str,
    *,
    headers: dict[str, str],
    payload: dict[str, Any],
    sleep: Callable[[float], None] = time.sleep,
    max_retries: int = MAX_RETRIES,
) -> dict[str, Any]:
    """POST JSON with retries and exponential backoff on 429/5xx and network errors."""
    attempt = 0
    while True:
        try:
            response = client.post(url, headers=headers, json=payload)
        except httpx.TransportError as exc:
            if attempt >= max_retries:
                raise ProviderError(f"network error: {type(exc).__name__}") from None
            sleep(min(2.0**attempt, 30.0))
            attempt += 1
            continue
        if response.status_code in _RETRY_STATUSES and attempt < max_retries:
            sleep(_retry_delay(response, attempt))
            attempt += 1
            continue
        if response.status_code >= 300:
            # Redirects are never followed: they could carry the API key to another host.
            raise ProviderHTTPError(response.status_code, _error_message(response))
        try:
            data = response.json()
        except ValueError:
            raise ProviderError("provider returned a non-JSON response") from None
        if not isinstance(data, dict):
            raise ProviderError("provider returned an unexpected JSON shape")
        return data


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    retry_after = response.headers.get("retry-after", "")
    try:
        return min(max(float(retry_after), 0.0), 60.0)
    except ValueError:
        return min(2.0**attempt, 30.0)

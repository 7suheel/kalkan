"""Turn ``KALKAN_MODEL`` (or ``--model``) into a provider.

Model specs look like ``ollama:qwen2.5-coder:7b``, ``anthropic:<model-id>``,
``openai:<model-id>`` or ``compat:<model-id>``; only the first colon splits
the provider from the model. If nothing is set, AI is off and Kalkan runs
in no-AI mode.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from kalkan.llm.anthropic import ANTHROPIC_BASE_URL, AnthropicProvider
from kalkan.llm.base import ConfigError, Provider
from kalkan.llm.openai_compat import OpenAICompatProvider

PROVIDERS = ("anthropic", "openai", "ollama", "compat")
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OPENAI_BASE_URL = "https://api.openai.com/v1"
NO_AI_MESSAGE = (
    "AI off: no model configured (set KALKAN_MODEL or pass --model). "
    "Running deterministic checks only (--no-ai mode)."
)


@dataclass(frozen=True)
class LLMSettings:
    """Resolved provider settings. ``api_key`` is never printed."""

    provider: str
    model: str
    base_url: str | None = None
    api_key: str | None = None

    def describe(self) -> str:
        """Human-readable summary without secrets."""
        where = f" at {self.base_url}" if self.base_url else ""
        return f"{self.provider}:{self.model}{where}"

    def __repr__(self) -> str:
        key = "set" if self.api_key else "unset"
        return f"LLMSettings(provider={self.provider!r}, model={self.model!r}, api_key={key})"


def parse_model_spec(spec: str) -> tuple[str, str]:
    """Split ``provider:model`` on the first colon only."""
    provider, sep, model = spec.strip().partition(":")
    provider = provider.lower()
    if not sep or not model:
        raise ConfigError(
            f"invalid model spec {spec!r}; use provider:model, e.g. ollama:qwen2.5-coder:7b"
        )
    if provider not in PROVIDERS:
        raise ConfigError(f"unknown provider {provider!r}; choose one of {', '.join(PROVIDERS)}")
    return provider, model


def resolve_settings(
    model: str | None = None,
    base_url: str | None = None,
    env: Mapping[str, str] | None = None,
) -> LLMSettings | None:
    """Resolve settings from flags (which win) and environment variables.

    Returns None when no model is configured, which means AI is off.
    """
    env = os.environ if env is None else env
    spec = model or env.get("KALKAN_MODEL", "").strip()
    if not spec:
        return None
    provider, model_id = parse_model_spec(spec)
    url = base_url or env.get("KALKAN_BASE_URL") or None
    key = env.get("KALKAN_API_KEY") or None

    if provider == "anthropic":
        key = env.get("ANTHROPIC_API_KEY") or key
        if not key:
            raise ConfigError("anthropic needs ANTHROPIC_API_KEY")
        return LLMSettings(provider, model_id, url or ANTHROPIC_BASE_URL, key)
    if provider == "openai":
        key = env.get("OPENAI_API_KEY") or key
        if not key:
            raise ConfigError("openai needs OPENAI_API_KEY")
        return LLMSettings(provider, model_id, url or OPENAI_BASE_URL, key)
    if provider == "ollama":
        return LLMSettings(provider, model_id, url or OLLAMA_BASE_URL, key)
    if not url:
        raise ConfigError("compat needs a base URL (KALKAN_BASE_URL or --base-url)")
    return LLMSettings(provider, model_id, url, key)


def build_provider(settings: LLMSettings, transport: httpx.BaseTransport | None = None) -> Provider:
    """Create the adapter for resolved settings."""
    if settings.provider == "anthropic":
        if not settings.api_key:
            raise ConfigError("anthropic needs ANTHROPIC_API_KEY")
        return AnthropicProvider(
            settings.api_key,
            settings.model,
            base_url=settings.base_url or ANTHROPIC_BASE_URL,
            transport=transport,
        )
    if not settings.base_url:
        raise ConfigError(f"{settings.provider} needs a base URL")
    return OpenAICompatProvider(
        settings.base_url,
        settings.model,
        api_key=settings.api_key,
        name=settings.provider,
        transport=transport,
    )

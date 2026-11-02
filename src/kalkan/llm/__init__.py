"""Bring-your-own-key LLM layer: small httpx adapters, a budget and JSON helpers."""

from kalkan.llm.base import (
    BudgetExceeded,
    ConfigError,
    LLMResponse,
    Provider,
    ProviderError,
    ProviderHTTPError,
    ProviderRefusal,
)
from kalkan.llm.budget import Budget, BudgetedProvider
from kalkan.llm.config import LLMSettings, build_provider, resolve_settings
from kalkan.llm.fake import FakeProvider
from kalkan.llm.json_output import complete_json

__all__ = [
    "Budget",
    "BudgetExceeded",
    "BudgetedProvider",
    "ConfigError",
    "FakeProvider",
    "LLMResponse",
    "LLMSettings",
    "Provider",
    "ProviderError",
    "ProviderHTTPError",
    "ProviderRefusal",
    "build_provider",
    "complete_json",
    "resolve_settings",
]

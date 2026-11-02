"""Per-run token budget and optional, user-supplied prices.

Kalkan ships no prices. Set ``KALKAN_PRICE_INPUT`` and ``KALKAN_PRICE_OUTPUT``
(USD per million tokens) to get a cost estimate.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from kalkan.llm.base import BudgetExceeded, LLMResponse, Provider

DEFAULT_MAX_TOKENS = 60_000


class Budget:
    """Counts tokens used in one run and stops when the limit is reached."""

    def __init__(
        self,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        price_input_per_mtok: float | None = None,
        price_output_per_mtok: float | None = None,
    ) -> None:
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        self.max_tokens = max_tokens
        self.input_tokens = 0
        self.output_tokens = 0
        self._price_in = price_input_per_mtok
        self._price_out = price_output_per_mtok

    @classmethod
    def from_env(
        cls, max_tokens: int | None = None, env: Mapping[str, str] | None = None
    ) -> Budget:
        """Build a budget from ``KALKAN_MAX_TOKENS`` and the optional price variables."""
        env = os.environ if env is None else env
        limit = max_tokens or int(env.get("KALKAN_MAX_TOKENS") or DEFAULT_MAX_TOKENS)
        return cls(
            limit, _float(env.get("KALKAN_PRICE_INPUT")), _float(env.get("KALKAN_PRICE_OUTPUT"))
        )

    @property
    def used(self) -> int:
        """Tokens used so far."""
        return self.input_tokens + self.output_tokens

    @property
    def remaining(self) -> int:
        """Tokens left before the budget stops further calls."""
        return max(self.max_tokens - self.used, 0)

    def check(self) -> None:
        """Raise BudgetExceeded if no tokens are left."""
        if self.used >= self.max_tokens:
            raise BudgetExceeded(f"token budget of {self.max_tokens} used up ({self.used} used)")

    def charge(self, response: LLMResponse) -> None:
        """Record a response's token usage."""
        self.input_tokens += response.input_tokens
        self.output_tokens += response.output_tokens

    def cost_usd(self) -> float | None:
        """Estimated cost, or None when the user set no prices."""
        if self._price_in is None or self._price_out is None:
            return None
        return (self.input_tokens * self._price_in + self.output_tokens * self._price_out) / 1e6


def _float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


class BudgetedProvider:
    """Wraps a provider so every call is checked against and charged to a budget."""

    def __init__(self, inner: Provider, budget: Budget) -> None:
        self.inner = inner
        self.budget = budget
        self.name = inner.name
        self.model = inner.model

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Check the budget, call the provider, then charge the usage."""
        self.budget.check()
        response = self.inner.complete(system, user, max_tokens=max_tokens, json_schema=json_schema)
        self.budget.charge(response)
        return response

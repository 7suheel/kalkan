"""A scripted provider for tests. Tests never call real LLMs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kalkan.llm.base import LLMResponse


@dataclass
class FakeCall:
    """One recorded call to FakeProvider."""

    system: str
    user: str
    max_tokens: int
    json_schema: dict[str, Any] | None


@dataclass
class FakeProvider:
    """Returns scripted responses in order and records every call.

    Each script item is a response text or an exception to raise.
    """

    script: list[str | Exception] = field(default_factory=list)
    name: str = "fake"
    model: str = "fake-model"
    tokens_per_call: int = 100
    calls: list[FakeCall] = field(default_factory=list)

    def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        """Pop the next scripted item."""
        self.calls.append(FakeCall(system, user, max_tokens, json_schema))
        if not self.script:
            raise AssertionError("FakeProvider ran out of scripted responses")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        half = self.tokens_per_call // 2
        return LLMResponse(text=item, input_tokens=half, output_tokens=half, model=self.model)

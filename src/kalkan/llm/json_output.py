"""Ask a model for JSON, validate it, and repair once.

If the answer is still invalid after one repair attempt, return None so the
caller can fall back to NEEDS_HUMAN instead of guessing.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ValidationError

from kalkan.llm.base import Provider

JSON_INSTRUCTIONS = (
    "\n\nRespond with a single JSON object only: no prose, no Markdown fences. "
    "It must match this JSON Schema:\n"
)
REPAIR_PROMPT = (
    "Your previous answer was not valid for the required schema.\n"
    "Problem: {error}\n\n"
    "Previous answer (truncated):\n{previous}\n\n"
    "Reply again with only the corrected JSON object that matches the schema."
)


def extract_json_object(text: str) -> Any:
    """Parse the first JSON object in ``text`` (tolerates fences and leading prose)."""
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start != -1:
        try:
            value, _ = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        return value
    raise ValueError("no JSON object found in the answer")


def complete_json[T: BaseModel](
    provider: Provider,
    system: str,
    user: str,
    model_cls: type[T],
    *,
    max_tokens: int = 2000,
) -> tuple[T | None, list[str]]:
    """Return a validated ``model_cls`` instance (or None) and a list of problems seen."""
    schema = model_cls.model_json_schema()
    full_system = system + JSON_INSTRUCTIONS + json.dumps(schema, separators=(",", ":"))
    problems: list[str] = []
    prompt = user
    for _attempt in range(2):
        response = provider.complete(full_system, prompt, max_tokens=max_tokens, json_schema=schema)
        try:
            return model_cls.model_validate(extract_json_object(response.text)), problems
        except (ValueError, ValidationError) as exc:
            error = _short_error(exc)
            problems.append(error)
            prompt = (
                user + "\n\n" + REPAIR_PROMPT.format(error=error, previous=response.text[:2000])
            )
    return None, problems


def _short_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        parts = [
            f"{'.'.join(str(p) for p in e['loc']) or 'root'}: {e['msg']}" for e in exc.errors()[:5]
        ]
        return "; ".join(parts)
    return str(exc)[:200]

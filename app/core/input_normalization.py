"""Shared helpers for defensive normalization of prompt-derived values."""

from __future__ import annotations


def normalize_prompt_value(value: object) -> str:
    """Return a safe stripped string for any prompt-derived value."""

    if value is None:
        return ""
    return str(value).strip()

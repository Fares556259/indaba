"""Memory rules: ensure memory writes do not persist untrusted instructions or exploit payloads."""

from __future__ import annotations

import re

_DIRECTIVE_PATTERN = re.compile(
    r"\bcall\s+[a-z][a-z0-9_]{1,63}\s+with\s*\{|\bremember\s*:\s*|\bbase64:[A-Za-z0-9+/=]{12,}",
    re.IGNORECASE,
)


def is_memory_write_poisoned(content: str, untrusted_texts: list[str]) -> bool:
    """
    Returns True if a memory write contains executable directives or unauthorized policy
    overrides derived from untrusted content.
    """
    if not content:
        return False

    # Check for prompt injection syntax / executable tool directives
    if _DIRECTIVE_PATTERN.search(content):
        return True

    # Check if untrusted source fabricated an approval/policy override
    content_lower = content.lower()
    if "approved by" in content_lower and ("legal" in content_lower or "policy" in content_lower):
        for ut in untrusted_texts:
            if "approved by" in ut.lower():
                return True

    return False

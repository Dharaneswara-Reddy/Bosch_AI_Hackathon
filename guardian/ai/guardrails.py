"""Input guardrails applied before anything reaches the model.

Everything from the target repository (README text, package names, file paths,
diffs) is attacker-controllable. It is redacted, truncated, scanned for
instruction-like text and wrapped as data. These guardrails reduce exposure;
the validator is what actually guarantees no unsupported claim is accepted.
"""

from __future__ import annotations

import re

MAX_UNTRUSTED_CHARS = 12_000

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b(\s*[:=]\s*)(['\"]?)[^\s'\",]{6,}\3"
    ),
)

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules?|prompts?|guidelines)\b"
    ),
    re.compile(r"(?i)\byou are now\b"),
    re.compile(r"(?i)\b(system|developer) (prompt|message)\b"),
    re.compile(r"(?i)\bmark (everything|all|this|it|them)\b.{0,30}\b(safe|secure|clean|low)\b"),
    re.compile(r"(?i)\bdo not (report|flag|mention)\b"),
    re.compile(r"(?i)</?\s*(system|assistant|instructions?)\s*>"),
)

_DELIMITER = re.compile(r"<(\s*/?\s*untrusted)", re.IGNORECASE)


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace anything that looks like a credential. Returns (text, number of redactions)."""
    count = 0
    for pattern in _SECRET_PATTERNS:
        text, n = pattern.subn("[REDACTED]", text)
        count += n
    return text, count


def find_injection_markers(text: str) -> list[str]:
    """Return instruction-like snippets found in untrusted text (reported, never obeyed)."""
    markers: list[str] = []
    for pattern in _INJECTION_PATTERNS:
        markers.extend(match.group(0)[:120] for match in pattern.finditer(text))
    return markers


def wrap_untrusted(text: str, limit: int = MAX_UNTRUSTED_CHARS) -> str:
    """Wrap repo-derived text as data, neutralising any delimiter look-alikes inside it."""
    clipped = text if len(text) <= limit else text[:limit] + "\n[TRUNCATED]"
    escaped = _DELIMITER.sub(r"&lt;\1", clipped)
    return f"<untrusted>\n{escaped}\n</untrusted>"

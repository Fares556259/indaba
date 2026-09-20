"""Normalizer: multi-scheme recursive decoding (base64, hex, url, rot13, reversed, spaced).

Recursively decodes text with bounded depth and length bounds to prevent resource exhaustion.
Keeps raw and all decoded views for multi-perspective inspection.
"""

from __future__ import annotations

import base64
import codecs
import re
from urllib.parse import unquote

_NON_ALNUM = re.compile(r"[^a-z0-9]")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")

MAX_INPUT_CHARS = 100_000
MAX_VIEWS = 64
MAX_DEPTH = 3


def normalize_alnum(text: str) -> str:
    """Canonical alphanumeric string stripped of case, whitespace, and punctuation."""
    return _NON_ALNUM.sub("", text.lower())


def _try_decode_base64(text: str) -> list[str]:
    results: list[str] = []
    # Explicit base64: prefix if present
    if "base64:" in text:
        for part in text.split("base64:")[1:]:
            token = part.split()[0].split('"')[0].split("'")[0].rstrip(".,;")
            padded = token + "=" * (-len(token) % 4)
            try:
                dec = base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
                if dec and any(c.isalnum() for c in dec):
                    results.append(dec)
            except Exception:
                pass

    # Scan for base64 tokens
    for token in _B64_TOKEN.findall(text):
        if len(token) % 4 != 0 and "=" in token:
            continue
        padded = token + "=" * (-len(token) % 4)
        try:
            dec = base64.b64decode(padded, validate=True).decode("utf-8", "ignore")
            if len(dec) >= 4 and sum(c.isprintable() for c in dec) / len(dec) > 0.80:
                results.append(dec)
        except Exception:
            continue
    return results


def _try_decode_hex(text: str) -> list[str]:
    results: list[str] = []
    clean = text.strip()
    if clean.startswith("0x"):
        clean = clean[2:]
    for token in _HEX_TOKEN.findall(clean):
        if len(token) % 2 != 0:
            continue
        try:
            dec = bytes.fromhex(token).decode("utf-8", "ignore")
            if len(dec) >= 4 and sum(c.isprintable() for c in dec) / len(dec) > 0.80:
                results.append(dec)
        except Exception:
            continue
    return results


def _try_decode_url(text: str) -> list[str]:
    if "%" in text:
        try:
            unq = unquote(text)
            if unq != text:
                return [unq]
        except Exception:
            pass
    return []


def _try_decode_rot13(text: str) -> list[str]:
    alpha_count = sum(c.isalpha() for c in text)
    if alpha_count >= 8:
        try:
            rot = codecs.decode(text, "rot_13")
            if rot != text:
                return [rot]
        except Exception:
            pass
    return []


def _try_decode_reversed(text: str) -> list[str]:
    if 6 <= len(text) <= 5000:
        return [text[::-1]]
    return []


def _try_decode_spaced(text: str) -> list[str]:
    results: list[str] = []
    if " " in text or "." in text or "-" in text:
        collapsed = re.sub(r"(?<=\b[a-zA-Z0-9])[ \t._\-](?=[a-zA-Z0-9]\b)", "", text)
        if collapsed != text:
            results.append(collapsed)
    return results


def decode_step(text: str) -> list[str]:
    """Applies one round of individual decoders to input text."""
    variants: list[str] = []
    variants.extend(_try_decode_base64(text))
    variants.extend(_try_decode_hex(text))
    variants.extend(_try_decode_url(text))
    variants.extend(_try_decode_rot13(text))
    variants.extend(_try_decode_spaced(text))
    variants.extend(_try_decode_reversed(text))
    return variants


def extract_all_views(text: str, max_depth: int = MAX_DEPTH, max_views: int = MAX_VIEWS) -> set[str]:
    """Recursively decodes text up to max_depth, returning all raw and decoded views."""
    bounded = text[:MAX_INPUT_CHARS]
    views: set[str] = {bounded}
    queue: list[tuple[str, int]] = [(bounded, 0)]

    while queue and len(views) < max_views:
        current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for candidate in decode_step(current):
            cand = candidate.strip()
            if cand and cand not in views:
                views.add(cand)
                if len(views) >= max_views:
                    break
                queue.append((cand, depth + 1))

    return views


def extract_normalized_probes(text: str, window: int = 14, step: int = 7) -> set[str]:
    """Extracts shingle probes from normalized text for fast subsequence matching."""
    norm = normalize_alnum(text)
    if len(norm) < window:
        return {norm} if len(norm) >= 8 else set()
    return {norm[i : i + window] for i in range(0, len(norm) - window + 1, step)}


def check_sensitive_flow(
    payload_text: str,
    sensitive_texts: list[str],
    window: int = 14,
) -> bool:
    """Returns True if any decoded or normalized view of payload_text matches sensitive content."""
    if not payload_text or not sensitive_texts:
        return False

    sensitive_probes: set[str] = set()
    sensitive_norms: list[str] = []
    for st in sensitive_texts:
        s_norm = normalize_alnum(st)
        if s_norm:
            sensitive_norms.append(s_norm)
            sensitive_probes.update(extract_normalized_probes(st, window=window, step=max(1, window // 2)))

    if not sensitive_probes and not sensitive_norms:
        return False

    views = extract_all_views(payload_text)
    for view in views:
        view_norm = normalize_alnum(view)
        if not view_norm:
            continue
        for probe in sensitive_probes:
            if probe in view_norm:
                return True
        for s_norm in sensitive_norms:
            if len(s_norm) >= 8 and s_norm in view_norm:
                return True

    return False

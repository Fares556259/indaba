"""Cross-record corpus aggregation and multi-record matching."""

from __future__ import annotations

from app.normalizer import extract_all_views, normalize_alnum


def build_cross_record_corpus(untrusted_texts: list[str]) -> str:
    """Concatenates all untrusted items into a single unified cross-record corpus."""
    return "\n---\n".join(untrusted_texts)


def match_in_corpus(corpus: str, tool: str, arguments: dict[str, object]) -> bool:
    """Checks if tool and distinct arguments co-occur anywhere in the cross-record corpus (raw or decoded)."""
    if not corpus:
        return False

    views = extract_all_views(corpus, max_depth=2, max_views=16)
    tool_lower = tool.lower()
    tool_norm = normalize_alnum(tool)

    for view in views:
        view_lower = view.lower()
        view_norm = normalize_alnum(view)
        if tool_lower in view_lower or tool_norm in view_norm:
            for _, val in arguments.items():
                if val is None:
                    continue
                v_str = str(val).lower()
                v_norm = normalize_alnum(v_str)
                if len(v_norm) >= 4 and (v_str in view_lower or v_norm in view_norm):
                    return True

    return False

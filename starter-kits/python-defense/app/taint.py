"""Taint tracking: maps provenance IDs to trust levels and tracks lineage."""

from __future__ import annotations

from app.models import DefenseRequest

TRUSTED_LEVELS = frozenset({"system_policy", "authenticated_user", "trusted_internal"})
UNTRUSTED_LEVELS = frozenset({"untrusted_internal", "untrusted_external", "adversary_controlled"})


def get_trust_map(request: DefenseRequest) -> dict[str, str]:
    """Builds a map from provenance ID to its trust level string."""
    return {rec.id: rec.provenance.trust_level for rec in request.provenance}


def is_provenance_untrusted(prov_id: str, trust_map: dict[str, str]) -> bool:
    trust = trust_map.get(prov_id)
    return trust in UNTRUSTED_LEVELS


def conversation_trust_summary(request: DefenseRequest) -> tuple[list[str], list[str]]:
    """Returns (trusted_texts, untrusted_texts) from conversation and observation items."""
    trust_map = get_trust_map(request)
    trusted: list[str] = []
    untrusted: list[str] = []

    for item in request.conversation:
        p_trusts = [trust_map[pid] for pid in item.provenance_ids if pid in trust_map]
        if any(t in UNTRUSTED_LEVELS for t in p_trusts):
            untrusted.append(item.content)
        elif any(t in TRUSTED_LEVELS for t in p_trusts):
            trusted.append(item.content)

    if request.observation is not None:
        p_trusts = [trust_map[pid] for pid in request.observation.provenance_ids if pid in trust_map]
        if any(t in UNTRUSTED_LEVELS for t in p_trusts):
            untrusted.append(request.observation.content)
        elif any(t in TRUSTED_LEVELS for t in p_trusts):
            trusted.append(request.observation.content)

    return trusted, untrusted

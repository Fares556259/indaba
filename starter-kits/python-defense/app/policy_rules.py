"""Effect tiers and policy rules based strictly on policy_context and request metadata."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from app.models import CandidateAction, DefenseRequest


class EffectTier(StrEnum):
    READ_ONLY = "read_only"
    INTERNAL_WRITE = "internal_write"
    OUTBOUND = "outbound"
    CONSEQUENTIAL = "consequential"
    UNKNOWN = "unknown"


STATUS_CONSEQUENTIAL = {
    "ticket_update": {"closed", "resolved"},
    "incident_update": {"closed"},
}

OUTBOUND_TOOLS = {"email_send", "email_draft"}

# Known synthetic read-only tools across enterprise, finance, soc
KNOWN_READ_TOOLS = {
    "email_search",
    "email_read",
    "document_search",
    "document_read",
    "wiki_search",
    "ticket_read",
    "customer_lookup",
    "case_document_read",
    "account_lookup",
    "asset_lookup",
    "log_search",
    "intel_lookup",
    "incident_read",
    "policy_read",
}


def action_digest(action: CandidateAction) -> str:
    """Canonical SHA-256 digest matching sentinel.core.actions.CandidateAction.digest()."""

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def target_action(request: DefenseRequest) -> CandidateAction:
    candidate = request.candidate_action
    if candidate.type == "request_confirmation" and candidate.confirmation_for is not None:
        return candidate.confirmation_for
    return candidate


def is_confirmed(request: DefenseRequest, action: CandidateAction) -> bool:
    return action_digest(action) in request.history_digest.confirmations_granted


def is_consequential(request: DefenseRequest, action: CandidateAction) -> bool:
    if action.type != "tool_call" or action.tool is None:
        return False
    policy = request.policy_context
    if action.tool in policy.get("consequential_tools", []) or action.tool in policy.get("confirmation_required_tools", []):
        return True
    status = action.arguments.get("status")
    if isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(action.tool, set()):
        return True
    return False


def is_external_recipient(request: DefenseRequest, action: CandidateAction) -> bool:
    if action.tool not in OUTBOUND_TOOLS:
        return False
    recipient = str(action.arguments.get("to", "")).lower()
    if not recipient:
        return False
    internal = [d.lower() for d in request.policy_context.get("internal_email_domains", [])]
    return not any(recipient.endswith("@" + domain) for domain in internal)


def classify_tier(request: DefenseRequest, action: CandidateAction) -> EffectTier:
    """Classifies an action into effect tiers using policy_context and domain registry rules."""
    if action.type != "tool_call" or not action.tool:
        return EffectTier.READ_ONLY if action.type == "respond" else EffectTier.INTERNAL_WRITE

    policy = request.policy_context
    allowed = set(policy.get("allowed_tools", []))

    # Unknown tools (outside allowed list or uncataloged) are treated as non-read-only
    if action.tool not in allowed:
        return EffectTier.UNKNOWN

    if is_consequential(request, action):
        return EffectTier.CONSEQUENTIAL

    if action.tool in OUTBOUND_TOOLS:
        return EffectTier.OUTBOUND

    if action.tool in KNOWN_READ_TOOLS:
        return EffectTier.READ_ONLY

    # Any other allowed tool is an internal write
    return EffectTier.INTERNAL_WRITE


def action_text_payload(action: CandidateAction) -> str:
    """Extracts all free-form text payload from a candidate action."""
    parts: list[str] = []
    if action.content:
        parts.append(action.content)
    for v in action.arguments.values():
        if v is not None:
            parts.append(str(v))
    if action.confirmation_for is not None:
        parts.append(action_text_payload(action.confirmation_for))
    return "\n".join(parts)


def texts_by_trust(request: DefenseRequest) -> tuple[list[str], list[str]]:
    """Split conversation and observation content into (untrusted texts, sensitive texts) using provenance."""
    records = {record.id: record.provenance for record in request.provenance}
    untrusted: list[str] = []
    sensitive: list[str] = []

    for item in request.conversation:
        provs = [records[pid] for pid in item.provenance_ids if pid in records]
        if any(p.trust_level in ("untrusted_internal", "untrusted_external", "adversary_controlled") for p in provs):
            untrusted.append(item.content)
        if any(p.sensitivity in ("confidential", "restricted") for p in provs):
            sensitive.append(item.content)

    if request.observation is not None:
        provs = [records[pid] for pid in request.observation.provenance_ids if pid in records]
        if any(p.trust_level in ("untrusted_internal", "untrusted_external", "adversary_controlled") for p in provs):
            untrusted.append(request.observation.content)
        if any(p.sensitivity in ("confidential", "restricted") for p in provs):
            sensitive.append(request.observation.content)

    return untrusted, sensitive


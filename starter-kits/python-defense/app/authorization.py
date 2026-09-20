"""Authorization and action-level intent checks.

Verifies whether action and its arguments originate from the user goal or trusted
sources, and blocks actions outside user intent that mirror untrusted instructions.
"""

from __future__ import annotations

import re
from typing import Any

from app.models import CandidateAction, DefenseRequest
from app.normalizer import normalize_alnum

TOOL_INTENT_KEYWORDS: dict[str, list[str]] = {
    # Enterprise
    "email_read": ["email", "reminder", "message", "inbox", "mail", "em-"],
    "email_search": ["email", "search", "find", "inbox", "mail"],
    "document_read": [
        "document",
        "doc",
        "policy",
        "msa",
        "contract",
        "po",
        "purchase order",
        "invoice",
        "delivery note",
        "note",
        "report",
        "summary",
        "doc-",
        "check",
        "review",
    ],
    "document_search": ["document", "doc", "policy", "msa", "contract", "search", "find", "check"],
    "wiki_search": ["wiki", "knowledge base", "portal", "wk-"],
    "email_draft": ["draft", "reply", "send", "email", "notify", "forward", "share", "prepare", "write", "summary"],
    "email_send": ["send", "email", "notify", "forward", "share"],
    "ticket_read": ["ticket", "issue", "tck-", "summary", "check", "review"],
    "ticket_update": ["ticket", "note", "close", "resolve", "update", "tck-"],
    # Finance
    "customer_lookup": ["customer", "profile", "user", "client", "cu-", "check", "review"],
    "account_lookup": ["account", "balance", "acc-"],
    "policy_search": ["policy", "rules", "search", "handling"],
    "case_document_read": ["case", "document", "investigator", "note", "cd-", "case-", "read", "check", "review"],
    "case_note_create": ["note", "log", "update", "case", "status"],
    "payment_prepare": ["payment", "pay", "transfer", "refund", "settle", "claim", "prepare"],
    "payment_confirm": ["confirm", "payment", "sign-off"],
    "payment_execute": ["execute", "payment", "send"],
    # SOC
    "alert_read": ["alert", "al-", "triage", "check"],
    "alert_search": ["alert", "search", "find", "al-"],
    "asset_lookup": ["asset", "server", "host", "srv-", "check", "triage"],
    "intel_lookup": ["intel", "domain", "indicator", "hash", "ip", "ti-"],
    "intel_search": ["intel", "domain", "indicator", "hash", "ip", "ti-", "check"],
    "incident_create": ["incident", "triage", "ticket", "open", "inc-"],
    "incident_update": ["incident", "triage", "update", "close", "contain", "investigating", "inc-"],
    "isolate_asset": ["isolate", "quarantine", "contain"],
    "restore_asset": ["restore", "reconnect"],
}


def is_tool_called_for(tool: str, goal: str) -> bool:
    """Returns True if the tool aligns with the user goal semantics or identifiers."""
    tool_lower = tool.lower()
    goal_lower = goal.lower()
    goal_norm = normalize_alnum(goal)

    if tool_lower in goal_lower or normalize_alnum(tool_lower) in goal_norm:
        return True

    keywords = TOOL_INTENT_KEYWORDS.get(tool_lower, [])
    for kw in keywords:
        if kw in goal_lower or normalize_alnum(kw) in goal_norm:
            return True

    return False


def check_action_intent(
    request: DefenseRequest,
    action: CandidateAction,
    untrusted_texts: list[str],
) -> tuple[bool, str]:
    """
    Checks if a candidate action aligns with user intent or was injected by untrusted content.
    Returns (is_allowed, reason_code).
    """
    if action.type != "tool_call" or action.tool is None:
        return True, ""

    tool = action.tool.lower()
    tool_norm = normalize_alnum(tool)
    tool_allowed_by_goal = is_tool_called_for(tool, request.user_goal)

    # 1. If tool is completely outside the user's intent:
    if not tool_allowed_by_goal:
        # Check if it was prompted by untrusted content
        for ut in untrusted_texts:
            ut_lower = ut.lower()
            ut_norm = normalize_alnum(ut)
            if tool in ut_lower or tool_norm in ut_norm:
                return False, "UNTRUSTED_INSTRUCTION_SOURCE"

    # 2. For actions with significant arguments:
    # If the tool is a write/draft/consequential action, check if arguments were untrusted-derived
    for ut in untrusted_texts:
        ut_lower = ut.lower()
        ut_norm = normalize_alnum(ut)
        if tool in ut_lower or tool_norm in ut_norm:
            for _, arg_v in action.arguments.items():
                if arg_v is None:
                    continue
                v_str = str(arg_v).lower()
                v_norm = normalize_alnum(v_str)
                if len(v_norm) >= 4 and (v_str in ut_lower or v_norm in ut_norm):
                    # Check if this argument was authorized by user goal
                    if v_str not in request.user_goal.lower() and v_norm not in normalize_alnum(request.user_goal):
                        # Consequential or outbound write actions with untrusted-only arguments are blocked
                        if action.tool in (
                            "email_send",
                            "email_draft",
                            "ticket_update",
                            "payment_prepare",
                            "payment_confirm",
                            "payment_execute",
                        ):
                            return False, "UNTRUSTED_INSTRUCTION_SOURCE"
                        if not tool_allowed_by_goal:
                            return False, "UNTRUSTED_INSTRUCTION_SOURCE"

    return True, ""

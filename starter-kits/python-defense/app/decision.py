"""Decision logic: multi-tier defense pipeline with ablation-safe component flags."""

from __future__ import annotations

from app.authorization import check_action_intent, is_tool_called_for
from app.config import DEFENSE_CONFIG
from app.corpus import build_cross_record_corpus, match_in_corpus
from app.memory_rules import is_memory_write_poisoned
from app.models import CandidateAction, DefenseDecision, DefenseRequest
from app.normalizer import check_sensitive_flow
from app.policy_rules import (
    EffectTier,
    action_text_payload,
    classify_tier,
    is_confirmed,
    is_consequential,
    is_external_recipient,
    target_action,
    texts_by_trust,
)



def decide(request: DefenseRequest, cfg: "DefenseConfig | None" = None) -> DefenseDecision:  # type: ignore[name-defined]
    from app.config import DefenseConfig
    if cfg is None:
        cfg = DEFENSE_CONFIG
    candidate = request.candidate_action
    action = target_action(request)
    tier = classify_tier(request, action)
    allowed = request.policy_context.get("allowed_tools", [])

    # Extract untrusted and sensitive texts — gated on taint flag
    if cfg.taint_enabled:
        untrusted, sensitive = texts_by_trust(request)
    else:
        untrusted, sensitive = [], []

    risk = 0.05
    confidence = 0.85
    codes: list[str] = []
    conflict = False

    # 1. Unknown or unallowed tool: Hard block
    if action.type == "tool_call" and action.tool not in allowed:
        return DefenseDecision(
            decision="block",
            risk_score=0.95,
            confidence=0.95,
            reason_codes=["TOOL_NOT_ALLOWED"],
            explanation=f"tool {action.tool} is not in policy allowed_tools",
        )

    # 2. Outbound Flow Rule: Policy overrides user goal
    if cfg.outbound_flow_enabled and is_external_recipient(request, action):
        payload = action_text_payload(action)
        flow_hit = (
            check_sensitive_flow(payload, sensitive)
            if cfg.normalizer_enabled
            else any(s in payload for s in sensitive)
        )
        if flow_hit:
            return DefenseDecision(
                decision="block",
                risk_score=0.95,
                confidence=0.95,
                reason_codes=["SENSITIVE_TO_UNTRUSTED_SINK", "FLOW_RULE_VIOLATION"],
                explanation="sensitive or restricted content addressed to an external destination",
            )

    # 3. Memory Write Protection
    if action.type == "memory_write":
        content = action.content or ""
        if cfg.memory_rules_enabled and is_memory_write_poisoned(content, untrusted):
            return DefenseDecision(
                decision="block",
                risk_score=0.90,
                confidence=0.90,
                reason_codes=["UNTRUSTED_INSTRUCTION_SOURCE", "MEMORY_POISON_PREVENTED"],
                explanation="memory write contains untrusted directives or unauthorized policy override",
            )
        return DefenseDecision(
            decision="allow",
            risk_score=0.10,
            confidence=0.85,
            reason_codes=["USER_GOAL_ALIGNED"],
            explanation="safe memory write aligned with user goal",
        )

    # 4. Cross-Record Corpus & Action-Level Intent Check
    corpus = build_cross_record_corpus(untrusted) if cfg.corpus_enabled else ""
    if cfg.authorization_enabled:
        intent_ok, intent_code = check_action_intent(request, action, untrusted)
        if not intent_ok:
            return DefenseDecision(
                decision="block",
                risk_score=0.92,
                confidence=0.90,
                reason_codes=[intent_code, "ACTION_OUTSIDE_USER_INTENT"],
                explanation="tool call mirrors an instruction from untrusted content outside user intent",
            )
    if cfg.corpus_enabled and action.type == "tool_call" and action.tool:
        if not is_tool_called_for(action.tool, request.user_goal) and match_in_corpus(corpus, action.tool, action.arguments):
            return DefenseDecision(
                decision="block",
                risk_score=0.92,
                confidence=0.90,
                reason_codes=["UNTRUSTED_INSTRUCTION_SOURCE", "SPLIT_INSTRUCTION_BLOCKED"],
                explanation="action matches split instruction in untrusted corpus outside user intent",
            )

    # 5. Confirmed by human: Allow
    if is_confirmed(request, action):
        return DefenseDecision(
            decision="allow",
            risk_score=0.05,
            confidence=0.95,
            reason_codes=["CONFIRMED_BY_HUMAN"],
            explanation="action was previously approved by human supervisor",
        )

    # 6. Proactive confirmation request
    if candidate.type == "request_confirmation":
        return DefenseDecision(
            decision="allow",
            risk_score=0.15,
            confidence=0.90,
            reason_codes=["CONFIRMATION_REQUESTED"],
            explanation="agent is safely requesting human confirmation",
        )

    # 7. Consequential action handling
    if tier == EffectTier.CONSEQUENTIAL:
        risk += 0.55
        codes.append("CONSEQUENTIAL_REQUIRES_CONFIRMATION")
        codes.append("MISSING_CONFIRMATION")
        conflict = True

        # Rewrite unconfirmed external send to draft if permitted
        if action.tool == "email_send" and "email_draft" in allowed:
            rewritten = CandidateAction(
                type="tool_call",
                tool="email_draft",
                arguments=dict(action.arguments),
            )
            return DefenseDecision(
                decision="rewrite",
                risk_score=0.50,
                confidence=0.80,
                reason_codes=["REWRITE_TO_DRAFT", "MISSING_CONFIRMATION"],
                explanation="unconfirmed send rewritten to a draft",
                rewritten_action=rewritten,
            )

        confidence = 0.65 if conflict else 0.80
        return DefenseDecision(
            decision="escalate",
            risk_score=round(min(1.0, risk), 4),
            confidence=round(confidence, 4),
            reason_codes=codes,
            explanation="consequential action lacks human confirmation; escalating",
        )

    # 8. Read-only actions in allowed tools
    if tier == EffectTier.READ_ONLY:
        return DefenseDecision(
            decision="allow",
            risk_score=0.08,
            confidence=0.85,
            reason_codes=["READ_ONLY_PERMITTED"],
            explanation="read-only action within policy allowed tools",
        )

    # 9. Safe internal writes and responses
    return DefenseDecision(
        decision="allow",
        risk_score=0.10,
        confidence=0.80,
        reason_codes=["USER_GOAL_ALIGNED"],
        explanation="action is allowed under baseline effect tiers",
    )


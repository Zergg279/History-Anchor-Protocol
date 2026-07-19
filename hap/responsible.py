from __future__ import annotations

from typing import Any, Iterable

RESPONSIBLE_PROFILE = "hap-responsible-publication-v1"
PERSON_IMPACT_PREFIX = "hap:person-impact:"
PERSON_IMPACT_VALUES = {"none", "direct", "indirect-or-mosaic", "uncertain"}
VIEW_ENABLE_TAG = "hap:view:enable-discovery"
VIEW_RESTRICT_TAG = "hap:view:restrict-discovery"

CONTEXT_KINDS = {
    "subject_response",
    "person_impact_notice",
    "restriction_notice",
    "withdrawal_notice",
    "legal_adjudication",
    "public_interest_justification",
    "view_decision",
    "dispute",
    "correction",
    "attestation",
}


class ResponsibleProfileError(ValueError):
    pass


def declared_person_impact(record: dict[str, Any]) -> str | None:
    values = {
        tag.removeprefix(PERSON_IMPACT_PREFIX)
        for tag in record.get("tags", [])
        if isinstance(tag, str) and tag.startswith(PERSON_IMPACT_PREFIX)
    }
    values &= PERSON_IMPACT_VALUES
    if len(values) > 1:
        return "uncertain"
    return next(iter(values), None)


def validate_responsible_record(record: dict[str, Any]) -> None:
    """Validate the reference responsible-publication profile.

    These are relay/profile rules, not base-protocol validity. A record that fails
    this function can still be a valid HAP record and can still be published
    directly through Bitcoin.
    """
    kind = record.get("kind")
    tags = set(record.get("tags", []))
    impact = declared_person_impact(record)

    if kind == "claim" and impact is None:
        raise ResponsibleProfileError(
            "responsible-profile relays require one person-impact declaration: "
            "none, direct, indirect-or-mosaic, or uncertain"
        )
    if kind == "person_impact_notice" and impact not in {
        "direct",
        "indirect-or-mosaic",
        "uncertain",
    }:
        raise ResponsibleProfileError(
            "person_impact_notice requires a non-none person-impact tag"
        )
    if kind == "view_decision":
        actions = tags & {VIEW_ENABLE_TAG, VIEW_RESTRICT_TAG}
        if len(actions) != 1:
            raise ResponsibleProfileError(
                "view_decision requires exactly one view action tag"
            )
    elif tags & {VIEW_ENABLE_TAG, VIEW_RESTRICT_TAG}:
        raise ResponsibleProfileError(
            "view action tags are reserved for view_decision records"
        )


def _record_summary(record: dict[str, Any], anchored_ids: set[str]) -> dict[str, Any]:
    return {
        "record_id": record["record_id"],
        "kind": record["kind"],
        "author_id": record["author_id"],
        "title": record["title"],
        "statement": record["statement"],
        "created_at": record["created_at"],
        "bitcoin_anchored": record["record_id"] in anchored_ids,
        "tags": record.get("tags", []),
    }


def assess_responsible_publication(
    *,
    record: dict[str, Any],
    linked_records: list[dict[str, Any]],
    anchored_record_ids: set[str],
    anchor_heights: dict[str, int],
    chain_height: int | None,
    recognised_accountable_authors: Iterable[str] = (),
    cooling_blocks: int = 6,
    notice_protection_blocks: int = 6,
) -> dict[str, Any]:
    """Build a deterministic local view under the reference publication profile.

    The result never changes base-protocol validity. It only governs the reference
    client's discovery and amplification behaviour.
    """
    recognised = set(recognised_accountable_authors)
    impact = declared_person_impact(record)
    reasons: list[str] = []
    canonically_published = record["record_id"] in anchored_record_ids
    if not canonically_published:
        reasons.append("record is not canonically published in Bitcoin")

    if impact is None:
        reasons.append("person impact was not declared")
    elif impact != "none":
        reasons.append(f"publisher declared person impact: {impact}")

    context = [item for item in linked_records if item.get("kind") in CONTEXT_KINDS]
    subject_responses = [item for item in context if item["kind"] == "subject_response"]
    impact_notices = [
        item for item in context if item["kind"] == "person_impact_notice"
    ]
    restrictions = [item for item in context if item["kind"] == "restriction_notice"]
    withdrawals = [item for item in context if item["kind"] == "withdrawal_notice"]
    adjudications = [item for item in context if item["kind"] == "legal_adjudication"]
    public_interest = [
        item for item in context if item["kind"] == "public_interest_justification"
    ]
    decisions = [item for item in context if item["kind"] == "view_decision"]
    disputes = [item for item in context if item["kind"] == "dispute"]
    corrections = [item for item in context if item["kind"] == "correction"]

    review_flags: list[str] = []
    if impact_notices:
        review_flags.append("one or more person-impact notices exist")
    if subject_responses:
        review_flags.append("one or more subject responses exist")
    if restrictions:
        review_flags.append("one or more restriction notices exist")
    if disputes:
        review_flags.append("the record is disputed")

    anchored_notice_heights = sorted(
        height
        for item in [*impact_notices, *restrictions]
        if item["record_id"] in anchored_record_ids
        if (height := anchor_heights.get(item["record_id"])) is not None
    )
    temporary_notice_active = False
    notice_window_ends_at = None
    if anchored_notice_heights and chain_height is not None:
        first_notice_height = anchored_notice_heights[0]
        notice_window_ends_at = first_notice_height + max(0, notice_protection_blocks)
        temporary_notice_active = chain_height < notice_window_ends_at
        if temporary_notice_active:
            reasons.append("the fixed non-renewable challenge window is active")

    recognised_restrictions = [
        item
        for item in restrictions
        if item["record_id"] in anchored_record_ids and item["author_id"] in recognised
    ]
    if recognised_restrictions:
        reasons.append("a recognised accountable restriction notice exists")

    protected = bool(reasons)
    original_height = anchor_heights.get(record["record_id"])
    blocks_elapsed = None
    cooling_complete = False
    if chain_height is not None and original_height is not None:
        blocks_elapsed = max(0, chain_height - original_height)
        cooling_complete = blocks_elapsed >= max(0, cooling_blocks)

    accepted_enable: dict[str, Any] | None = None
    accepted_restrict: dict[str, Any] | None = None
    decision_evaluations: list[dict[str, Any]] = []
    for decision in decisions:
        tags = set(decision.get("tags", []))
        action = (
            "enable-discovery"
            if VIEW_ENABLE_TAG in tags
            else ("restrict-discovery" if VIEW_RESTRICT_TAG in tags else "invalid")
        )
        anchored = decision["record_id"] in anchored_record_ids
        accountable = decision["author_id"] in recognised
        eligible = anchored and accountable
        evaluation = {
            **_record_summary(decision, anchored_record_ids),
            "action": action,
            "recognised_accountable_author": accountable,
            "eligible": eligible,
        }
        decision_evaluations.append(evaluation)
        if not eligible:
            continue
        if action == "restrict-discovery":
            accepted_restrict = evaluation
        elif action == "enable-discovery" and cooling_complete:
            accepted_enable = evaluation

    if accepted_restrict:
        protected = True
        reasons.append("a recognised accountable view decision restricts discovery")
    elif (
        protected
        and accepted_enable
        and not recognised_restrictions
        and not temporary_notice_active
    ):
        protected = False
        reasons = [
            "a recognised accountable view decision enabled discovery after the cooling period"
        ]

    if not canonically_published:
        state = "unpublished"
    elif not protected and impact == "none":
        state = "discoverable"
    elif not protected:
        state = "discoverable-by-accountable-decision"
    else:
        state = "protected"

    def summaries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [_record_summary(item, anchored_record_ids) for item in items]

    return {
        "schema": "hap.responsible-publication",
        "version": 1,
        "profile": RESPONSIBLE_PROFILE,
        "record_id": record["record_id"],
        "base_protocol_validity_unchanged": True,
        "person_impact": {
            "declared": impact or "missing",
            "protective_triggered": state == "protected",
            "reasons": reasons,
            "mosaic_identifiability_can_be_missed": True,
        },
        "cooling": {
            "required_blocks": max(0, cooling_blocks),
            "original_anchor_height": original_height,
            "current_chain_height": chain_height,
            "blocks_elapsed": blocks_elapsed,
            "complete": cooling_complete,
        },
        "challenge_window": {
            "required_blocks": max(0, notice_protection_blocks),
            "first_anchored_notice_height": anchored_notice_heights[0]
            if anchored_notice_heights
            else None,
            "ends_at_height": notice_window_ends_at,
            "active": temporary_notice_active,
            "later_burner_notices_extend_window": False,
        },
        "review_flags": review_flags,
        "discovery": {
            "state": state,
            "exact_identifier_access": True,
            "listed_in_reference_feed": state
            in {"discoverable", "discoverable-by-accountable-decision"},
            "search_indexing_recommended": state
            in {"discoverable", "discoverable-by-accountable-decision"},
            "recommendation_or_trending_recommended": state
            in {"discoverable", "discoverable-by-accountable-decision"},
            "public_interest_claim_has_automatic_effect": False,
            "unilateral_emergency_override_available": False,
        },
        "context": {
            "subject_responses": summaries(subject_responses),
            "person_impact_notices": summaries(impact_notices),
            "restriction_notices": summaries(restrictions),
            "withdrawal_notices": summaries(withdrawals),
            "legal_adjudications": summaries(adjudications),
            "public_interest_justifications": summaries(public_interest),
            "disputes": summaries(disputes),
            "corrections": summaries(corrections),
            "view_decisions": decision_evaluations,
        },
        "limitations": [
            "This profile constrains good-faith HAP clients only; hostile republishers can ignore it.",
            "Restriction cannot recall screenshots, mirrors, downloads, or copies outside compliant infrastructure.",
            "Recognised accountable authors are a local client trust choice, not protocol authorities.",
            "No automated process can reliably detect every directly or mosaically identifiable person.",
        ],
    }

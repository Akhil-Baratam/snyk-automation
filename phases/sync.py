"""
Phase 2 — Jira sync.

11.1 Forward check  — for every target with C/H vulns, ensure an open Jira
                       ticket exists and reflects the current counts.
11.2 Reverse check  — scan all open snyk-jolt tickets and flag any whose
                       target is gone or clean in Snyk.
"""
import logging

import config
import state
from clients.jira import JiraClient
from models.run_result import (
    CreatedTicket,
    FlaggedTicket,
    RunResult,
    UpdatedTicket,
)
from models.target import SnykTarget

logger = logging.getLogger(__name__)


def _snyk_target_url(target_id: str) -> str:
    return (
        f"{config.SNYK_API_BASE_URL.rstrip('/')}"
        f"/org/{config.SNYK_ORG_ID}/project/{target_id}"
    )


def _build_summary(display_name: str, critical: int, high: int, today: str) -> str:
    dd_mm_yy = "/".join(reversed(today.split("-")))[:-2]  # YYYY-MM-DD → DD/MM/YY
    return (
        f"Snyk Vulnerabilities Check Repo Name: {display_name},"
        f" Severity[C{critical}H{high} as on {dd_mm_yy}]"
    )


def _build_adf_description(target: SnykTarget) -> dict:
    """Minimal ADF document with the two tables described in §13."""
    project_rows = [
        {
            "type": "tableRow",
            "cells": [
                {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": p}]}]},
            ],
        }
        for p in target.projects
    ]

    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": f"Snyk Target: {target.display_name}",
                        "marks": [{"type": "strong"}],
                    }
                ],
            },
            {
                "type": "paragraph",
                "content": [
                    {"type": "text", "text": f"Critical: {target.critical}  High: {target.high}"},
                ],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "Scanned files:"}],
            },
            {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": p}]}],
                    }
                    for p in target.projects
                ],
            },
        ],
    }


def run_sync(
    targets: list[SnykTarget],
    all_target_ids: set[str],
    current_state: dict,
) -> RunResult:
    """
    Runs forward check then reverse check.
    Mutates current_state in-place.
    Returns a RunResult accumulator for Phase 3.
    """
    jira = JiraClient()
    result = RunResult()
    today = state.today_str()

    # ── 11.1 Forward check ────────────────────────────────────────────────────
    logger.info("Phase 2 — Forward check started (%d targets)", len(targets))

    for target in targets:
        try:
            _forward_check_target(target, jira, current_state, result, today)
            result.processed_count += 1
        except Exception as exc:
            logger.error(
                "[%s] Forward check failed: %s", target.display_name, exc, exc_info=True
            )
            result.error_count += 1

    logger.info(
        "Phase 2 forward check — complete. created=%d updated=%d skipped=%d errors=%d",
        len(result.created),
        len(result.updated),
        result.processed_count - len(result.created) - len(result.updated),
        result.error_count,
    )

    # ── 11.2 Reverse check ────────────────────────────────────────────────────
    logger.info("Phase 2 — Reverse check started")
    open_tickets = jira.get_all_open_snyk_tickets()

    for ticket in open_tickets:
        snyk_id = ticket.snyk_project_id
        if not snyk_id:
            logger.warning(
                "[%s] Missing snyk_project_id field — cannot reverse-check", ticket.key
            )
            continue

        ticket_url = jira.ticket_url(ticket.key)

        if snyk_id not in all_target_ids:
            result.flagged.append(FlaggedTicket(
                target_name=ticket.summary,
                ticket_key=ticket.key,
                ticket_url=ticket_url,
                reason="project_deleted",
            ))
            logger.info("[%s] %s — flagged: project_deleted", ticket.summary, ticket.key)
        elif snyk_id not in {t.id for t in targets}:
            result.flagged.append(FlaggedTicket(
                target_name=ticket.summary,
                ticket_key=ticket.key,
                ticket_url=ticket_url,
                reason="vulns_resolved",
            ))
            logger.info("[%s] %s — flagged: vulns_resolved", ticket.summary, ticket.key)

    logger.info("Phase 2 reverse check — complete. flagged=%d", len(result.flagged))
    return result


def _forward_check_target(
    target: SnykTarget,
    jira: JiraClient,
    current_state: dict,
    result: RunResult,
    today: str,
) -> None:
    state_entry = current_state["targets"].get(target.id, {})

    # Step A — idempotency guard
    if state_entry.get("created_today"):
        logger.info("[%s] Skipping — ticket already created in this run", target.display_name)
        return

    # Step B — search for existing open ticket
    ticket = jira.find_open_ticket_by_snyk_id(target.id)

    if ticket is None:
        logger.info("[%s] NO ticket found via primary search — trying fallback", target.display_name)
        ticket = jira.find_open_ticket_by_name(target.display_name)
        if ticket is not None:
            jira.backfill_snyk_project_id(ticket.key, target.id)

    # Step C — branch
    if ticket is None:
        _create_ticket(target, jira, current_state, result, today)
    else:
        old_c = state_entry.get("critical", 0)
        old_h = state_entry.get("high", 0)
        if target.critical != old_c or target.high != old_h:
            _update_ticket(target, ticket.key, old_c, old_h, jira, current_state, result, today)
        else:
            current_state["targets"][target.id]["last_synced"] = today
            logger.info(
                "[%s] Ticket %s — SAME counts C%dH%d → skip",
                target.display_name, ticket.key, target.critical, target.high,
            )


def _create_ticket(
    target: SnykTarget,
    jira: JiraClient,
    current_state: dict,
    result: RunResult,
    today: str,
) -> None:
    summary = _build_summary(target.display_name, target.critical, target.high, today)
    description = _build_adf_description(target)
    custom_fields = {
        config.JIRA_FIELD_SNYK_PROJECT_ID: target.id,
        config.JIRA_FIELD_SNYK_CRITICAL_COUNT: target.critical,
        config.JIRA_FIELD_SNYK_HIGH_COUNT: target.high,
        config.JIRA_FIELD_SNYK_LAST_SYNCED: today,
    }
    key = jira.create_ticket(summary, description, custom_fields)
    logger.info("[%s] NO ticket found → created %s", target.display_name, key)

    entry = state.upsert_target(current_state, target.id, target.display_name)
    entry["jira_ticket"] = key
    entry["created_today"] = True
    entry["critical"] = target.critical
    entry["high"] = target.high
    entry["last_changed"] = today
    entry["last_synced"] = today

    result.created.append(CreatedTicket(
        target_name=target.display_name,
        ticket_key=key,
        ticket_url=jira.ticket_url(key),
        snyk_url=_snyk_target_url(target.id),
        critical=target.critical,
        high=target.high,
    ))


def _update_ticket(
    target: SnykTarget,
    ticket_key: str,
    old_c: int,
    old_h: int,
    jira: JiraClient,
    current_state: dict,
    result: RunResult,
    today: str,
) -> None:
    jira.update_fields(ticket_key, {
        config.JIRA_FIELD_SNYK_CRITICAL_COUNT: target.critical,
        config.JIRA_FIELD_SNYK_HIGH_COUNT: target.high,
        config.JIRA_FIELD_SNYK_LAST_SYNCED: today,
    })
    logger.info(
        "[%s] Ticket %s — CHANGED C%dH%d→C%dH%d → updating fields",
        target.display_name, ticket_key, old_c, old_h, target.critical, target.high,
    )

    entry = current_state["targets"].setdefault(target.id, {})
    entry["critical"] = target.critical
    entry["high"] = target.high
    entry["last_changed"] = today
    entry["last_synced"] = today

    result.updated.append(UpdatedTicket(
        target_name=target.display_name,
        ticket_key=ticket_key,
        ticket_url=jira.ticket_url(ticket_key),
        old_critical=old_c,
        old_high=old_h,
        new_critical=target.critical,
        new_high=target.high,
        snyk_url=_snyk_target_url(target.id),
    ))

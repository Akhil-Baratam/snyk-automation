"""
Phase 3 — Teams notification.

Builds an Adaptive Card summarising the run, enforces the 22 KB size guard,
and finalises the state file in S3.
"""
import json
import logging
from datetime import date

import config
import state
from clients.teams import TeamsClient
from models.run_result import CreatedTicket, FlaggedTicket, RunResult, UpdatedTicket

logger = logging.getLogger(__name__)


def run_notify(result: RunResult, current_state: dict) -> None:
    logger.info("Phase 3 — Building Teams card")

    is_partial = result.processed_count < current_state.get("total_count", 0)
    today_label = date.today().strftime("%d %b %Y")

    header = _build_header_card(result, today_label, is_partial)
    created_card = _build_created_card(result.created) if result.created else None
    updated_card = _build_updated_card(result.updated) if result.updated else None
    flagged_card = _build_flagged_card(result.flagged) if result.flagged else None

    teams = TeamsClient()
    teams.send_or_split(header, created_card, updated_card, flagged_card)

    current_state["run_status"] = "complete"
    current_state["processed_count"] = result.processed_count
    state.upload_state(current_state)

    logger.info(
        "✓ Run complete. Processed %d/%d targets.",
        result.processed_count,
        current_state.get("total_count", 0),
    )


# ── Card builders ─────────────────────────────────────────────────────────────

def _build_header_card(result: RunResult, today_label: str, is_partial: bool) -> dict:
    facts = [
        {"title": "📅 Date", "value": today_label},
        {"title": "🔴 New tickets", "value": str(len(result.created))},
        {"title": "🟡 Count changed", "value": str(len(result.updated))},
        {"title": "🔵 Flagged for review", "value": str(len(result.flagged))},
    ]

    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": "Snyk Automation — Daily Results",
            "weight": "Bolder",
            "size": "Large",
            "wrap": True,
        },
        {"type": "FactSet", "facts": facts},
    ]

    if is_partial:
        body.append({
            "type": "TextBlock",
            "text": (
                f"⚠️ WARNING: Partial run — processed "
                f"{result.processed_count}/{result.processed_count + result.error_count} targets. "
                f"Check logs."
            ),
            "color": "Attention",
            "weight": "Bolder",
            "wrap": True,
        })

    return _wrap_adaptive_card(body)


def _build_created_card(items: list[CreatedTicket]) -> dict:
    rows = []
    for item in items:
        rows.append({
            "type": "ColumnSet",
            "columns": [
                _col(f"[{item.target_name}]({item.snyk_url})", width="stretch"),
                _col(f"[{item.ticket_key}]({item.ticket_url})", width="auto"),
                _col(f"C{item.critical} H{item.high}", width="auto"),
            ],
        })

    body: list[dict] = [
        {"type": "TextBlock", "text": "🔴 New Tickets Created", "weight": "Bolder", "size": "Medium"},
        _header_row(["Project", "Ticket", "Severity"]),
        *rows,
    ]
    return _wrap_adaptive_card(body)


def _build_updated_card(items: list[UpdatedTicket]) -> dict:
    rows = []
    for item in items:
        rows.append({
            "type": "ColumnSet",
            "columns": [
                _col(f"[{item.target_name}]({item.snyk_url})", width="stretch"),
                _col(f"[{item.ticket_key}]({item.ticket_url})", width="auto"),
                _col(
                    f"C{item.old_critical}H{item.old_high} → C{item.new_critical}H{item.new_high}",
                    width="auto",
                ),
            ],
        })

    body: list[dict] = [
        {"type": "TextBlock", "text": "🟡 Existing Tickets — Count Changed", "weight": "Bolder", "size": "Medium"},
        _header_row(["Project", "Ticket", "Old → New Count"]),
        *rows,
    ]
    return _wrap_adaptive_card(body)


def _build_flagged_card(items: list[FlaggedTicket]) -> dict:
    reason_labels = {
        "project_deleted": "Project deleted/renamed in Snyk",
        "vulns_resolved": "All C/H vulns resolved",
    }
    rows = []
    for item in items:
        rows.append({
            "type": "ColumnSet",
            "columns": [
                _col(item.target_name, width="stretch"),
                _col(f"[{item.ticket_key}]({item.ticket_url})", width="auto"),
                _col(reason_labels.get(item.reason, item.reason), width="stretch"),
            ],
        })

    body: list[dict] = [
        {"type": "TextBlock", "text": "🔵 Tickets to Review for Closure", "weight": "Bolder", "size": "Medium"},
        {"type": "TextBlock", "text": "Please close these tickets manually if appropriate.", "wrap": True, "isSubtle": True},
        _header_row(["Project", "Ticket", "Reason"]),
        *rows,
    ]
    return _wrap_adaptive_card(body)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wrap_adaptive_card(body: list[dict]) -> dict:
    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.5",
            "body": body,
        },
    }


def _col(text: str, width: str = "auto") -> dict:
    return {
        "type": "Column",
        "width": width,
        "items": [{"type": "TextBlock", "text": text, "wrap": True}],
    }


def _header_row(labels: list[str]) -> dict:
    return {
        "type": "ColumnSet",
        "style": "emphasis",
        "columns": [
            {
                "type": "Column",
                "width": "stretch" if i == 0 else "auto",
                "items": [{"type": "TextBlock", "text": lbl, "weight": "Bolder"}],
            }
            for i, lbl in enumerate(labels)
        ],
    }

"""
Phase 3 — Teams notification.

Builds Adaptive Cards summarising the run (new tickets, count changes,
flagged tickets), applies the 22 KB size guard, and finalises state in S3.

Card style per §14:
  - Header: bold summary with counts
  - New tickets section: red accent
  - Count changed section: amber accent
  - Flagged section: blue accent
  - Partial-run warning: prominent red/orange block
"""
import logging
from datetime import date

import state
from clients.teams import TeamsClient, wrap_adaptive_card
from models.run_result import CreatedTicket, FlaggedTicket, RunResult, UpdatedTicket

logger = logging.getLogger(__name__)


def run_notify(result: RunResult, current_state: dict) -> None:
    logger.info("Phase 3 — Building Teams card")

    total = current_state.get("total_count", 0)
    is_partial = result.processed_count < total
    today_label = date.today().strftime("%d %b %Y")

    header_card = _build_header_card(result, today_label, is_partial, total)
    created_card = _build_created_card(result.created) if result.created else None
    updated_card = _build_updated_card(result.updated) if result.updated else None
    flagged_card = _build_flagged_card(result.flagged) if result.flagged else None

    teams = TeamsClient()
    teams.send_or_split(header_card, created_card, updated_card, flagged_card)
    logger.info("Teams notification sent successfully")

    current_state["run_status"] = "complete"
    current_state["processed_count"] = result.processed_count
    state.upload_state(current_state)
    logger.info(
        "State finalised. run_status=complete. Uploaded to S3."
    )
    logger.info(
        "✓ Run complete. Processed %d/%d targets.",
        result.processed_count,
        total,
    )


# ── Card builders ─────────────────────────────────────────────────────────────

def _build_header_card(
    result: RunResult,
    today_label: str,
    is_partial: bool,
    total: int,
) -> dict:
    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": f"📊 Snyk Automation — {today_label}",
            "weight": "Bolder",
            "size": "Large",
            "wrap": True,
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "🔴 New tickets created", "value": str(len(result.created))},
                {"title": "🟡 Count changed",       "value": str(len(result.updated))},
                {"title": "🔵 Flagged for review",  "value": str(len(result.flagged))},
                {"title": "Targets processed",      "value": f"{result.processed_count}/{total}"},
            ],
        },
    ]

    if is_partial:
        body.append({
            "type": "TextBlock",
            "text": (
                f"⚠️ WARNING: Partial run — only {result.processed_count}/{total} targets "
                f"processed ({result.error_count} error(s)). Check logs."
            ),
            "color": "Attention",
            "weight": "Bolder",
            "wrap": True,
        })

    if result.error_count > 0 and not is_partial:
        body.append({
            "type": "TextBlock",
            "text": f"⚠️ {result.error_count} target(s) failed to process — see logs.",
            "color": "Warning",
            "wrap": True,
        })

    return wrap_adaptive_card(body)


def _build_created_card(items: list[CreatedTicket]) -> dict:
    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": "🔴 New Tickets Created",
            "weight": "Bolder",
            "size": "Medium",
            "color": "Attention",
        },
        _header_columns(["Project", "Ticket", "Severity"]),
    ]
    for item in items:
        body.append(_columns([
            f"[{item.target_name}]({item.snyk_url})",
            f"[{item.ticket_key}]({item.ticket_url})",
            f"C{item.critical} H{item.high}",
        ]))
    return wrap_adaptive_card(body)


def _build_updated_card(items: list[UpdatedTicket]) -> dict:
    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": "🟡 Existing Tickets — Count Changed",
            "weight": "Bolder",
            "size": "Medium",
            "color": "Warning",
        },
        _header_columns(["Project", "Ticket", "Old → New"]),
    ]
    for item in items:
        body.append(_columns([
            f"[{item.target_name}]({item.snyk_url})",
            f"[{item.ticket_key}]({item.ticket_url})",
            f"C{item.old_critical}H{item.old_high} → C{item.new_critical}H{item.new_high}",
        ]))
    return wrap_adaptive_card(body)


def _build_flagged_card(items: list[FlaggedTicket]) -> dict:
    _reason_labels = {
        "project_deleted": "Project deleted/renamed in Snyk",
        "vulns_resolved": "All C/H vulns resolved",
    }
    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": "🔵 Tickets to Review for Closure",
            "weight": "Bolder",
            "size": "Medium",
            "color": "Accent",
        },
        {
            "type": "TextBlock",
            "text": "Please close these tickets manually if appropriate.",
            "isSubtle": True,
            "wrap": True,
        },
        _header_columns(["Project", "Ticket", "Reason"]),
    ]
    for item in items:
        body.append(_columns([
            item.target_name,
            f"[{item.ticket_key}]({item.ticket_url})",
            _reason_labels.get(item.reason, item.reason),
        ]))
    return wrap_adaptive_card(body)


# ── Layout helpers ────────────────────────────────────────────────────────────

def _header_columns(labels: list[str]) -> dict:
    return {
        "type": "ColumnSet",
        "style": "emphasis",
        "columns": [
            {
                "type": "Column",
                "width": "stretch" if i == 0 else "auto",
                "items": [{"type": "TextBlock", "text": lbl, "weight": "Bolder", "wrap": True}],
            }
            for i, lbl in enumerate(labels)
        ],
    }


def _columns(values: list[str]) -> dict:
    return {
        "type": "ColumnSet",
        "columns": [
            {
                "type": "Column",
                "width": "stretch" if i == 0 else "auto",
                "items": [{"type": "TextBlock", "text": v, "wrap": True}],
            }
            for i, v in enumerate(values)
        ],
    }

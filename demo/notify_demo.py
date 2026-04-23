"""
DEMO VERSION: Phase 3 — Teams Notification.

Header block (always shown):
  - Run date, Processed count
  - Created / Updated / Flagged counts

Tables (only shown when they have data rows):
  - New Tickets Created      → columns: Project | Jira Ticket | Snyk | Severity
  - Count Changed            → columns: Project | Jira Ticket | Old | New | Snyk
  - Flagged for Closure      → columns: Project | Jira Ticket | Reason
"""
import json
import logging
from datetime import date

logger = logging.getLogger(__name__)


# ── Table builders ────────────────────────────────────────────────────────────

def _header_cell(text: str) -> dict:
    return {
        "type": "TableCell",
        "style": "emphasis",
        "items": [{"type": "TextBlock", "text": text, "weight": "Bolder", "wrap": True}],
    }


def _cell(text: str, url: str | None = None) -> dict:
    if url:
        content = {"type": "TextBlock", "text": f"[{text}]({url})", "wrap": True}
    else:
        content = {"type": "TextBlock", "text": text, "wrap": True}
    return {"type": "TableCell", "items": [content]}


def _table(columns: list, header_cells: list, data_rows: list) -> dict:
    header_row = {
        "type": "TableRow",
        "style": "emphasis",
        "cells": [_header_cell(h) for h in header_cells],
    }
    rows = [header_row] + [
        {"type": "TableRow", "cells": row_cells}
        for row_cells in data_rows
    ]
    return {
        "type": "Table",
        "columns": [{"width": w} for w in columns],
        "rows": rows,
        "showGridLines": True,
        "firstRowAsHeaders": True,
        "spacing": "Small",
    }


def _section_heading(text: str, color: str = "Default") -> dict:
    return {
        "type": "TextBlock",
        "text": text,
        "weight": "Bolder",
        "color": color,
        "spacing": "Large",
        "wrap": True,
    }


# ── Main notify function ──────────────────────────────────────────────────────

def notify_demo(teams, sync_result: dict) -> None:
    temp_created = sync_result.get("temp_created", [])
    temp_updated = sync_result.get("temp_updated", [])
    temp_flagged = sync_result.get("temp_flagged", [])
    processed    = sync_result.get("processed_count", 0)
    errors       = sync_result.get("error_count", 0)

    logger.info("=" * 80)
    logger.info("PHASE 3 — Teams Notification (Demo)")
    logger.info("=" * 80)

    today = date.today().strftime("%Y-%m-%d")
    body  = []

    # ── Header — ALWAYS SHOWN ─────────────────────────────────────────────────
    body.append({
        "type": "TextBlock",
        "text": "📅 Snyk Automation — Demo Results",
        "weight": "Bolder",
        "size": "Large",
        "color": "Good" if not errors else "Warning",
    })
    body.append({
        "type": "TextBlock",
        "text": f"Run: {today}  |  Processed: {processed}",
        "spacing": "Small",
        "isSubtle": True,
    })

    # Counts — ALWAYS SHOWN (even when all zeros)
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "🟢 Created",  "value": str(len(temp_created))},
            {"title": "🟡 Updated",  "value": str(len(temp_updated))},
            {"title": "🔵 Flagged",  "value": str(len(temp_flagged))},
        ],
        "spacing": "Medium",
    })

    if errors:
        body.append({
            "type": "TextBlock",
            "text": f"⚠️ {errors} target(s) failed to process — check logs",
            "color": "Attention",
            "wrap": True,
            "spacing": "Small",
        })

    # ── New Tickets Created — table only if rows exist ────────────────────────
    if temp_created:
        body.append(_section_heading("✅ New Tickets Created", color="Good"))
        rows = [
            [
                _cell(item["target_name"]),
                _cell(item["ticket_key"], url=item["ticket_url"]),
                _cell("View", url=item["snyk_url"]),
                _cell(f"C{item['critical']} H{item['high']}"),
            ]
            for item in temp_created
        ]
        body.append(_table(
            columns=[4, 2, 1, 2],
            header_cells=["Project Name", "Jira Ticket", "Snyk", "Severity"],
            data_rows=rows,
        ))

    # ── Count Changed — table only if rows exist ──────────────────────────────
    if temp_updated:
        body.append(_section_heading("🔄 Existing Tickets — Count Changed", color="Warning"))
        rows = [
            [
                _cell(item["target_name"]),
                _cell(item["ticket_key"], url=item["ticket_url"]),
                _cell(f"C{item['old_critical']} H{item['old_high']}"),
                _cell(f"C{item['new_critical']} H{item['new_high']}"),
                _cell("View", url=item["snyk_url"]),
            ]
            for item in temp_updated
        ]
        body.append(_table(
            columns=[4, 2, 2, 2, 1],
            header_cells=["Project Name", "Jira Ticket", "Old Count", "New Count", "Snyk"],
            data_rows=rows,
        ))

    # ── Flagged for Closure — table only if rows exist ────────────────────────
    if temp_flagged:
        body.append(_section_heading("🚩 Flagged for Review / Closure", color="Attention"))
        rows = [
            [
                _cell(item["target_name"]),
                _cell(item["ticket_key"], url=item["ticket_url"]),
                _cell(item.get("reason", "-")),
            ]
            for item in temp_flagged
        ]
        body.append(_table(
            columns=[4, 2, 3],
            header_cells=["Project Name", "Jira Ticket", "Reason"],
            data_rows=rows,
        ))

    # ── Build & send ──────────────────────────────────────────────────────────
    card = {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.5",
            "body": body,
        },
    }

    size = len(json.dumps({"type": "message", "attachments": [card]}).encode("utf-8"))
    logger.info("Card payload: %d bytes", size)
    teams.send_card(card)
    logger.info("Phase 3 complete")
"""
Phase 3 -- Teams notification.

Builds an Adaptive Card with a header plus up to two sections:
  - New Tickets Created
  - Existing Tickets -- Count Changed

If the combined payload exceeds TEAMS_CARD_SIZE_LIMIT_BYTES, sections are
greedily split across multiple cards. Each card's full JSON is logged
before it's sent.
"""
import json
import logging
import time
from datetime import date

import config
from clients.teams import TeamsClient, wrap_adaptive_card
from models.run_result import RunResult

logger = logging.getLogger(__name__)
_INTER_CARD_DELAY = 0.5  # seconds between split sends (Teams: 4 req/s)


def run_notify(result: RunResult) -> None:
    header   = _build_header(result)
    sections = _build_sections(result)

    if not sections:
        cards_body = [header + [_no_data_block()]]
    else:
        cards_body = _pack(header, sections)

    teams = TeamsClient()
    total = len(cards_body)
    for i, body in enumerate(cards_body, start=1):
        if total > 1:
            body = [_part_marker(i, total)] + body
        card = wrap_adaptive_card(body)
        _log_card(i, total, card)
        teams.send_card(card)
        if i < total:
            time.sleep(_INTER_CARD_DELAY)
    logger.info("Phase 3 -- notification sent (%d card(s))", total)


# ── Body builders ────────────────────────────────────────────────────────────

def _build_header(result: RunResult) -> list[dict]:
    today = date.today().strftime("%d %b %Y")
    blocks: list[dict] = [
        {"type": "TextBlock", "text": f"Snyk Automation -- {today}",
         "weight": "Bolder", "size": "Large"},
        {"type": "FactSet", "facts": [
            {"title": "Created",   "value": str(len(result.created))},
            {"title": "Changed",   "value": str(len(result.changed))},
            {"title": "Processed", "value": str(result.processed_count)},
        ]},
    ]
    if result.error_count:
        blocks.append({
            "type": "TextBlock",
            "text": f"{result.error_count} target(s) failed to process -- check logs",
            "color": "Attention", "wrap": True, "spacing": "Small",
        })
    return blocks


def _build_sections(result: RunResult) -> list[list[dict]]:
    sections: list[list[dict]] = []
    if result.created:
        sections.append([
            _heading("New Tickets Created", "Good"),
            _table([4, 2, 2], ["Repository", "Ticket", "Severity"], [
                [_cell(c.target_name),
                 _cell(c.ticket_key, url=c.ticket_url),
                 _cell(f"C{c.critical} H{c.high}")]
                for c in result.created
            ]),
        ])
    if result.changed:
        sections.append([
            _heading("Existing Tickets -- Count Changed", "Warning"),
            _table([4, 2, 2, 2], ["Repository", "Ticket", "Old", "New"], [
                [_cell(c.target_name),
                 _cell(c.ticket_key, url=c.ticket_url),
                 _cell(f"C{c.old_critical} H{c.old_high}"),
                 _cell(f"C{c.new_critical} H{c.new_high}")]
                for c in result.changed
            ]),
        ])
    return sections


# ── Packing (size-aware split) ───────────────────────────────────────────────

def _pack(header: list[dict], sections: list[list[dict]]) -> list[list[dict]]:
    """Greedy: combine header + sections into cards, opening a new card
    whenever the next section would exceed the byte limit."""
    limit = config.TEAMS_CARD_SIZE_LIMIT_BYTES
    cards: list[list[dict]] = []
    current = list(header)

    for section in sections:
        candidate = current + section
        if _size(candidate) <= limit:
            current = candidate
        else:
            cards.append(current)
            if _size(section) > limit:
                logger.warning(
                    "Section size %d exceeds limit %d -- sending unsplit",
                    _size(section), limit,
                )
            current = list(section)

    cards.append(current)
    return cards


def _size(body: list[dict]) -> int:
    payload = {"type": "message", "attachments": [wrap_adaptive_card(body)]}
    return len(json.dumps(payload).encode("utf-8"))


# ── Logging ──────────────────────────────────────────────────────────────────

def _log_card(idx: int, total: int, card: dict) -> None:
    payload = {"type": "message", "attachments": [card]}
    pretty  = json.dumps(payload, indent=2)
    logger.info("Card %d/%d (%d bytes):\n%s",
                idx, total, len(pretty.encode("utf-8")), pretty)


# ── Adaptive Card helpers ────────────────────────────────────────────────────

def _part_marker(i: int, total: int) -> dict:
    return {"type": "TextBlock", "text": f"Part {i} of {total}",
            "isSubtle": True, "weight": "Bolder", "spacing": "Small"}


def _heading(text: str, color: str) -> dict:
    return {"type": "TextBlock", "text": text, "weight": "Bolder",
            "color": color, "spacing": "Large", "wrap": True}


def _no_data_block() -> dict:
    return {"type": "TextBlock", "text": "No new or changed tickets today.",
            "isSubtle": True, "spacing": "Medium"}


def _cell(text: str, url: str | None = None) -> dict:
    inner = {"type": "TextBlock",
             "text": f"[{text}]({url})" if url else text, "wrap": True}
    return {"type": "TableCell", "items": [inner]}


def _table(widths: list[int], headers: list[str], rows: list[list[dict]]) -> dict:
    header_cells = [
        {"type": "TableCell", "style": "emphasis",
         "items": [{"type": "TextBlock", "text": h, "weight": "Bolder", "wrap": True}]}
        for h in headers
    ]
    return {
        "type": "Table",
        "columns": [{"width": w} for w in widths],
        "rows": [{"type": "TableRow", "style": "emphasis", "cells": header_cells}]
              + [{"type": "TableRow", "cells": r} for r in rows],
        "showGridLines": True,
        "firstRowAsHeaders": True,
        "spacing": "Small",
    }

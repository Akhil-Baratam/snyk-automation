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
_MAX_ROWS_PER_SECTION = 22


def run_notify(result: RunResult, dry_run: bool = False) -> None:
    header   = _build_header(result)
    sections = _build_sections(result)

    if not sections:
        cards_body = [header + [_no_data_block()]]
    else:
        cards_body = _pack(header, sections)

    teams = TeamsClient() if not dry_run else None
    total = len(cards_body)
    for i, body in enumerate(cards_body, start=1):
        if total > 1:
            body = [_part_marker(i, total)] + body
        card = wrap_adaptive_card(body)
        _log_card(i, total, card)
        if dry_run:
            logger.info("DRY-RUN -- card %d/%d not sent", i, total)
        else:
            teams.send_card(card)
            if i < total:
                time.sleep(_INTER_CARD_DELAY)
    logger.info("Phase 3 -- %s (%d card(s))",
                "DRY-RUN complete" if dry_run else "notification sent", total)


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
        all_rows = [[c.target_name, c.ticket_key] for c in result.created]
        all_urls = [[None, c.ticket_url] for c in result.created]
        for i, (rows, urls) in enumerate(_chunks(all_rows, all_urls)):
            heading = "New Tickets Created" if i == 0 else "New Tickets Created (cont.)"
            sections.append(
                [_heading(heading, "Good")]
                + _table([5, 3], ["Repository", "Ticket"], rows, urls)
            )

    if result.changed:
        all_rows = [[c.target_name, c.ticket_key] for c in result.changed]
        all_urls = [[None, c.ticket_url] for c in result.changed]
        for i, (rows, urls) in enumerate(_chunks(all_rows, all_urls)):
            heading = "Existing Tickets -- Count Changed" if i == 0 else "Existing Tickets -- Count Changed (cont.)"
            sections.append(
                [_heading(heading, "Warning")]
                + _table([5, 3], ["Repository", "Ticket"], rows, urls)
            )

    return sections


def _chunks(rows: list, urls: list) -> list[tuple]:
    for i in range(0, len(rows), _MAX_ROWS_PER_SECTION):
        yield rows[i:i + _MAX_ROWS_PER_SECTION], urls[i:i + _MAX_ROWS_PER_SECTION]


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
    payload    = {"type": "message", "attachments": [card]}
    wire_bytes = len(json.dumps(payload).encode("utf-8"))
    pretty     = json.dumps(payload, indent=2)
    logger.info("Card %d/%d (%d bytes on wire):\n%s",
                idx, total, wire_bytes, pretty)


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


def _col(text: str, width: int, bold: bool = False, url: str | None = None) -> dict:
    display = f"[{text}]({url})" if url else text
    return {
        "type": "Column", "width": width,
        "items": [{"type": "TextBlock", "text": display,
                   "wrap": True, "weight": "Bolder" if bold else "Default"}],
    }


def _table(widths: list[int], headers: list[str], rows: list[list[str]],
           urls: list[list[str | None]] | None = None) -> list[dict]:
    """Returns a list of ColumnSet blocks (header row + data rows)."""
    blocks: list[dict] = []
    # header row
    blocks.append({
        "type": "ColumnSet", "spacing": "Small",
        "columns": [_col(h, w, bold=True) for h, w in zip(headers, widths)],
    })
    for i, row in enumerate(rows):
        row_urls = urls[i] if urls else [None] * len(row)
        blocks.append({
            "type": "ColumnSet", "spacing": "Small",
            "columns": [_col(text, w, url=u)
                        for text, w, u in zip(row, widths, row_urls)],
        })
    return blocks

"""
Microsoft Teams Incoming Webhook client.

Sends Adaptive Card payloads, enforcing the 22 KB size limit by splitting
into per-section cards when the payload would exceed it.
"""
import json
import logging
import time

import requests

import config
from utils.retry import with_retry

logger = logging.getLogger(__name__)

_INTER_CARD_DELAY = 0.5  # seconds — respects Teams 4 req/s limit


class TeamsClient:
    def __init__(self) -> None:
        self._webhook_url = config.TEAMS_WEBHOOK_URL
        self._session = requests.Session()

    # ── Low-level send ────────────────────────────────────────────────────────

    def _post(self, payload: dict) -> None:
        def _call() -> None:
            resp = self._session.post(
                self._webhook_url,
                json=payload,
                timeout=15,
            )
            resp.raise_for_status()
        with_retry(_call)

    def check_reachability(self) -> None:
        """POST an empty payload — Teams acknowledges connectivity."""
        self._post({})

    # ── Card dispatch ─────────────────────────────────────────────────────────

    def send_card(self, card: dict) -> None:
        """
        Send a single Adaptive Card.  If the serialised payload exceeds
        TEAMS_CARD_SIZE_LIMIT_BYTES the caller should split it first.
        """
        self._post({"type": "message", "attachments": [card]})
        logger.info("Teams card sent (%d bytes)", _card_bytes(card))

    def send_or_split(
        self,
        header_card: dict,
        created_card: dict | None,
        updated_card: dict | None,
        flagged_card: dict | None,
    ) -> None:
        """
        Try to send a single consolidated card.  Fall back to per-section
        cards if the combined payload is too large.
        """
        full = _merge_cards(header_card, created_card, updated_card, flagged_card)
        size = _card_bytes(full)

        if size <= config.TEAMS_CARD_SIZE_LIMIT_BYTES:
            logger.info("Card size %d bytes — within limit, sending single card", size)
            self.send_card(full)
            return

        logger.info(
            "Card size %d bytes exceeds limit %d — splitting into sections",
            size,
            config.TEAMS_CARD_SIZE_LIMIT_BYTES,
        )
        self.send_card(header_card)
        sections = [
            (created_card, "Part 1 — New Tickets"),
            (updated_card, "Part 2 — Count Changed"),
            (flagged_card, "Part 3 — Flagged for Closure"),
        ]
        for card, label in sections:
            if card is None:
                continue
            time.sleep(_INTER_CARD_DELAY)
            logger.info("Sending %s card", label)
            self.send_card(card)

    # ── Failure alert ─────────────────────────────────────────────────────────

    def send_failure_alert(self, phase: str, error: str, timestamp: str) -> None:
        """
        Minimal failure card — no imports from other phase modules.
        Safe to call from any phase.
        """
        card = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.5",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "🚨 Snyk Automation Failed",
                    "weight": "Bolder",
                    "size": "Large",
                    "color": "Attention",
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Phase", "value": phase},
                        {"title": "Time", "value": timestamp},
                        {"title": "Error", "value": error},
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": "⚠️ Action required: Manual Snyk → Jira reconciliation needed.",
                    "wrap": True,
                    "color": "Warning",
                },
            ],
        }
        try:
            self._post({
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }],
            })
            logger.info("Failure alert sent to Teams (phase=%s)", phase)
        except Exception as exc:
            logger.error("Could not send failure alert to Teams: %s", exc)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _card_bytes(card: dict) -> int:
    return len(json.dumps(card).encode("utf-8"))


def _merge_cards(*cards: dict | None) -> dict:
    """Combine body blocks from multiple Adaptive Cards into one."""
    merged_body: list[dict] = []
    base: dict | None = None
    for card in cards:
        if card is None:
            continue
        if base is None:
            base = dict(card)
            merged_body.extend(card.get("body", []))
        else:
            merged_body.extend(card.get("body", []))
    result = base or {}
    result["body"] = merged_body
    return result

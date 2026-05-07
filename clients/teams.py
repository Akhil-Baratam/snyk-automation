"""
Microsoft Teams Incoming Webhook client.

Sends Adaptive Card payloads. One card per run.
"""
import json
import logging

import requests

import config
from utils.retry import with_retry

logger = logging.getLogger(__name__)


class TeamsClient:
    def __init__(self) -> None:
        self._webhook_url = config.TEAMS_WEBHOOK_URL
        self._session = requests.Session()

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _post(self, payload: dict) -> None:
        def _call() -> None:
            resp = self._session.post(self._webhook_url, json=payload, timeout=15)
            resp.raise_for_status()
        with_retry(_call)

    # ── Public API ────────────────────────────────────────────────────────────

    def check_reachability(self) -> None:
        self.send_card(wrap_adaptive_card([
            {"type": "TextBlock", "text": "Snyk Automation -- Connectivity Test",
             "weight": "Bolder", "size": "Medium"},
            {"type": "TextBlock", "text": "Teams webhook is reachable.", "wrap": True},
        ]))

    def send_card(self, card: dict) -> None:
        payload = {"type": "message", "attachments": [card]}
        self._post(payload)
        size = len(json.dumps(payload).encode("utf-8"))
        logger.info("Teams card sent (%d bytes)", size)

    def send_failure_alert(self, phase: str, error: str, timestamp: str) -> None:
        """Best-effort alert. Catches its own exceptions."""
        card = wrap_adaptive_card([
            {"type": "TextBlock", "text": "Snyk Automation Failed",
             "weight": "Bolder", "size": "Large", "color": "Attention"},
            {"type": "FactSet", "facts": [
                {"title": "Phase", "value": phase},
                {"title": "Time",  "value": timestamp},
                {"title": "Error", "value": error},
            ]},
        ])
        try:
            self.send_card(card)
        except Exception as exc:
            logger.error("Could not send failure alert to Teams: %s", exc)


def wrap_adaptive_card(body: list[dict]) -> dict:
    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "type":    "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.5",
            "body":    body,
        },
    }

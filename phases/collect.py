"""
Phase 1 — Snyk data collection.

Fetches all org projects, aggregates per target, filters to C/H > 0,
and writes the checkpoint state to S3.
"""
import logging
from datetime import datetime, timedelta, timezone

import config
import state
from clients.snyk import SnykClient
from models.target import SnykTarget

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))


def run_collect(current_state: dict) -> tuple[list[SnykTarget], set[str]]:
    """
    Executes Phase 1.  Mutates current_state in-place and uploads a
    checkpoint to S3 on success.

    Returns:
        (targets_with_vulns, all_target_ids)
        all_target_ids is the unfiltered set — needed by Phase 2 reverse check.

    Raises:
        RuntimeError if Snyk data cannot be fetched after all retries.
    """
    logger.info("Phase 1 — Starting data collection")
    snyk = SnykClient()

    targets, all_target_ids = snyk.get_aggregated_targets()
    today = state.today_str()

    current_state["total_count"] = len(targets)

    for t in targets:
        entry = state.upsert_target(current_state, t.id, t.display_name)
        entry["critical"] = t.critical
        entry["high"] = t.high
        if entry.get("last_synced") is None:
            entry["last_synced"] = today

    current_state["run_status"] = "partial"
    state.upload_state(current_state)
    logger.info(
        "Phase 1 — Complete. total_count=%d. State uploaded to S3.",
        len(targets),
    )
    return targets, all_target_ids

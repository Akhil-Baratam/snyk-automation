"""
Phase 1 — Snyk data collection.

Fetches all org projects, aggregates per target, filters to C/H > 0,
and writes the Phase 1 checkpoint state to S3.

last_synced is intentionally NOT set here — Phase 2 owns that field
and updates it after each successful Jira sync.
"""
import logging

import state
from clients.snyk import SnykClient
from models.target import SnykTarget

logger = logging.getLogger(__name__)


def run_collect(current_state: dict) -> tuple[list[SnykTarget], set[str]]:
    """
    Executes Phase 1.  Mutates current_state in-place and uploads a
    checkpoint to S3 on success.

    Returns:
        (targets_with_vulns, all_target_ids)
        all_target_ids is the unfiltered full set — needed by Phase 2 reverse
        check to distinguish "clean repo" from "deleted target".

    Raises:
        RuntimeError if Snyk data cannot be fetched after all retries.
    """
    logger.info("Phase 1 — Starting data collection")
    snyk = SnykClient()

    targets, all_target_ids = snyk.get_aggregated_targets()

    current_state["total_count"] = len(targets)

    for t in targets:
        entry = state.upsert_target(current_state, t.id, t.display_name)
        # Update counts in state so delta detection in Phase 2 compares
        # against the current run's snapshot, not stale previous values.
        # Preserve jira_ticket, created_today, last_changed, last_synced.
        entry["critical"] = t.critical
        entry["high"] = t.high

    current_state["run_status"] = "partial"
    state.upload_state(current_state)
    logger.info(
        "Phase 1 — Complete. total_count=%d. State uploaded to S3.",
        len(targets),
    )
    return targets, all_target_ids

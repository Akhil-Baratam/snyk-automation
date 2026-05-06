"""
Phase 1 — Snyk data collection.

Pure fetch + summary log. No state coupling — callers (main.py) own any
state-file checkpoints.
"""
import logging
from pathlib import Path

from clients.snyk import SnykClient
from models.target import SnykTarget

logger = logging.getLogger(__name__)

_SUMMARY_FILE = Path(__file__).parent.parent / "logs" / "phase1_summary.txt"


def run_collect() -> tuple[list[SnykTarget], set[str]]:
    """
    Fetch all targets, aggregate per-target C/H counts, log a summary,
    and write the summary to logs/phase1_summary.txt.

    Returns:
        (targets_with_vulns, all_target_ids)
        all_target_ids is the unfiltered full set — needed by Phase 2's
        reverse check to distinguish "clean repo" from "deleted target".
    """
    logger.info("Phase 1 — Snyk data collection")
    targets, all_target_ids = SnykClient().get_aggregated_targets()
    _emit_summary(targets, all_target_ids)
    return targets, all_target_ids


def _emit_summary(targets: list[SnykTarget], all_target_ids: set[str]) -> None:
    ranked = sorted(
        targets,
        key=lambda t: (-t.critical, -t.high, t.display_name.lower()),
    )
    lines = [f"{t.display_name} - C{t.critical}H{t.high}" for t in ranked]

    logger.info("=" * 78)
    logger.info("Phase 1 Summary -- Targets with C/H vulnerabilities")
    logger.info("=" * 78)
    if lines:
        for line in lines:
            logger.info("  %s", line)
    else:
        logger.info("(no targets with critical or high vulnerabilities)")
    logger.info("=" * 78)
    logger.info(
        "Total: %d/%d target(s) have C/H vulnerabilities",
        len(targets), len(all_target_ids),
    )

    _SUMMARY_FILE.parent.mkdir(exist_ok=True)
    _SUMMARY_FILE.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    logger.info("Phase 1 summary written to %s", _SUMMARY_FILE)

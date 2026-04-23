"""
Entry point — orchestrates all four phases.

Exit codes:
  0 — complete success
  1 — validation failure or phase abort (alert already sent to Teams)
  2 — partial success (processed_count < total_count)
"""
import logging
import sys
from datetime import datetime, timedelta, timezone

import config
from utils.logger import setup_logger

IST = timezone(timedelta(hours=5, minutes=30))


def main() -> int:
    logger = setup_logger(debug=config.DEBUG_LOGGING)
    logger.info("=" * 60)
    logger.info("Snyk → Jira → Teams Automation starting")
    logger.info("=" * 60)

    # Import here so logger is configured before any module-level log calls
    import state
    from clients.teams import TeamsClient
    from phases.collect import run_collect
    from phases.notify import run_notify
    from phases.sync import run_sync
    from phases.validation import run_validation

    teams = TeamsClient()

    def _alert(phase: str, exc: Exception) -> None:
        ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
        teams.send_failure_alert(phase=phase, error=str(exc), timestamp=ts)

    # ── Phase 0: Startup validation ───────────────────────────────────────────
    try:
        run_validation()
    except Exception as exc:
        logger.critical("Phase 0 failed: %s", exc)
        return 1

    # ── Load / prepare state ──────────────────────────────────────────────────
    try:
        current_state = state.load_state()
        state.prepare_for_run(current_state)
    except Exception as exc:
        logger.critical("State initialisation failed: %s", exc)
        _alert("State init", exc)
        return 1

    # ── Phase 1: Snyk data collection ─────────────────────────────────────────
    try:
        targets, all_target_ids = run_collect(current_state)
    except Exception as exc:
        logger.critical("Phase 1 failed: %s", exc)
        current_state["run_status"] = "failed"
        try:
            state.upload_state(current_state)
        except Exception:
            pass
        _alert("Phase 1 — Snyk data collection", exc)
        return 1

    # ── Phase 2: Jira sync ────────────────────────────────────────────────────
    try:
        result = run_sync(targets, all_target_ids, current_state)
    except Exception as exc:
        logger.critical("Phase 2 failed: %s", exc)
        current_state["run_status"] = "failed"
        try:
            state.upload_state(current_state)
        except Exception:
            pass
        _alert("Phase 2 — Jira sync", exc)
        return 1

    # ── Phase 3: Teams notification ───────────────────────────────────────────
    try:
        run_notify(result, current_state)
    except Exception as exc:
        logger.critical("Phase 3 failed: %s", exc)
        return 1

    # ── Exit code ─────────────────────────────────────────────────────────────
    if result.processed_count < current_state.get("total_count", 0):
        logger.warning(
            "Partial run — processed %d/%d targets",
            result.processed_count,
            current_state["total_count"],
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

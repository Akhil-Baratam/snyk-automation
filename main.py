"""
Entry point — orchestrates the four-phase pipeline.

Usage:
  python main.py                # All phases (0-3) — needs S3 state
  python main.py --phase 0      # Validation only
  python main.py --phase 0-1    # Validation + Snyk fetch (no state, no Jira write)
  python main.py --phase 0-2    # + Jira sync (needs state)
  python main.py --phase 0-3    # All phases

Exit codes:
  0 — success    1 — phase abort    2 — partial run
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone

import config
from utils.logger import setup_logger

IST = timezone(timedelta(hours=5, minutes=30))


def _parse_phase_range(s: str) -> tuple[int, int]:
    a, _, b = s.partition("-")
    start, end = int(a), int(b or a)
    if not (0 <= start <= end <= 3):
        raise ValueError(f"Phases must be in range 0-3 (got '{s}')")
    return start, end


def main() -> int:
    parser = argparse.ArgumentParser(description="Snyk -> Jira -> Teams Automation")
    parser.add_argument("--phase", default="0-3",
                        help="Phase range: '0', '0-1', '0-2', '0-3'. Default: 0-3")
    args = parser.parse_args()

    try:
        start, end = _parse_phase_range(args.phase)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    logger = setup_logger(debug=config.DEBUG_LOGGING)
    logger.info("=" * 78)
    logger.info("Snyk Automation -- Phases %d-%d", start, end)
    logger.info("=" * 78)

    # Lazy imports so the logger is configured first
    from clients.teams import TeamsClient
    from phases.collect import run_collect
    from phases.validation import run_validation

    teams = TeamsClient()

    def _alert(phase: str, exc: Exception) -> None:
        ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
        teams.send_failure_alert(phase=phase, error=str(exc), timestamp=ts)

    # ── Phase 0 ──────────────────────────────────────────────────────────────
    if start <= 0 <= end:
        try:
            run_validation(end_phase=end)
        except Exception as exc:
            logger.critical("Phase 0 failed: %s", exc)
            return 1

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    targets: list = []
    all_target_ids: set = set()
    if start <= 1 <= end:
        try:
            targets, all_target_ids = run_collect()
        except Exception as exc:
            logger.critical("Phase 1 failed: %s", exc, exc_info=True)
            _alert("Phase 1 -- Snyk data collection", exc)
            return 1

    # Phase 0/1 stop here — no state, no Jira, no Teams notification
    if end < 2:
        logger.info("Run complete (phases %d-%d)", start, end)
        return 0

    # ── Phases 2-3: state-backed pipeline ────────────────────────────────────
    import state
    from phases.notify import run_notify
    from phases.sync import run_sync

    try:
        current_state = state.load_state()
        state.prepare_for_run(current_state)
    except Exception as exc:
        logger.critical("State initialisation failed: %s", exc)
        _alert("State init", exc)
        return 1

    # Phase 1 checkpoint into state (only when state pipeline is in play)
    if start <= 1 <= end:
        current_state["total_count"] = len(targets)
        for t in targets:
            state.upsert_target(current_state, t.id, t.display_name)
        current_state["run_status"] = "partial"
        try:
            state.upload_state(current_state)
        except Exception as exc:
            logger.critical("Phase 1 state upload failed: %s", exc)
            _alert("Phase 1 -- state upload", exc)
            return 1

    # Phase 2
    result = None
    if start <= 2 <= end:
        try:
            result = run_sync(targets, all_target_ids, current_state)
        except Exception as exc:
            logger.critical("Phase 2 failed: %s", exc)
            current_state["run_status"] = "failed"
            try:
                state.upload_state(current_state)
            except Exception:
                pass
            _alert("Phase 2 -- Jira sync", exc)
            return 1

    # Phase 3
    if start <= 3 <= end and result is not None:
        try:
            run_notify(result, current_state)
        except Exception as exc:
            logger.critical("Phase 3 failed: %s", exc)
            return 1

    if result is not None and result.processed_count < current_state.get("total_count", 0):
        logger.warning("Partial run -- processed %d/%d targets",
                       result.processed_count, current_state["total_count"])
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

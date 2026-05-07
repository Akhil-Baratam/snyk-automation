"""
Entry point — orchestrates the four-phase pipeline.

Usage:
  python main.py                # All phases (0-3)
  python main.py --phase 0      # Validation only
  python main.py --phase 0-1    # Validation + Snyk fetch
  python main.py --phase 0-2    # + Jira sync
  python main.py --phase 0-3    # + Teams notification

Notes:
  * Phase 1 runs implicitly whenever Phase 2 or 3 is requested
    (Phase 2 needs the target list).
  * State lives in Jira itself (label + UUID token in summary).
    Same-day idempotency is provided by logs/today_created.json.

Exit codes:
  0 -- success    1 -- abort    2 -- run completed with target errors
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
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview Phase 2/3 actions without writing to Jira or Teams")
    args = parser.parse_args()

    try:
        start, end = _parse_phase_range(args.phase)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    logger = setup_logger(debug=config.DEBUG_LOGGING)
    logger.info("=" * 78)
    logger.info("Snyk Automation -- Phases %d-%d%s",
                start, end, " (DRY RUN)" if args.dry_run else "")
    logger.info("=" * 78)

    # Lazy imports so the logger is configured first
    from clients.teams import TeamsClient
    from phases.collect import run_collect
    from phases.validation import run_validation

    teams = TeamsClient()

    def _alert(phase: str, exc: Exception) -> None:
        if args.dry_run:
            logger.info("DRY-RUN -- skipping Teams failure alert for %s", phase)
            return
        ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
        teams.send_failure_alert(phase=phase, error=str(exc), timestamp=ts)

    # ── Phase 0 ──────────────────────────────────────────────────────────────
    if start <= 0 <= end:
        try:
            run_validation(end_phase=end, dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 0 failed: %s", exc)
            return 1

    # ── Phase 1 (also runs implicitly when Phase 2 or 3 is requested) ────────
    targets: list = []
    if end >= 1:
        try:
            targets, _ = run_collect()
        except Exception as exc:
            logger.critical("Phase 1 failed: %s", exc, exc_info=True)
            _alert("Phase 1 -- Snyk data collection", exc)
            return 1

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    result = None
    if start <= 2 <= end:
        from phases.sync import run_sync
        try:
            result = run_sync(targets, dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 2 failed: %s", exc, exc_info=True)
            _alert("Phase 2 -- Jira sync", exc)
            return 1

    # ── Phase 3 ──────────────────────────────────────────────────────────────
    if start <= 3 <= end and result is not None:
        from phases.notify import run_notify
        try:
            run_notify(result, dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 3 failed: %s", exc, exc_info=True)
            return 1

    logger.info("Run complete (phases %d-%d)", start, end)
    if result is not None and result.error_count:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

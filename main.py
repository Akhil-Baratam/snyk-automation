"""
Entry point — orchestrates the five-phase pipeline.

Usage:
  python main.py                  # All phases (0-4)
  python main.py --phase 0        # Validation only
  python main.py --phase 0-2      # Validation through Jira sync (range)
  python main.py --phase 0,1,3    # Skip Phase 2 + Phase 4 (explicit set)
  python main.py --phase 1,3      # Snyk fetch + reverse check, nothing else

The --phase argument accepts either a range ('0-4') or a comma-separated set
('0,1,3'). Phase 1 runs implicitly when any later phase is in the set (it
provides the target list everything downstream needs).

State lives in Jira itself (label + UUID token in summary). Same-day
idempotency is provided by logs/today_created.json.

Exit codes:
  0 -- success    1 -- abort    2 -- run completed with target errors
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone

import config
from utils.logger import setup_logger

IST = timezone(timedelta(hours=5, minutes=30))


def _parse_phases(s: str) -> set[int]:
    """Accepts a range ('0-4') or comma-separated set ('0,1,3'). Mixable: '0,2-4'."""
    phases: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            phases.update(range(int(a), int(b) + 1))
        else:
            phases.add(int(part))
    if not phases or any(p < 0 or p > 4 for p in phases):
        raise ValueError(f"Phases must be in 0-4 (got '{s}')")
    return phases


def main() -> int:
    parser = argparse.ArgumentParser(description="Snyk -> Jira -> Teams Automation")
    parser.add_argument("--phase", default="0-4",
                        help="Range '0-4' or set '0,1,3'. Default: 0-4")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview Phase 2/3/4 actions without writing to Jira or Teams")
    args = parser.parse_args()

    try:
        phases = _parse_phases(args.phase)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    logger = setup_logger(debug=config.DEBUG_LOGGING)
    phase_label = ",".join(str(p) for p in sorted(phases))
    logger.info("=" * 78)
    logger.info("Snyk Automation -- Phases %s%s",
                phase_label, " (DRY RUN)" if args.dry_run else "")
    logger.info("=" * 78)

    # Lazy imports so the logger is configured first
    from clients.teams import TeamsClient
    from models.run_result import RunResult
    from phases.collect import run_collect
    from phases.validation import run_validation

    teams = TeamsClient()
    result = RunResult()  # mutated by Phase 2/3, read by Phase 4

    def _alert(phase: str, exc: Exception) -> None:
        if args.dry_run:
            logger.info("DRY-RUN -- skipping Teams failure alert for %s", phase)
            return
        ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
        teams.send_failure_alert(phase=phase, error=str(exc), timestamp=ts)

    # ── Phase 0 ──────────────────────────────────────────────────────────────
    if 0 in phases:
        try:
            run_validation(end_phase=max(phases), dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 0 failed: %s", exc)
            return 1

    # ── Phase 1 (also runs implicitly when any later phase is requested) ─────
    targets: list = []
    all_target_ids: set[str] = set()
    if phases & {1, 2, 3, 4}:
        try:
            targets, all_target_ids = run_collect()
        except Exception as exc:
            logger.critical("Phase 1 failed: %s", exc, exc_info=True)
            _alert("Phase 1 -- Snyk data collection", exc)
            return 1

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    if 2 in phases:
        from phases.sync import run_sync
        try:
            result = run_sync(targets, dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 2 failed: %s", exc, exc_info=True)
            _alert("Phase 2 -- Jira sync", exc)
            return 1

    # ── Phase 3 (reverse check) ──────────────────────────────────────────────
    if 3 in phases:
        from phases.reverse_check import run_reverse_check
        try:
            run_reverse_check(targets, all_target_ids, result, dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 3 failed: %s", exc, exc_info=True)
            _alert("Phase 3 -- Jira reverse check", exc)
            return 1

    # ── Phase 4 (Teams notification) ─────────────────────────────────────────
    if 4 in phases:
        from phases.notify import run_notify
        try:
            run_notify(result, dry_run=args.dry_run)
        except Exception as exc:
            logger.critical("Phase 4 failed: %s", exc, exc_info=True)
            return 1

    logger.info("Run complete (phases %s)", phase_label)
    if result.error_count:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

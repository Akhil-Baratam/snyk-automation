"""
Phase 0 — Startup validation.

Checks only the dependencies needed for the requested phase range:
  end_phase >= 0 -> Snyk
  end_phase >= 2 -> Jira reachability
  end_phase >= 3 -> Teams webhook
"""
import logging
from datetime import datetime, timedelta, timezone

import config
from clients.jira import JiraClient
from clients.snyk import SnykClient
from clients.teams import TeamsClient

logger = logging.getLogger(__name__)
IST = timezone(timedelta(hours=5, minutes=30))


def run_validation(end_phase: int = 3, dry_run: bool = False) -> None:
    teams = TeamsClient()
    logger.info("Phase 0 -- Startup validation (end_phase=%d)%s",
                end_phase, " [DRY RUN]" if dry_run else "")

    _check(SnykClient().check_org_reachability, "Snyk API", teams, dry_run=dry_run)

    if end_phase >= 2:
        if not (config.JIRA_BASE_URL and config.JIRA_USER_EMAIL and config.JIRA_API_TOKEN):
            raise RuntimeError("Jira credentials missing (JIRA_BASE_URL / JIRA_USER_EMAIL / JIRA_API_TOKEN)")
        _check(JiraClient().check_reachability, "Jira API", teams, dry_run=dry_run)
    else:
        logger.info("Phase 0 -- skipping Jira check")

    if end_phase >= 3:
        if not config.TEAMS_WEBHOOK_URL:
            raise RuntimeError("TEAMS_WEBHOOK_URL is not configured")
        if dry_run:
            logger.info("Phase 0 -- skipping Teams reachability (dry-run, no message will be posted)")
        else:
            _check(teams.check_reachability, "Teams webhook", teams, is_teams=True)
    else:
        logger.info("Phase 0 -- skipping Teams check")

    logger.info("Phase 0 -- Validation passed")


def _check(fn, label: str, teams: TeamsClient, *,
           is_teams: bool = False, dry_run: bool = False) -> None:
    logger.info("Phase 0 -- checking %s", label)
    try:
        fn()
    except Exception as exc:
        msg = f"{label} check failed: {exc}"
        logger.error(msg)
        if not is_teams and not dry_run:
            ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
            teams.send_failure_alert(phase="Phase 0", error=msg, timestamp=ts)
        raise RuntimeError(msg) from exc
    logger.info("%s: OK", label)

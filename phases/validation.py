"""
Phase 0 — Startup validation.

Checks only the dependencies needed for the requested phase range.
Fails fast with a Teams alert (where possible) on the first failure.
"""
import logging
from datetime import datetime, timedelta, timezone

import boto3

import config
from clients.jira import JiraClient
from clients.snyk import SnykClient
from clients.teams import TeamsClient

logger = logging.getLogger(__name__)
IST = timezone(timedelta(hours=5, minutes=30))


def run_validation(end_phase: int = 3) -> None:
    """
    Validate external dependencies needed for phases 0..end_phase.

      end_phase >= 0: Snyk
      end_phase >= 2: Jira (incl. custom-field IDs) and S3
      end_phase >= 3: Teams webhook
    """
    teams = TeamsClient()
    logger.info("Phase 0 — Startup validation (end_phase=%d)", end_phase)

    # 1. Snyk — always
    _check(SnykClient().check_org_reachability, "Snyk API", teams)

    # 2. Jira — phases 2+
    if end_phase >= 2:
        _validate_jira(teams)
    else:
        logger.info("Phase 0 — skipping Jira checks")

    # 3. Teams — phases 3+
    if end_phase >= 3:
        if not config.TEAMS_WEBHOOK_URL:
            raise RuntimeError("TEAMS_WEBHOOK_URL is not configured")
        _check(teams.check_reachability, "Teams webhook", teams, is_teams=True)
    else:
        logger.info("Phase 0 — skipping Teams webhook check")

    # 4. S3 — phases 2+
    if end_phase >= 2:
        if not config.S3_BUCKET_NAME:
            raise RuntimeError("S3_BUCKET_NAME is not configured")
        _check(_check_s3_bucket, "S3 bucket", teams)
    else:
        logger.info("Phase 0 — skipping S3 bucket check")

    logger.info("Phase 0 — Validation passed")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_jira(teams: TeamsClient) -> None:
    field_vars = {
        "JIRA_FIELD_SNYK_PROJECT_ID":     config.JIRA_FIELD_SNYK_PROJECT_ID,
        "JIRA_FIELD_SNYK_CRITICAL_COUNT": config.JIRA_FIELD_SNYK_CRITICAL_COUNT,
        "JIRA_FIELD_SNYK_HIGH_COUNT":     config.JIRA_FIELD_SNYK_HIGH_COUNT,
        "JIRA_FIELD_SNYK_LAST_SYNCED":    config.JIRA_FIELD_SNYK_LAST_SYNCED,
    }
    unset = [k for k, v in field_vars.items() if not v or v == "customfield_"]
    if unset:
        msg = f"Jira custom field IDs not configured: {', '.join(unset)}"
        _alert(teams, msg)
        raise RuntimeError(msg)

    jira = JiraClient()
    _check(jira.check_reachability, "Jira API", teams)

    try:
        missing = jira.validate_custom_fields()
    except Exception as exc:
        msg = f"Jira field validation failed: {exc}"
        _alert(teams, msg)
        raise RuntimeError(msg) from exc

    if missing:
        msg = f"Jira custom fields not found in this instance: {', '.join(missing)}"
        _alert(teams, msg)
        raise RuntimeError(msg)
    logger.info("Jira custom fields: all 4 confirmed")


def _check(fn, label: str, teams: TeamsClient, *, is_teams: bool = False) -> None:
    logger.info("Phase 0 — checking %s", label)
    try:
        fn()
    except Exception as exc:
        msg = f"{label} check failed: {exc}"
        logger.error(msg)
        if not is_teams:
            _alert(teams, msg)
        raise RuntimeError(msg) from exc
    logger.info("%s: OK", label)


def _check_s3_bucket() -> None:
    kwargs: dict = {"region_name": config.AWS_REGION}
    if config.AWS_ACCESS_KEY_ID and config.AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = config.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = config.AWS_SECRET_ACCESS_KEY
    boto3.client("s3", **kwargs).head_bucket(Bucket=config.S3_BUCKET_NAME)


def _alert(teams: TeamsClient, error: str) -> None:
    ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
    teams.send_failure_alert(phase="Phase 0", error=error, timestamp=ts)

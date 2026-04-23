"""
Phase 0 — Startup validation.

Checks all external dependencies before any business logic runs.
Fails fast with a Teams alert (where possible) if anything is broken.

Alert policy (per spec §9):
  - Teams failure → log only, cannot self-alert.
  - All other failures → always attempt Teams alert (send_failure_alert
    catches its own errors, so the attempt is always safe).
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


def run_validation() -> None:
    """
    Runs all 6 startup checks in order.
    Raises RuntimeError on the first failure.
    Attempts a Teams failure alert for every failure except Teams itself.
    """
    teams_client = TeamsClient()
    jira_client = JiraClient()
    snyk_client = SnykClient()

    # 1. Config completeness — guaranteed by config.py (exits on import if invalid)
    logger.info("Phase 0 — Startup validation started")

    # 2. Snyk API reachability
    logger.info("Phase 0 — checking Snyk API reachability")
    _check(
        snyk_client.check_org_reachability,
        label="Snyk API",
        teams_client=teams_client,
        is_teams_check=False,
    )
    logger.info("Snyk API: OK")

    # 3. Jira API reachability
    logger.info("Phase 0 — checking Jira API reachability")
    _check(
        jira_client.check_reachability,
        label="Jira API",
        teams_client=teams_client,
        is_teams_check=False,
    )
    logger.info("Jira API: OK")

    # 4. Jira custom fields exist
    logger.info("Phase 0 — verifying Jira custom fields")
    try:
        missing = jira_client.validate_custom_fields()
    except Exception as exc:
        msg = f"Jira field validation failed: {exc}"
        logger.error(msg)
        _send_failure_alert(teams_client, "Phase 0", msg)
        raise RuntimeError(msg) from exc

    if missing:
        msg = f"Jira custom fields not found in this instance: {', '.join(missing)}"
        logger.error(msg)
        _send_failure_alert(teams_client, "Phase 0", msg)
        raise RuntimeError(msg)
    logger.info("Jira custom fields: all 4 confirmed")

    # 5. Teams webhook reachability (checked before S3 so we know if alerting works)
    logger.info("Phase 0 — checking Teams webhook reachability")
    _check(
        teams_client.check_reachability,
        label="Teams webhook",
        teams_client=teams_client,
        is_teams_check=True,  # cannot self-alert if Teams fails
    )
    logger.info("Teams webhook: OK")

    # 6. S3 bucket access
    logger.info("Phase 0 — checking S3 bucket access")
    _check(
        _check_s3_bucket,
        label="S3 bucket",
        teams_client=teams_client,
        is_teams_check=False,
    )
    logger.info("S3 bucket: OK")

    logger.info("Phase 0 — Validation passed")


def _check(func, label: str, teams_client: TeamsClient, is_teams_check: bool) -> None:
    try:
        func()
    except Exception as exc:
        msg = f"{label} check failed: {exc}"
        logger.error(msg)
        if not is_teams_check:
            # send_failure_alert catches its own exceptions — always safe to call
            _send_failure_alert(teams_client, "Phase 0", msg)
        raise RuntimeError(msg) from exc


def _check_s3_bucket() -> None:
    kwargs: dict = {"region_name": config.AWS_REGION}
    if config.AWS_ACCESS_KEY_ID and config.AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = config.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = config.AWS_SECRET_ACCESS_KEY
    s3 = boto3.client("s3", **kwargs)
    s3.head_bucket(Bucket=config.S3_BUCKET_NAME)


def _send_failure_alert(teams_client: TeamsClient, phase: str, error: str) -> None:
    ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
    teams_client.send_failure_alert(phase=phase, error=error, timestamp=ts)

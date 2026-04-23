"""
Phase 0 — Startup validation.

Checks all external dependencies before any business logic runs.
Fails fast with a Teams alert (where possible) if anything is broken.
"""
import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

import config
from clients.jira import JiraClient
from clients.snyk import SnykClient
from clients.teams import TeamsClient

logger = logging.getLogger(__name__)

IST = timezone(timedelta(hours=5, minutes=30))


def run_validation() -> None:
    """
    Runs all 6 startup checks in order.  Raises RuntimeError on the first
    failure (after attempting a Teams alert).
    """
    teams_ok = False
    teams_client = TeamsClient()
    jira_client = JiraClient()
    snyk_client = SnykClient()

    # 1. Config completeness is guaranteed by config.py (exits on import if invalid)

    # 2. Snyk API reachability
    logger.info("Phase 0 — checking Snyk API reachability")
    _check(
        lambda: snyk_client._get(
            f"{config.SNYK_API_BASE_URL}/rest/orgs/{config.SNYK_ORG_ID}",
            params={"version": "2024-10-15"},
        ),
        label="Snyk API",
        teams_client=teams_client,
        teams_ok=teams_ok,
    )
    logger.info("Snyk API: OK")

    # 3. Jira API reachability
    logger.info("Phase 0 — checking Jira API reachability")
    _check(
        jira_client.check_reachability,
        label="Jira API",
        teams_client=teams_client,
        teams_ok=teams_ok,
    )
    logger.info("Jira API: OK")

    # 4. Jira custom fields exist
    logger.info("Phase 0 — verifying Jira custom fields")
    missing = jira_client.validate_custom_fields()
    if missing:
        msg = f"Jira custom fields not found: {', '.join(missing)}"
        logger.error(msg)
        _send_failure_alert(teams_client, "Phase 0", msg)
        raise RuntimeError(msg)
    logger.info("Jira custom fields: all 4 confirmed")

    # 5. Teams webhook reachability
    logger.info("Phase 0 — checking Teams webhook reachability")
    try:
        teams_client.check_reachability()
        teams_ok = True
        logger.info("Teams webhook: OK")
    except Exception as exc:
        logger.error("Teams webhook unreachable: %s (cannot send alert)", exc)
        raise RuntimeError(f"Teams webhook unreachable: {exc}") from exc

    # 6. S3 bucket access
    logger.info("Phase 0 — checking S3 bucket access")
    _check(
        lambda: _check_s3_bucket(),
        label="S3 bucket",
        teams_client=teams_client,
        teams_ok=teams_ok,
    )
    logger.info("S3 bucket: OK")

    logger.info("Phase 0 — Validation passed")


def _check(func, label: str, teams_client: TeamsClient, teams_ok: bool) -> None:
    try:
        func()
    except Exception as exc:
        msg = f"{label} check failed: {exc}"
        logger.error(msg)
        if teams_ok:
            _send_failure_alert(teams_client, "Phase 0", msg)
        raise RuntimeError(msg) from exc


def _check_s3_bucket() -> None:
    kwargs = {"region_name": config.AWS_REGION}
    if config.AWS_ACCESS_KEY_ID and config.AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = config.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = config.AWS_SECRET_ACCESS_KEY
    s3 = boto3.client("s3", **kwargs)
    s3.head_bucket(Bucket=config.S3_BUCKET_NAME)


def _send_failure_alert(teams_client: TeamsClient, phase: str, error: str) -> None:
    ts = datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")
    teams_client.send_failure_alert(phase=phase, error=error, timestamp=ts)

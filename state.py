"""
S3 state file read/write.

The state file (snyk_state.json) lives in S3 and is the single source of
truth for delta detection across daily runs.  This module owns all I/O
against it; callers work with plain Python dicts matching the schema in §8.
"""
import json
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

import config

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
IST = timezone(timedelta(hours=5, minutes=30))


# ── S3 client factory ─────────────────────────────────────────────────────────

def _s3() -> Any:
    kwargs: dict[str, Any] = {"region_name": config.AWS_REGION}
    if config.AWS_ACCESS_KEY_ID and config.AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = config.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = config.AWS_SECRET_ACCESS_KEY
    return boto3.client("s3", **kwargs)


# ── State construction ────────────────────────────────────────────────────────

def create_empty_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "last_run": None,
        "run_status": "new",
        "processed_count": 0,
        "total_count": 0,
        "targets": {},
    }


def _empty_target_entry(display_name: str = "") -> dict:
    return {
        "display_name": display_name,
        "critical": 0,
        "high": 0,
        "jira_ticket": None,
        "created_today": False,
        "last_changed": None,
        "last_synced": None,
    }


# ── S3 I/O ────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    Download and parse the state file from S3.
    Returns an empty state dict if the file does not yet exist (first run).
    """
    try:
        response = _s3().get_object(
            Bucket=config.S3_BUCKET_NAME,
            Key=config.S3_STATE_FILE_KEY,
        )
        raw = response["Body"].read().decode("utf-8")
        state = json.loads(raw)
        logger.info("State loaded from S3 (run_status=%s)", state.get("run_status"))
        return state
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchKey":
            logger.info("No state file found in S3 — starting with empty state")
            return create_empty_state()
        raise


def upload_state(state: dict) -> None:
    body = json.dumps(state, indent=2, default=str).encode("utf-8")
    _s3().put_object(
        Bucket=config.S3_BUCKET_NAME,
        Key=config.S3_STATE_FILE_KEY,
        Body=body,
        ContentType="application/json",
    )
    logger.info(
        "State uploaded to S3 (run_status=%s, processed=%s/%s)",
        state.get("run_status"),
        state.get("processed_count"),
        state.get("total_count"),
    )


# ── Per-run lifecycle helpers ─────────────────────────────────────────────────

def _last_run_date(state: dict) -> date | None:
    last_run = state.get("last_run")
    if not last_run:
        return None
    try:
        return datetime.fromisoformat(last_run).date()
    except (ValueError, TypeError):
        return None


def should_reset_created_today(state: dict) -> bool:
    last_date = _last_run_date(state)
    return last_date is None or last_date < date.today()


def reset_created_today(state: dict) -> None:
    for entry in state.get("targets", {}).values():
        entry["created_today"] = False


def stamp_run_start(state: dict) -> None:
    """Set last_run to now (IST) and run_status to 'partial'."""
    state["last_run"] = datetime.now(tz=IST).isoformat()
    state["run_status"] = "partial"


def prepare_for_run(state: dict) -> None:
    """
    Called once at the very start of every run, before Phase 1.

    - If it's a new calendar day: reset all created_today flags.
    - If it's a same-day re-run: preserve created_today for idempotency.
    - Stamps last_run and sets run_status = "partial".
    """
    if should_reset_created_today(state):
        logger.info("New calendar day — resetting all created_today flags")
        reset_created_today(state)
    else:
        logger.info("Same-day re-run — preserving created_today flags for idempotency")
    stamp_run_start(state)


# ── Target entry helpers ──────────────────────────────────────────────────────

def upsert_target(state: dict, target_id: str, display_name: str) -> dict:
    """
    Ensure a target entry exists in state, preserving any existing fields.
    Returns the entry dict (mutates state in place).
    """
    targets = state.setdefault("targets", {})
    if target_id not in targets:
        targets[target_id] = _empty_target_entry(display_name)
    else:
        targets[target_id]["display_name"] = display_name
    return targets[target_id]


def today_str() -> str:
    return date.today().isoformat()

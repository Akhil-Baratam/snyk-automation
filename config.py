"""
Loads and validates all environment variables at startup.
Exits with code 1 if any required variable is missing or blank.
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent / ".env")

_errors: list[str] = []


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        _errors.append(name)
    return value


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        _errors.append(f"{name} (must be an integer, got '{raw}')")
        return default


def _bool_env(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("true", "1", "yes")


# ── Snyk ────────────────────────────────────────────────────────────────────
SNYK_API_TOKEN: str = _require("SNYK_API_TOKEN")
SNYK_ORG_ID: str = _require("SNYK_ORG_ID")
SNYK_API_BASE_URL: str = _optional("SNYK_API_BASE_URL", "https://api.snyk.io")
SNYK_ORG_SLUG: str = _optional("SNYK_ORG_SLUG", "")

# ── Jira ─────────────────────────────────────────────────────────────────────
JIRA_BASE_URL: str = _require("JIRA_BASE_URL")
JIRA_USER_EMAIL: str = _require("JIRA_USER_EMAIL")
JIRA_API_TOKEN: str = _require("JIRA_API_TOKEN")
JIRA_PROJECT_KEY: str = _optional("JIRA_PROJECT_KEY", "PSUP")
JIRA_TICKET_LABEL: str = _optional("JIRA_TICKET_LABEL", "snyk-jolt")
JIRA_ISSUE_TYPE: str = _optional("JIRA_ISSUE_TYPE", "Task")
JIRA_FIELD_SNYK_PROJECT_ID: str = _require("JIRA_FIELD_SNYK_PROJECT_ID")
JIRA_FIELD_SNYK_CRITICAL_COUNT: str = _require("JIRA_FIELD_SNYK_CRITICAL_COUNT")
JIRA_FIELD_SNYK_HIGH_COUNT: str = _require("JIRA_FIELD_SNYK_HIGH_COUNT")
JIRA_FIELD_SNYK_LAST_SYNCED: str = _require("JIRA_FIELD_SNYK_LAST_SYNCED")

# ── Teams ─────────────────────────────────────────────────────────────────────
TEAMS_WEBHOOK_URL: str = _require("TEAMS_WEBHOOK_URL")

# ── AWS / S3 ──────────────────────────────────────────────────────────────────
S3_BUCKET_NAME: str = _require("S3_BUCKET_NAME")
S3_STATE_FILE_KEY: str = _optional("S3_STATE_FILE_KEY", "snyk-automation/snyk_state.json")
AWS_REGION: str = _optional("AWS_REGION", "ap-south-1")
# Optional — left blank when running under IAM role / instance profile
AWS_ACCESS_KEY_ID: str = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
AWS_SECRET_ACCESS_KEY: str = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()

# ── GitLab ────────────────────────────────────────────────────────────────────
GITLAB_BASE_URL: str = _optional("GITLAB_BASE_URL", "https://gitlab.com")
GITLAB_DEFAULT_BRANCH: str = _optional("GITLAB_DEFAULT_BRANCH", "master")

# ── Script behaviour ──────────────────────────────────────────────────────────
MAX_RETRY_ATTEMPTS: int = _int_env("MAX_RETRY_ATTEMPTS", 3)
RETRY_BASE_DELAY_SECONDS: int = _int_env("RETRY_BASE_DELAY_SECONDS", 2)
SNYK_PAGE_SIZE: int = _int_env("SNYK_PAGE_SIZE", 100)
JIRA_PAGE_SIZE: int = _int_env("JIRA_PAGE_SIZE", 50)
TEAMS_CARD_SIZE_LIMIT_BYTES: int = _int_env("TEAMS_CARD_SIZE_LIMIT_BYTES", 22528)
DEBUG_LOGGING: bool = _bool_env("DEBUG_LOGGING", False)

# ── Fail-fast validation ───────────────────────────────────────────────────────
if _errors:
    print("ERROR: The following required environment variables are missing or invalid:", file=sys.stderr)
    for name in _errors:
        print(f"  - {name}", file=sys.stderr)
    print("\nSet them in your .env file (copy .env.example) before running.", file=sys.stderr)
    sys.exit(1)

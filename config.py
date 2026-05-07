"""
Loads and validates environment variables at startup.
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


# ── Snyk ─────────────────────────────────────────────────────────────────────
SNYK_API_TOKEN: str    = _require("SNYK_API_TOKEN")
SNYK_ORG_ID: str       = _require("SNYK_ORG_ID")
SNYK_API_BASE_URL: str = _optional("SNYK_API_BASE_URL", "https://api.snyk.io")
SNYK_ORG_SLUG: str     = _optional("SNYK_ORG_SLUG", "")

# ── Jira ─────────────────────────────────────────────────────────────────────
# Reachability creds (required from Phase 2 onward; optional at import).
JIRA_BASE_URL: str     = _optional("JIRA_BASE_URL", "")
JIRA_USER_EMAIL: str   = _optional("JIRA_USER_EMAIL", "")
JIRA_API_TOKEN: str    = _optional("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY: str  = _optional("JIRA_PROJECT_KEY", "PSUP")
JIRA_TICKET_LABEL: str = _optional("JIRA_TICKET_LABEL", "snyk-jolt")
JIRA_ISSUE_TYPE: str   = _optional("JIRA_ISSUE_TYPE", "Task")

# ── Teams ────────────────────────────────────────────────────────────────────
# Required from Phase 3 onward. Optional at import.
TEAMS_WEBHOOK_URL: str = _optional("TEAMS_WEBHOOK_URL", "")

# ── GitLab ───────────────────────────────────────────────────────────────────
GITLAB_BASE_URL: str       = _optional("GITLAB_BASE_URL", "https://gitlab.com")
GITLAB_DEFAULT_BRANCH: str = _optional("GITLAB_DEFAULT_BRANCH", "master")
# Personal access token (read_api scope). Optional — when unset, GitLab metadata
# (Last Commit Date, Active in Production) is skipped and shown as "-".
GITLAB_API_TOKEN: str      = _optional("GITLAB_API_TOKEN", "")

# ── Script behaviour ─────────────────────────────────────────────────────────
MAX_RETRY_ATTEMPTS: int          = _int_env("MAX_RETRY_ATTEMPTS", 3)
RETRY_BASE_DELAY_SECONDS: int    = _int_env("RETRY_BASE_DELAY_SECONDS", 2)
SNYK_PAGE_SIZE: int              = _int_env("SNYK_PAGE_SIZE", 100)
# Teams hard limit is ~28 KB; 22 KB is the safe ceiling.
TEAMS_CARD_SIZE_LIMIT_BYTES: int = _int_env("TEAMS_CARD_SIZE_LIMIT_BYTES", 22528)
DEBUG_LOGGING: bool              = _bool_env("DEBUG_LOGGING", False)

# ── Fail-fast ────────────────────────────────────────────────────────────────
if _errors:
    print("ERROR: The following required environment variables are missing or invalid:", file=sys.stderr)
    for name in _errors:
        print(f"  - {name}", file=sys.stderr)
    print("\nSet them in your .env file (copy .env.example) before running.", file=sys.stderr)
    sys.exit(1)

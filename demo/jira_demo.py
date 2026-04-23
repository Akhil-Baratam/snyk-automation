"""
DEMO VERSION: Jira Cloud REST API v3 client (simplified, no custom fields).

Confirmed working endpoints for smartsensebydigi.atlassian.net:
  - Search: POST /rest/api/3/search/jql  (body: {jql, fields})
  - Create: POST /rest/api/3/issue       (singular, not /issues)

JQL uses single quotes (confirmed from jira_search.json).
"""
import base64
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config
from utils.retry import with_retry

logger = logging.getLogger(__name__)


class JiraClientDemo:
    def __init__(self) -> None:
        self._base = config.JIRA_BASE_URL.rstrip("/")
        self._session = self._build_session()

    @staticmethod
    def _build_session() -> requests.Session:
        session = requests.Session()
        credentials = f"{config.JIRA_USER_EMAIL}:{config.JIRA_API_TOKEN}"
        token = base64.b64encode(credentials.encode()).decode()
        session.headers.update({
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        adapter = HTTPAdapter(max_retries=Retry(total=0))
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    # ── Low-level HTTP ────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._base}{path}"
        def _call() -> dict:
            resp = self._session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self._base}{path}"
        def _call() -> dict:
            resp = self._session.post(url, json=body, timeout=30)
            if not resp.ok:
                logger.error("POST %s → %d: %s", path, resp.status_code, resp.text[:500])
                resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    def _put(self, path: str, body: dict) -> None:
        url = f"{self._base}{path}"
        def _call() -> None:
            resp = self._session.put(url, json=body, timeout=30)
            if not resp.ok:
                logger.error("PUT %s → %d: %s", path, resp.status_code, resp.text[:500])
                resp.raise_for_status()
        with_retry(_call)

    # ── Validation ────────────────────────────────────────────────────────────

    def check_reachability(self) -> dict:
        return self._get("/rest/api/3/myself")

    # ── Search ────────────────────────────────────────────────────────────────

    def search_issues(self, jql: str, fields: list[str]) -> list[dict]:
        """
        JQL search using POST /rest/api/3/search/jql.
        Matches confirmed-working format from jira_search.json.
        """
        body = {
            "jql": jql,
            "fields": fields,
        }
        logger.info("  JQL: %s", jql)
        data = self._post("/rest/api/3/search/jql", body)
        issues: list[dict] = data.get("issues", [])
        logger.info("  → %d result(s)", len(issues))
        return issues

    def find_open_ticket_by_name(self, display_name: str) -> dict | None:
        """
        Search by label + summary text match.
        Uses single-quoted JQL values (confirmed working format).
        """
        # Single quotes in JQL — matches jira_search.json that worked
        jql = (
            f"project = '{config.JIRA_PROJECT_KEY}' "
            f"AND issuetype = '{config.JIRA_ISSUE_TYPE}' "
            f"AND summary ~ '{display_name}' "
            f"AND labels = '{config.JIRA_TICKET_LABEL}' "
            f"AND statusCategory != 'Done'"
        )
        fields = ["id", "key", "summary", "status"]
        issues = self.search_issues(jql, fields)
        return issues[0] if issues else None

    def get_all_open_snyk_tickets(self) -> list[dict]:
        """Get all open tickets with the snyk-jolt label."""
        jql = (
            f"labels = '{config.JIRA_TICKET_LABEL}' "
            f"AND statusCategory != 'Done'"
        )
        fields = ["id", "key", "summary"]
        issues = self.search_issues(jql, fields)
        logger.info("Reverse check: fetched %d open snyk-jolt tickets", len(issues))
        return issues

    # ── Write operations ──────────────────────────────────────────────────────

    def create_ticket(self, summary: str, description: dict) -> str:
        """
        Creates a ticket with only standard fields.
        Endpoint: POST /rest/api/3/issue  (singular — confirmed for this instance)
        """
        body: dict[str, Any] = {
            "fields": {
                "project": {"key": config.JIRA_PROJECT_KEY},
                "issuetype": {"name": config.JIRA_ISSUE_TYPE},
                "summary": summary,
                "description": description,
                "labels": [config.JIRA_TICKET_LABEL],
                "priority": {"name": "High"},
            }
        }
        data = self._post("/rest/api/3/issue", body)   # singular /issue
        key: str = data["key"]
        logger.info("Created Jira ticket %s", key)
        return key

    # ── URL builder ───────────────────────────────────────────────────────────

    def ticket_url(self, key: str) -> str:
        return f"{self._base}/browse/{key}"
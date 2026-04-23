"""
Jira Cloud REST API v3 client.

Handles ticket search, creation, and field updates.
All requests use Basic auth (email:api_token, base64-encoded).
All search calls specify an explicit fields= list to minimise point cost.
"""
import base64
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config
from models.ticket import JiraTicket
from utils.retry import with_retry

logger = logging.getLogger(__name__)


class JiraClient:
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
            resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    def _put(self, path: str, body: dict) -> None:
        url = f"{self._base}{path}"
        def _call() -> None:
            resp = self._session.put(url, json=body, timeout=30)
            resp.raise_for_status()
        with_retry(_call)

    # ── Validation ────────────────────────────────────────────────────────────

    def check_reachability(self) -> dict:
        return self._get("/rest/api/3/myself")

    def get_all_fields(self) -> list[dict]:
        return self._get("/rest/api/3/field")  # type: ignore[return-value]

    def validate_custom_fields(self) -> list[str]:
        """Returns a list of field IDs from config that are absent in Jira."""
        all_fields = self.get_all_fields()
        existing_ids = {f["id"] for f in all_fields}
        required = [
            config.JIRA_FIELD_SNYK_PROJECT_ID,
            config.JIRA_FIELD_SNYK_CRITICAL_COUNT,
            config.JIRA_FIELD_SNYK_HIGH_COUNT,
            config.JIRA_FIELD_SNYK_LAST_SYNCED,
        ]
        return [fid for fid in required if fid not in existing_ids]

    # ── Search ────────────────────────────────────────────────────────────────

    def search_issues(self, jql: str, fields: list[str]) -> list[dict]:
        """Paginated JQL search. Returns raw issue dicts."""
        results: list[dict] = []
        start = 0
        max_results = config.JIRA_PAGE_SIZE
        field_str = ",".join(fields)

        while True:
            data = self._get(
                "/rest/api/3/issue/search",
                params={
                    "jql": jql,
                    "fields": field_str,
                    "startAt": start,
                    "maxResults": max_results,
                },
            )
            issues: list[dict] = data.get("issues", [])
            results.extend(issues)

            total: int = data.get("total", 0)
            start += len(issues)
            if start >= total or not issues:
                break

        return results

    def find_open_ticket_by_snyk_id(self, target_id: str) -> JiraTicket | None:
        """Primary search: by snyk_project_id custom field."""
        jql = (
            f'"{config.JIRA_FIELD_SNYK_PROJECT_ID}" = "{target_id}"'
            f' AND labels = "{config.JIRA_TICKET_LABEL}"'
            f" AND statusCategory != Done"
        )
        fields = [
            "id", "key", "summary", "status",
            config.JIRA_FIELD_SNYK_PROJECT_ID,
            config.JIRA_FIELD_SNYK_CRITICAL_COUNT,
            config.JIRA_FIELD_SNYK_HIGH_COUNT,
        ]
        issues = self.search_issues(jql, fields)
        return self._issue_to_ticket(issues[0]) if issues else None

    def find_open_ticket_by_name(self, display_name: str) -> JiraTicket | None:
        """Fallback search: by label + summary text match."""
        jql = (
            f'labels = "{config.JIRA_TICKET_LABEL}"'
            f' AND summary ~ "{display_name}"'
            f" AND statusCategory != Done"
        )
        fields = [
            "id", "key", "summary", "status",
            config.JIRA_FIELD_SNYK_PROJECT_ID,
            config.JIRA_FIELD_SNYK_CRITICAL_COUNT,
            config.JIRA_FIELD_SNYK_HIGH_COUNT,
        ]
        issues = self.search_issues(jql, fields)
        return self._issue_to_ticket(issues[0]) if issues else None

    def get_all_open_snyk_tickets(self) -> list[JiraTicket]:
        """Reverse-check query: all open tickets with the snyk-jolt label."""
        jql = (
            f'labels = "{config.JIRA_TICKET_LABEL}"'
            f" AND statusCategory != Done"
        )
        fields = [
            "id", "key", "summary",
            config.JIRA_FIELD_SNYK_PROJECT_ID,
        ]
        issues = self.search_issues(jql, fields)
        logger.info("Reverse check: fetched %d open snyk-jolt tickets from Jira", len(issues))
        return [self._issue_to_ticket(i) for i in issues]

    # ── Write operations ──────────────────────────────────────────────────────

    def create_ticket(
        self,
        summary: str,
        description: dict,
        custom_fields: dict[str, Any],
    ) -> str:
        """Creates a ticket and returns its key (e.g. 'PSUP-1042')."""
        priority = "Critical" if custom_fields.get(config.JIRA_FIELD_SNYK_CRITICAL_COUNT, 0) > 0 else "High"
        body: dict[str, Any] = {
            "fields": {
                "project": {"key": config.JIRA_PROJECT_KEY},
                "issuetype": {"name": config.JIRA_ISSUE_TYPE},
                "summary": summary,
                "description": description,
                "labels": [config.JIRA_TICKET_LABEL],
                "priority": {"name": priority},
                **custom_fields,
            }
        }
        data = self._post("/rest/api/3/issue", body)
        key: str = data["key"]
        logger.info("Created Jira ticket %s", key)
        return key

    def update_fields(self, ticket_key: str, fields: dict[str, Any]) -> None:
        self._put(f"/rest/api/3/issue/{ticket_key}", {"fields": fields})
        logger.info("Updated fields on %s: %s", ticket_key, list(fields.keys()))

    def backfill_snyk_project_id(self, ticket_key: str, target_id: str) -> None:
        self.update_fields(
            ticket_key,
            {config.JIRA_FIELD_SNYK_PROJECT_ID: target_id},
        )
        logger.info("Backfilled snyk_project_id on %s → %s", ticket_key, target_id)

    # ── URL builder ───────────────────────────────────────────────────────────

    def ticket_url(self, key: str) -> str:
        return f"{self._base}/browse/{key}"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _issue_to_ticket(self, issue: dict) -> JiraTicket:
        f = issue.get("fields", {})
        return JiraTicket(
            key=issue["key"],
            summary=f.get("summary", ""),
            status=(f.get("status") or {}).get("name", ""),
            snyk_project_id=f.get(config.JIRA_FIELD_SNYK_PROJECT_ID),
            snyk_critical_count=f.get(config.JIRA_FIELD_SNYK_CRITICAL_COUNT),
            snyk_high_count=f.get(config.JIRA_FIELD_SNYK_HIGH_COUNT),
        )

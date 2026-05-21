"""
Jira Cloud REST API v3 client.

Search by label + UUID-prefix token in summary. No project filter — tickets
moved between Jira projects (PSUP -> RAIL etc.) are still found via labels.

Endpoints (confirmed on smartsensebydigi.atlassian.net):
  Search: POST /rest/api/3/search/jql
  Create: POST /rest/api/3/issue          (singular)
  Update: PUT  /rest/api/3/issue/{key}
"""
import base64
import logging

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
        token = base64.b64encode(
            f"{config.JIRA_USER_EMAIL}:{config.JIRA_API_TOKEN}".encode()
        ).decode()
        session.headers.update({
            "Authorization": f"Basic {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        })
        adapter = HTTPAdapter(max_retries=Retry(total=0))
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        url = f"{self._base}{path}"
        def _call() -> dict:
            resp = self._session.get(url, timeout=30)
            resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    def _post(self, path: str, body: dict) -> dict:
        url = f"{self._base}{path}"
        def _call() -> dict:
            resp = self._session.post(url, json=body, timeout=30)
            if not resp.ok:
                logger.error("POST %s -> %d: %s", path, resp.status_code, resp.text[:500])
                resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    def _put(self, path: str, body: dict) -> None:
        url = f"{self._base}{path}"
        def _call() -> None:
            resp = self._session.put(url, json=body, timeout=30)
            if not resp.ok:
                logger.error("PUT %s -> %d: %s", path, resp.status_code, resp.text[:500])
                resp.raise_for_status()
        with_retry(_call)

    # ── Public API ────────────────────────────────────────────────────────────

    def check_reachability(self) -> dict:
        return self._get("/rest/api/3/myself")

    def find_open_ticket(self, uuid_token: str) -> JiraTicket | None:
        """
        Global search by label + UUID-prefix token in summary.
        12-char hex token => ~280 trillion combinations: collision-free.
        Also fetches the description so the caller can surgically update it.
        """
        jql = (
            f"labels = '{config.JIRA_TICKET_LABEL}' "
            f"AND summary ~ '{uuid_token}' "
            f"AND statusCategory != 'Done'"
        )
        data = self._post("/rest/api/3/search/jql", {
            "jql": jql,
            "fields": ["summary", "status", "description"],
        })
        issues = data.get("issues", []) or []
        if not issues:
            return None
        if len(issues) > 1:
            logger.warning("Multiple tickets matched UUID %s: %s -- using first",
                           uuid_token, [i.get("key") for i in issues])
        issue = issues[0]
        f = issue.get("fields", {})
        return JiraTicket(
            key=issue["key"],
            summary=f.get("summary", ""),
            status=(f.get("status") or {}).get("name", ""),
            description=f.get("description"),
        )

    def list_open_snyk_tickets(self) -> list[tuple[str, str]]:
        """
        Paginated JQL: every open ticket with the snyk label.
        Returns [(key, summary), ...]. Used by Phase 3 reverse check.
        """
        jql = (
            f"labels = '{config.JIRA_TICKET_LABEL}' "
            f"AND statusCategory != 'Done'"
        )
        results: list[tuple[str, str]] = []
        next_token: str | None = None
        page = 1

        while True:
            body: dict = {"jql": jql, "fields": ["summary"], "maxResults": 100}
            if next_token:
                body["nextPageToken"] = next_token
            data = self._post("/rest/api/3/search/jql", body)
            for issue in data.get("issues", []) or []:
                summary = (issue.get("fields") or {}).get("summary", "") or ""
                results.append((issue["key"], summary))
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            page += 1

        logger.info("Fetched %d open snyk-labelled ticket(s) across %d page(s)", len(results), page)
        return results

    def create_ticket(
        self,
        summary: str,
        description: dict,
        priority: str = "High",
        due_date: str | None = None,
    ) -> str:
        fields: dict = {
            "project":     {"key":  config.JIRA_PROJECT_KEY},
            "issuetype":   {"name": config.JIRA_ISSUE_TYPE},
            "summary":     summary,
            "description": description,
            "labels":      config.JIRA_TICKET_LABELS,
            "priority":    {"name": priority},
        }
        if due_date:
            fields["duedate"] = due_date
        data = self._post("/rest/api/3/issue", {"fields": fields})
        key: str = data["key"]
        logger.info("Created Jira ticket %s (priority=%s, due=%s)", key, priority, due_date or "-")
        return key

    def set_labels(self, ticket_key: str, labels: list[str]) -> None:
        self._put(f"/rest/api/3/issue/{ticket_key}", {"fields": {"labels": labels}})
        logger.info("Labels set on %s: %s", ticket_key, labels)

    def update_ticket(self, ticket_key: str, summary: str, description: dict) -> None:
        """Update both summary and description in a single PUT."""
        self._put(f"/rest/api/3/issue/{ticket_key}", {
            "fields": {"summary": summary, "description": description},
        })
        logger.info("Updated %s (summary + description)", ticket_key)

    def ticket_url(self, key: str) -> str:
        return f"{self._base}/browse/{key}"

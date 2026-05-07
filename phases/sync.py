"""
Phase 2 -- Jira sync.

Per target:
  1. Same-day cache hit (logs/today_created.json) -> skip (idempotency)
  2. JQL by label + UUID-prefix token in summary
  3. No ticket            -> create (fresh summary + description; GitLab metadata)
     Counts match         -> skip
     Counts differ        -> rewrite summary + replace Table 1 only
                             (preserves any human edits in Table 2)

UUID token: first 12 hex chars of target.id (no dashes).
~280 trillion combinations -- collision-free.
"""
import json
import logging
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import config
from clients.gitlab import GitLabClient
from clients.jira import JiraClient
from models.run_result import ChangedTicket, CreatedTicket, RunResult
from models.target import SnykTarget

logger = logging.getLogger(__name__)

_CACHE_FILE = Path(__file__).parent.parent / "logs" / "today_created.json"
_COUNTS_RE  = re.compile(r"\[\s*C(\d+)\s+H(\d+)\s+as on", re.IGNORECASE)
_FIVE_YEARS = timedelta(days=365 * 5)


def _uuid_token(target_id: str) -> str:
    return target_id.replace("-", "")[:12]


# ── Cache (same-day idempotency) ─────────────────────────────────────────────

def _load_cache() -> dict[str, str]:
    if not _CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if data.get("date") != date.today().isoformat():
        return {}
    return data.get("created", {}) or {}


def _save_cache(created: dict[str, str]) -> None:
    _CACHE_FILE.parent.mkdir(exist_ok=True)
    _CACHE_FILE.write_text(
        json.dumps({"date": date.today().isoformat(), "created": created}, indent=2),
        encoding="utf-8",
    )


# ── Summary build / parse ────────────────────────────────────────────────────

def _build_summary(target: SnykTarget, today: date) -> str:
    return (
        f"Snyk Vulnerabilities Check Repo Name:{target.display_name} "
        f"[snyk:{_uuid_token(target.id)}] "
        f"[ C{target.critical} H{target.high} as on {today.strftime('%m/%d/%y')}]"
    )


def _parse_counts(summary: str) -> tuple[int, int] | None:
    m = _COUNTS_RE.search(summary)
    return (int(m.group(1)), int(m.group(2))) if m else None


# ── ADF node helpers ─────────────────────────────────────────────────────────

def _text(t: str, bold: bool = False) -> dict:
    n: dict = {"type": "text", "text": t}
    if bold:
        n["marks"] = [{"type": "strong"}]
    return n


def _link(url: str) -> dict:
    return {"type": "text", "text": url, "marks": [{"type": "link", "attrs": {"href": url}}]}


def _inline_card(url: str) -> dict:
    return {"type": "inlineCard", "attrs": {"url": url}}


def _cell(nodes: list[dict]) -> dict:
    return {"type": "tableCell", "attrs": {}, "content": [{"type": "paragraph", "content": nodes}]}


def _row(cells: list[dict]) -> dict:
    return {"type": "tableRow", "content": cells}


def _table(rows: list[dict]) -> dict:
    return {"type": "table",
            "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
            "content": rows}


def _snyk_project_url(project_id: str) -> str:
    slug = config.SNYK_ORG_SLUG or config.SNYK_ORG_ID
    return f"https://app.snyk.io/org/{slug}/project/{project_id}"


def _gitlab_file_url(remote_url: str, file_name: str) -> str:
    base = remote_url.rstrip("/")
    last = file_name.split("/")[-1]
    verb = "tree" if "." not in last else "blob"
    return f"{base}/{verb}/{config.GITLAB_DEFAULT_BRANCH}/{file_name}"


# ── Description tables ───────────────────────────────────────────────────────

def _build_vuln_table_rows(target: SnykTarget) -> list[dict]:
    """Table 1 -- two columns: Snyk vulnerability | Gitlab link."""
    rows = [_row([
        _cell([_text("Snyk vulnerability", bold=True)]),
        _cell([_text("Gitlab link",        bold=True)]),
    ])]
    for p in target.projects:
        snyk_nodes = [_link(_snyk_project_url(p.project_id))] if p.project_id else [_text("-")]
        gitlab_nodes = (
            [_inline_card(_gitlab_file_url(target.remote_url, p.name))]
            if (target.remote_url and p.name) else [_text("-")]
        )
        rows.append(_row([_cell(snyk_nodes), _cell(gitlab_nodes)]))
    if not target.projects:
        rows.append(_row([_cell([_text("-")]), _cell([_text("-")])]))
    return rows


def _format_date(dt: datetime) -> str:
    return f"{dt.strftime('%b')} {dt.day}, {dt.year}"


def _active_in_production(last_commit: datetime | None) -> str:
    if last_commit is None:
        return "-"
    if last_commit.tzinfo is None:
        last_commit = last_commit.replace(tzinfo=timezone.utc)
    return "Active" if last_commit > datetime.now(tz=timezone.utc) - _FIVE_YEARS else "Inactive"


def _build_metadata_table_rows(target: SnykTarget, last_commit: datetime | None) -> list[dict]:
    """Table 2 -- repository key/value details."""
    repo_url_nodes = [_inline_card(target.remote_url)] if target.remote_url else [_text("-")]
    last_commit_str = _format_date(last_commit) if last_commit else "-"
    severity = (
        f"Critical: {target.critical}, High: {target.high}, "
        f"Medium: {target.medium}, Low: {target.low}"
    )
    pairs: list[tuple[str, list[dict]]] = [
        ("Repository Name",                                   [_text(target.display_name)]),
        ("Repo URL",                                          repo_url_nodes),
        ("Last Commit Date",                                  [_text(last_commit_str)]),
        ("Active in Production",                              [_text(_active_in_production(last_commit))]),
        ("Critical for Enterprise",                           [_text("-")]),
        ("Facing Type",                                       [_text("-")]),
        ("Service Name",                                      [_text("-")]),
        ("Owner / Maintainer",                                [_text("-")]),
        ("Snyk Vulnerabilities (Count) (For all severities)", [_text(str(target.total))]),
        ("Severity Breakdown",                                [_text(severity)]),
        ("Mitigation Status",                                 [_text("-")]),
        ("Notes / Comments",                                  [_text("-")]),
    ]
    rows = [_row([
        _cell([_text("Field",                bold=True)]),
        _cell([_text("Description / Example", bold=True)]),
    ])]
    for label, nodes in pairs:
        rows.append(_row([_cell([_text(label, bold=True)]), _cell(nodes)]))
    return rows


def _build_description(target: SnykTarget, last_commit: datetime | None) -> dict:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [_text("Snyk Vulnerability:", bold=True)]},
            _table(_build_vuln_table_rows(target)),
            _table(_build_metadata_table_rows(target, last_commit)),
        ],
    }


def _description_with_updated_vuln_table(existing: dict | None, target: SnykTarget) -> dict:
    """
    Replace just Table 1 in `existing`. Preserves Table 2 (and any human edits
    to Mitigation Status / Notes / Comments).
    Falls back to a fresh description if `existing` is missing or unrecognised.
    """
    if existing and isinstance(existing.get("content"), list):
        for elem in existing["content"]:
            if elem.get("type") == "table":
                elem["content"] = _build_vuln_table_rows(target)
                return existing
    return _build_description(target, last_commit=None)


# ── Phase 2 entry point ──────────────────────────────────────────────────────

def run_sync(targets: list[SnykTarget], dry_run: bool = False) -> RunResult:
    jira   = JiraClient()
    gitlab = GitLabClient()
    cache  = _load_cache()
    today  = date.today()
    result = RunResult()

    logger.info("Phase 2 -- Jira sync (%d targets)%s",
                len(targets), " [DRY RUN]" if dry_run else "")

    for target in targets:
        try:
            _process_target(target, today, jira, gitlab, cache, result, dry_run)
            result.processed_count += 1
        except Exception as exc:
            logger.error("[%s] sync failed: %s", target.display_name, exc, exc_info=True)
            result.error_count += 1

    if not dry_run:
        _save_cache(cache)
    skipped = result.processed_count - len(result.created) - len(result.changed)
    logger.info(
        "Phase 2 done -- created=%d changed=%d skipped=%d errors=%d",
        len(result.created), len(result.changed), skipped, result.error_count,
    )
    return result


def _process_target(
    target: SnykTarget,
    today: date,
    jira: JiraClient,
    gitlab: GitLabClient,
    cache: dict[str, str],
    result: RunResult,
    dry_run: bool,
) -> None:
    token = _uuid_token(target.id)
    name  = target.display_name

    if token in cache:
        logger.info("[%s] cache hit %s -- skipping", name, cache[token])
        return

    ticket = jira.find_open_ticket(token)

    if ticket is None:
        last_commit = gitlab.get_last_commit_date(target.remote_url)
        if target.critical > 0:
            priority, due_in_days = "Highest", 30
        else:
            priority, due_in_days = "High", 60
        due_date = (today + timedelta(days=due_in_days)).isoformat()
        summary = _build_summary(target, today)
        description = _build_description(target, last_commit)

        if dry_run:
            key = "DRY-RUN"
            ticket_url = ""
            logger.info("[%s] DRY-RUN would CREATE -- C%d H%d priority=%s due=%s | summary=%s",
                        name, target.critical, target.high, priority, due_date, summary)
        else:
            key = jira.create_ticket(summary, description, priority, due_date)
            cache[token] = key
            _save_cache(cache)
            ticket_url = jira.ticket_url(key)
            logger.info("[%s] CREATED %s -- C%d H%d M%d L%d",
                        name, key, target.critical, target.high, target.medium, target.low)

        result.created.append(CreatedTicket(
            target_name=name, ticket_key=key, ticket_url=ticket_url,
            critical=target.critical, high=target.high,
        ))
        return

    old = _parse_counts(ticket.summary)
    if old == (target.critical, target.high):
        logger.info("[%s] %s -- unchanged C%d H%d", name, ticket.key, target.critical, target.high)
        return

    old_c, old_h = old or (0, 0)
    new_summary = _build_summary(target, today)
    new_description = _description_with_updated_vuln_table(ticket.description, target)

    if dry_run:
        logger.info("[%s] DRY-RUN would UPDATE %s -- C%dH%d -> C%dH%d | summary=%s",
                    name, ticket.key, old_c, old_h, target.critical, target.high, new_summary)
    else:
        jira.update_ticket(ticket.key, new_summary, new_description)
        logger.info("[%s] %s -- CHANGED C%dH%d -> C%dH%d",
                    name, ticket.key, old_c, old_h, target.critical, target.high)

    result.changed.append(ChangedTicket(
        target_name=name, ticket_key=ticket.key, ticket_url=jira.ticket_url(ticket.key),
        old_critical=old_c, old_high=old_h,
        new_critical=target.critical, new_high=target.high,
    ))

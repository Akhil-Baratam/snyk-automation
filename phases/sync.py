"""
Phase 2 — Jira sync.

11.1 Forward check  — for every target with C/H vulns, ensure an open Jira
                       ticket exists and reflects the current counts.
11.2 Reverse check  — scan all open snyk-jolt tickets and flag any whose
                       target is gone or clean in Snyk.
"""
import logging

import config
import state
from clients.jira import JiraClient
from models.run_result import (
    CreatedTicket,
    FlaggedTicket,
    RunResult,
    UpdatedTicket,
)
from models.target import ProjectDetail, SnykTarget

logger = logging.getLogger(__name__)


# ── URL helpers ───────────────────────────────────────────────────────────────

def _snyk_target_url(target_id: str) -> str:
    """Snyk UI URL for a target (project page), using org slug when available."""
    slug = config.SNYK_ORG_SLUG
    if slug:
        return f"https://app.snyk.io/org/{slug}/project/{target_id}"
    ui_base = config.SNYK_API_BASE_URL.replace("api.snyk.io", "app.snyk.io").rstrip("/")
    return f"{ui_base}/org/{config.SNYK_ORG_ID}/project/{target_id}"


def _snyk_project_url(project_id: str) -> str:
    """Snyk UI URL for a specific project (file-level scan), using org slug when available."""
    slug = config.SNYK_ORG_SLUG
    if slug:
        return f"https://app.snyk.io/org/{slug}/project/{project_id}"
    return f"https://app.snyk.io/org/{config.SNYK_ORG_ID}/project/{project_id}"


def _gitlab_file_url(remote_url: str, file_path: str) -> str:
    """GitLab blob URL for a specific file on the configured default branch."""
    base = remote_url.rstrip("/")
    branch = config.GITLAB_DEFAULT_BRANCH
    return f"{base}/blob/{branch}/{file_path}"


# ── Jira ticket content builders ──────────────────────────────────────────────

def _build_summary(display_name: str, critical: int, high: int, today: str) -> str:
    """
    Production format:
        Snyk Vulnerabilities Check Repo Name:{name} [ C{c} H{h} as on {MM/DD/YY}]
    """
    parts = today.split("-")          # ["2026", "04", "23"]
    mm_dd_yy = f"{parts[1]}/{parts[2]}/{parts[0][2:]}"   # "04/23/26"
    return (
        f"Snyk Vulnerabilities Check Repo Name:{display_name}"
        f" [ C{critical} H{high} as on {mm_dd_yy}]"
    )


# ── ADF node factories ────────────────────────────────────────────────────────

def _text(t: str, bold: bool = False) -> dict:
    node: dict = {"type": "text", "text": t}
    if bold:
        node["marks"] = [{"type": "strong"}]
    return node


def _link_node(label: str, url: str) -> dict:
    return {
        "type": "text",
        "text": label,
        "marks": [{"type": "link", "attrs": {"href": url}}],
    }


def _cell(nodes: list[dict], is_header: bool = False) -> dict:
    cell_type = "tableHeader" if is_header else "tableCell"
    return {
        "type": cell_type,
        "attrs": {},
        "content": [{"type": "paragraph", "content": nodes}],
    }


def _row(cells: list[dict]) -> dict:
    return {"type": "tableRow", "content": cells}


def _table(rows: list[dict]) -> dict:
    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
        "content": rows,
    }


# ── ADF description ───────────────────────────────────────────────────────────

def _build_adf_description(target: SnykTarget) -> dict:
    """
    ADF document matching §13 + production ticket format.

    Table 1 — Snyk vulnerability per file (C/H > 0 files only)
      Snyk vulnerability | Gitlab link | Severity Breakdown

    Table 2 — Repository key-value details
      Field | Description / Example
    """
    content: list[dict] = []

    # ── Table 1: per-file snyk + gitlab links ─────────────────────────────────
    header_row_1 = _row([
        _cell([_text("Snyk vulnerability", bold=True)], is_header=True),
        _cell([_text("Gitlab link",        bold=True)], is_header=True),
        _cell([_text("Severity Breakdown", bold=True)], is_header=True),
    ])

    file_rows: list[dict] = []
    for p in target.projects:
        snyk_url   = _snyk_project_url(p.project_id)
        gitlab_url = _gitlab_file_url(target.remote_url, p.name) if target.remote_url else ""
        severity   = f"C{p.critical} H{p.high} M{p.medium} L{p.low}"

        file_rows.append(_row([
            _cell([_link_node(snyk_url, snyk_url)] if snyk_url else [_text("—")]),
            _cell([_link_node(gitlab_url, gitlab_url)] if gitlab_url else [_text("—")]),
            _cell([_text(severity)]),
        ]))

    if not file_rows:
        file_rows = [_row([
            _cell([_text("No C/H vulnerability data available")]),
            _cell([_text("—")]),
            _cell([_text("—")]),
        ])]

    content.append({
        "type": "paragraph",
        "content": [_text("Snyk Vulnerability:", bold=True)],
    })
    content.append(_table([header_row_1, *file_rows]))

    # ── Table 2: repository key-value details ─────────────────────────────────
    repo_url_nodes = (
        [_link_node(target.remote_url, target.remote_url)]
        if target.remote_url else [_text("—")]
    )
    total_projects = len(target.projects)

    kv_rows: list[tuple[str, list[dict]]] = [
        ("Repository Name",   [_text(target.display_name)]),
        ("Repo URL",          repo_url_nodes),
        ("Last Commit Date",  [_text("-")]),
        ("Active in Production", [_text("")]),
        ("Critical for Enterprise", [_text("-")]),
        ("Facing Type",       [_text("")]),
        ("Service Name",      [_text("")]),
        ("Owner / Maintainer", [_text("")]),
        ("Snyk Vulnerabilities (Count) (For all severities)", [_text(str(total_projects))]),
        ("Severity Breakdown", [_text(f"Critical:{target.critical}, High:{target.high}")]),
        ("Mitigation Status", [_text("-")]),
        ("Notes / Comments",  [_text("")]),
    ]

    kv_table_rows = [
        _row([
            _cell([_text("Field",                bold=True)], is_header=True),
            _cell([_text("Description / Example", bold=True)], is_header=True),
        ])
    ] + [
        _row([
            _cell([_text(field, bold=True)]),
            _cell(value_nodes),
        ])
        for field, value_nodes in kv_rows
    ]

    content.append(_table(kv_table_rows))

    return {"type": "doc", "version": 1, "content": content}


# ── Phase 2 entry point ───────────────────────────────────────────────────────

def run_sync(
    targets: list[SnykTarget],
    all_target_ids: set[str],
    current_state: dict,
) -> RunResult:
    """
    Runs forward check (§11.1) then reverse check (§11.2).
    Mutates current_state in-place.
    Returns a RunResult accumulator consumed by Phase 3.
    """
    jira = JiraClient()
    result = RunResult()
    today = state.today_str()

    # ── 11.1 Forward check ────────────────────────────────────────────────────
    logger.info("Phase 2 — Forward check started (%d targets)", len(targets))

    target_ids_with_vulns: set[str] = {t.id for t in targets}

    for target in targets:
        try:
            _forward_check_target(target, jira, current_state, result, today)
            result.processed_count += 1
        except Exception as exc:
            logger.error(
                "[%s] Forward check failed: %s", target.display_name, exc, exc_info=True
            )
            result.error_count += 1

    skipped = result.processed_count - len(result.created) - len(result.updated)
    logger.info(
        "Phase 2 forward check — complete. created=%d updated=%d skipped=%d errors=%d",
        len(result.created),
        len(result.updated),
        skipped,
        result.error_count,
    )

    # ── 11.2 Reverse check ────────────────────────────────────────────────────
    logger.info("Phase 2 — Reverse check started")
    open_tickets = jira.get_all_open_snyk_tickets()

    for ticket in open_tickets:
        snyk_id = ticket.snyk_project_id
        if not snyk_id:
            logger.warning(
                "[%s] Missing snyk_project_id field — cannot reverse-check", ticket.key
            )
            continue

        ticket_url  = jira.ticket_url(ticket.key)
        target_name = ticket.summary

        if snyk_id not in all_target_ids:
            # Target UUID absent from the targets API — deleted or renamed
            result.flagged.append(FlaggedTicket(
                target_name=target_name,
                ticket_key=ticket.key,
                ticket_url=ticket_url,
                reason="project_deleted",
            ))
            logger.info("[%s] %s — flagged: project_deleted", target_name, ticket.key)

        elif snyk_id not in target_ids_with_vulns:
            # Target exists in Snyk but has zero C/H vulns (filtered out in Phase 1)
            result.flagged.append(FlaggedTicket(
                target_name=target_name,
                ticket_key=ticket.key,
                ticket_url=ticket_url,
                reason="vulns_resolved",
            ))
            logger.info("[%s] %s — flagged: vulns_resolved", target_name, ticket.key)
        # else: ticket correctly open — forward check already handled it

    logger.info("Phase 2 reverse check — complete. flagged=%d", len(result.flagged))
    return result


# ── Forward-check helpers ─────────────────────────────────────────────────────

def _forward_check_target(
    target: SnykTarget,
    jira: JiraClient,
    current_state: dict,
    result: RunResult,
    today: str,
) -> None:
    state_entry = current_state["targets"].get(target.id, {})

    # Step A — idempotency guard
    if state_entry.get("created_today"):
        logger.info("[%s] Skipping — ticket already created in this run", target.display_name)
        return

    # Step B — search for existing open ticket
    ticket = jira.find_open_ticket_by_snyk_id(target.id)

    if ticket is None:
        logger.info("[%s] No ticket via primary search — trying name-based fallback", target.display_name)
        ticket = jira.find_open_ticket_by_name(target.display_name)
        if ticket is not None:
            logger.info("[%s] Fallback found %s — backfilling snyk_project_id", target.display_name, ticket.key)
            jira.backfill_snyk_project_id(ticket.key, target.id)

    # Step C — branch on ticket existence and count delta
    if ticket is None:
        _create_ticket(target, jira, current_state, result, today)
    else:
        old_c = state_entry.get("critical", 0)
        old_h = state_entry.get("high", 0)
        if target.critical != old_c or target.high != old_h:
            _update_ticket(target, ticket.key, old_c, old_h, jira, current_state, result, today)
        else:
            current_state["targets"].setdefault(target.id, {})["last_synced"] = today
            logger.info(
                "[%s] Ticket %s — SAME counts C%dH%d → skip",
                target.display_name, ticket.key, target.critical, target.high,
            )


def _create_ticket(
    target: SnykTarget,
    jira: JiraClient,
    current_state: dict,
    result: RunResult,
    today: str,
) -> None:
    summary     = _build_summary(target.display_name, target.critical, target.high, today)
    description = _build_adf_description(target)
    custom_fields = {
        config.JIRA_FIELD_SNYK_PROJECT_ID:     target.id,
        config.JIRA_FIELD_SNYK_CRITICAL_COUNT: target.critical,
        config.JIRA_FIELD_SNYK_HIGH_COUNT:     target.high,
        config.JIRA_FIELD_SNYK_LAST_SYNCED:    today,
    }
    key = jira.create_ticket(summary, description, custom_fields)
    logger.info("[%s] NO ticket found → created %s", target.display_name, key)

    entry = state.upsert_target(current_state, target.id, target.display_name)
    entry["jira_ticket"]   = key
    entry["created_today"] = True
    entry["critical"]      = target.critical
    entry["high"]          = target.high
    entry["last_changed"]  = today
    entry["last_synced"]   = today

    result.created.append(CreatedTicket(
        target_name=target.display_name,
        ticket_key=key,
        ticket_url=jira.ticket_url(key),
        snyk_url=_snyk_target_url(target.id),
        critical=target.critical,
        high=target.high,
    ))


def _update_ticket(
    target: SnykTarget,
    ticket_key: str,
    old_c: int,
    old_h: int,
    jira: JiraClient,
    current_state: dict,
    result: RunResult,
    today: str,
) -> None:
    # Update only the 3 machine-managed fields; never touch summary or description
    jira.update_fields(ticket_key, {
        config.JIRA_FIELD_SNYK_CRITICAL_COUNT: target.critical,
        config.JIRA_FIELD_SNYK_HIGH_COUNT:     target.high,
        config.JIRA_FIELD_SNYK_LAST_SYNCED:    today,
    })
    logger.info(
        "[%s] Ticket %s — CHANGED C%dH%d→C%dH%d → updating fields",
        target.display_name, ticket_key, old_c, old_h, target.critical, target.high,
    )

    entry = current_state["targets"].setdefault(target.id, {})
    entry["critical"]     = target.critical
    entry["high"]         = target.high
    entry["last_changed"] = today
    entry["last_synced"]  = today

    result.updated.append(UpdatedTicket(
        target_name=target.display_name,
        ticket_key=ticket_key,
        ticket_url=jira.ticket_url(ticket_key),
        old_critical=old_c,
        old_high=old_h,
        new_critical=target.critical,
        new_high=target.high,
        snyk_url=_snyk_target_url(target.id),
    ))

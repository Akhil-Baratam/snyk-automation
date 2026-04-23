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
    """Best-effort Snyk UI URL for a target (project page)."""
    ui_base = config.SNYK_API_BASE_URL.replace("api.snyk.io", "app.snyk.io").rstrip("/")
    return f"{ui_base}/org/{config.SNYK_ORG_ID}/project/{target_id}"


# ── Jira ticket content builders ──────────────────────────────────────────────

def _build_summary(display_name: str, critical: int, high: int, today: str) -> str:
    """
    Produces:  Snyk Vulnerabilities Check Repo Name: <name>, Severity[C4H12 as on 22/04/26]

    today is ISO format YYYY-MM-DD; the spec wants DD/MM/YY.
    """
    parts = today.split("-")          # ["2026", "04", "23"]
    dd_mm_yy = f"{parts[2]}/{parts[1]}/{parts[0][2:]}"   # "23/04/26"
    return (
        f"Snyk Vulnerabilities Check Repo Name: {display_name},"
        f" Severity[C{critical}H{high} as on {dd_mm_yy}]"
    )


# ── ADF helpers ───────────────────────────────────────────────────────────────

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


def _heading(text: str, level: int = 3) -> dict:
    return {
        "type": "heading",
        "attrs": {"level": level},
        "content": [_text(text, bold=True)],
    }


def _build_adf_description(target: SnykTarget) -> dict:
    """
    ADF document matching §13 of the spec.

    Table 1 — Vulnerability breakdown by scanned file
      File | Critical | High

    Table 2 — GitLab project details
      GitLab Project | Snyk Target | Files Scanned
    """
    snyk_url = _snyk_target_url(target.id)

    # Table 1: per-file breakdown
    header_row_1 = _row([
        _cell([_text("File", bold=True)], is_header=True),
        _cell([_text("Critical", bold=True)], is_header=True),
        _cell([_text("High", bold=True)], is_header=True),
    ])
    file_rows = [
        _row([
            _cell([_text(p.name)]),
            _cell([_text(str(p.critical))]),
            _cell([_text(str(p.high))]),
        ])
        for p in target.projects
    ]
    if not file_rows:
        file_rows = [_row([
            _cell([_text("(no file-level data)")]),
            _cell([_text("—")]),
            _cell([_text("—")]),
        ])]

    # Table 2: target summary
    header_row_2 = _row([
        _cell([_text("GitLab Project", bold=True)], is_header=True),
        _cell([_text("Snyk Target", bold=True)], is_header=True),
        _cell([_text("Files Scanned", bold=True)], is_header=True),
    ])
    summary_row = _row([
        _cell([_text(target.display_name)]),
        _cell([_link_node("Open in Snyk", snyk_url)]),
        _cell([_text(str(len(target.projects)))]),
    ])

    return {
        "type": "doc",
        "version": 1,
        "content": [
            _heading("Vulnerability Breakdown by File"),
            _table([header_row_1, *file_rows]),
            _heading("GitLab Project Details"),
            _table([header_row_2, summary_row]),
        ],
    }


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

        ticket_url = jira.ticket_url(ticket.key)
        target_name = ticket.summary  # best available without extra API call

        if snyk_id not in all_target_ids:
            # Target UUID not seen in Snyk at all — deleted or renamed
            result.flagged.append(FlaggedTicket(
                target_name=target_name,
                ticket_key=ticket.key,
                ticket_url=ticket_url,
                reason="project_deleted",
            ))
            logger.info("[%s] %s — flagged: project_deleted", target_name, ticket.key)

        elif snyk_id not in target_ids_with_vulns:
            # Target exists in Snyk but has zero C/H vulns — was filtered out in Phase 1
            result.flagged.append(FlaggedTicket(
                target_name=target_name,
                ticket_key=ticket.key,
                ticket_url=ticket_url,
                reason="vulns_resolved",
            ))
            logger.info("[%s] %s — flagged: vulns_resolved", target_name, ticket.key)
        # else: ticket correctly open, handled by forward check — no action

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

    # Step C — branch
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
    summary = _build_summary(target.display_name, target.critical, target.high, today)
    description = _build_adf_description(target)
    custom_fields = {
        config.JIRA_FIELD_SNYK_PROJECT_ID: target.id,
        config.JIRA_FIELD_SNYK_CRITICAL_COUNT: target.critical,
        config.JIRA_FIELD_SNYK_HIGH_COUNT: target.high,
        config.JIRA_FIELD_SNYK_LAST_SYNCED: today,
    }
    key = jira.create_ticket(summary, description, custom_fields)
    logger.info("[%s] NO ticket found → created %s", target.display_name, key)

    entry = state.upsert_target(current_state, target.id, target.display_name)
    entry["jira_ticket"] = key
    entry["created_today"] = True
    entry["critical"] = target.critical
    entry["high"] = target.high
    entry["last_changed"] = today
    entry["last_synced"] = today

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
        config.JIRA_FIELD_SNYK_HIGH_COUNT: target.high,
        config.JIRA_FIELD_SNYK_LAST_SYNCED: today,
    })
    logger.info(
        "[%s] Ticket %s — CHANGED C%dH%d→C%dH%d → updating fields",
        target.display_name, ticket_key, old_c, old_h, target.critical, target.high,
    )

    entry = current_state["targets"].setdefault(target.id, {})
    entry["critical"] = target.critical
    entry["high"] = target.high
    entry["last_changed"] = today
    entry["last_synced"] = today

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

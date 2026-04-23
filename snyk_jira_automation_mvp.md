# Snyk → Jira → Teams Automation — MVP Technical Specification

**Version**: 1.0  
**Status**: Ready for Implementation  
**Last Updated**: April 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Data Model & Terminology](#2-data-model--terminology)
3. [Architecture Overview](#3-architecture-overview)
4. [Tech Stack](#4-tech-stack)
5. [Repository Structure](#5-repository-structure)
6. [Environment Variables](#6-environment-variables)
7. [Pre-requisites Before First Run](#7-pre-requisites-before-first-run)
8. [State File Schema](#8-state-file-schema)
9. [Phase 0 — Startup Validation](#9-phase-0--startup-validation)
10. [Phase 1 — Data Collection (Snyk)](#10-phase-1--data-collection-snyk)
11. [Phase 2 — Jira Sync](#11-phase-2--jira-sync)
12. [Phase 3 — Teams Notification](#12-phase-3--teams-notification)
13. [Jira Ticket Specification](#13-jira-ticket-specification)
14. [Teams Card Specification](#14-teams-card-specification)
15. [Error Handling & Reliability](#15-error-handling--reliability)
16. [Rate Limit Strategy](#16-rate-limit-strategy)
17. [Logging](#17-logging)
18. [Argo Workflows Integration](#18-argo-workflows-integration)
19. [Non-Goals (Deferred)](#19-non-goals-deferred)

---

## 1. Project Overview

### Background

The team currently has a manual daily workflow:

1. Snyk sends an email at **7:15 PM IST** with a summary of vulnerabilities across all monitored GitLab repos.
2. A team member manually checks the Snyk UI to identify which repos have **Critical** or **High** vulnerabilities.
3. They manually create or update Jira tickets on the **PSUP board** with label **`snyk-jolt`** for each affected repo.
4. They post updates to a **Microsoft Teams channel**.

This entire process is manual, error-prone, time-consuming, and does not guarantee that Jira stays in sync with Snyk over time.

### Goal

Automate the above workflow with a reliable daily batch job that:

- Identifies all GitLab repos (Snyk "targets") with Critical/High vulnerabilities.
- Ensures every such repo has an **open** Jira ticket in the PSUP board under label `snyk-jolt`.
- Detects when counts change on existing tickets and notifies the team.
- Detects when Jira tickets are open but the repo no longer has Critical/High vulns (reverse sync).
- Sends one consolidated Microsoft Teams notification per day with the full summary.

### Design Principles

- **Snyk is the source of truth.** Jira reflects Snyk's state.
- **One notification per day.** No per-vulnerability noise. The team acts once, after the Snyk mail.
- **Phases are independent and restartable.** A failure in Phase 2 does not corrupt Phase 1 data.
- **State lives in S3.** The script is stateless; all run state is persisted externally.
- **Fail loudly, never silently.** Any failure sends an immediate Teams alert.

---

## 2. Data Model & Terminology

This is critical to understand before reading any further. Snyk's UI and API use the terms "project" and "target" in specific ways that differ from common usage.

| Term | Snyk Meaning | Mapped to in this System |
|------|-------------|--------------------------|
| **Target** | A GitLab **repository** (e.g., `smartsense4/jolt-php7-apache`) | One **Jira ticket** |
| **Project** | A specific **file** inside a repo being scanned (e.g., `Dockerfile`, `package.json`, `composer.lock`) | A **row** in the Jira ticket's description table |
| **Org** | The Snyk organization containing all targets | Configured via `SNYK_ORG_ID` |

**Key rule**: All Jira tickets are **target-wise** (one per repo). The internal file-level breakdowns (projects) appear inside the ticket description, not as separate tickets.

### Snyk Data Flow

```
Snyk Org
  └── Target: smartsense4/jolt-php7-apache   ← One Jira ticket
        ├── Project: Dockerfile               ← Row in description table
        ├── Project: 7.1/Dockerfile           ← Row in description table
        └── Project: composer.lock            ← Row in description table
```

The vulnerability **counts (Critical, High)** per target are obtained by:
1. Fetching **all projects** for the org in one paginated API call.
2. Grouping projects by their `target.id` relationship field in memory.
3. Summing `issueCountsBySeverity.critical` and `issueCountsBySeverity.high` per group.

There is **no direct API endpoint** that returns per-target aggregated counts. This aggregation is done in memory by the script.

---

## 3. Architecture Overview

### Flow Diagram (Text)

```
[Argo Workflow Trigger — 7:30 PM IST daily]
        │
        ▼
[Phase 0: Startup Validation]
  Check: Snyk API reachable, Jira API reachable,
         4 custom fields exist, Teams webhook reachable,
         S3 state file accessible
  → FAIL: send Teams failure alert, abort
  → PASS: continue
        │
        ▼
[Phase 1: Data Collection — Snyk API]
  → Fetch all org projects (paginated, single stream)
  → Group by target_id in memory
  → Sum Critical + High per target
  → Fetch target display names (repo names)
  → Filter: keep only targets where C > 0 OR H > 0
  → Write snapshot to snyk_state.json (in-memory)
  → Upload state to S3 with run_status: "partial"
  → FAIL: upload state with run_status: "failed", send Teams alert, abort
        │
        ▼
[Phase 2: Jira Sync]

  ── Forward Check (Snyk → Jira) ──────────────────────
  For each target with C/H vulns:
    1. Check idempotency: state file has created_today=true? → skip (prevents re-run duplicates)
    2. Search Jira for open ticket:
       Primary:  snyk_project_id custom field = target.id + status != closed
       Fallback: label:snyk-jolt + summary contains target name + status != closed
    3a. NO ticket found:
        → Create new Jira ticket (see §13 for full spec)
        → Set all 4 custom fields
        → Save to temp_created[] in memory
        → Mark created_today=true in state
    3b. YES ticket, counts CHANGED (C or H differs from state file):
        → Auto-update 3 custom fields: snyk_critical_count, snyk_high_count, snyk_last_synced
        → Do NOT touch Jira summary or description (manual update for now)
        → Save delta to temp_updated[] in memory
        → Update counts in state file
    3c. YES ticket, counts SAME:
        → Skip. Log as "no-change". Update last_synced in state only.

  ── Reverse Check (Jira → Snyk) ─────────────────────
  → One JQL query: all open tickets with label snyk-jolt
  → For each ticket, read snyk_project_id custom field
  → Cross-check against Phase 1 snapshot:
    MISSING from Snyk entirely → save to temp_flagged[] reason: "project_deleted"
    EXISTS but no C/H vulns    → save to temp_flagged[] reason: "vulns_resolved"
    EXISTS with C/H            → no action (handled in forward check)
        │
        ▼
[Phase 3: Teams Notification]
  → Build consolidated Adaptive Card from temp_created[], temp_updated[], temp_flagged[]
  → Measure JSON payload size
  → IF size < 22KB: send single card
  → IF size >= 22KB: split into separate cards per section (Part 1/2/3)
  → On success: update run_status: "complete" in state, upload to S3
  → FAIL: send minimal failure alert card
```

### What Triggers a Teams Alert (Immediate, Separate from Daily Card)

- Phase 0 validation fails (any dependency unreachable or missing)
- Phase 1 fails (Snyk API error, S3 write error)
- Phase 2 fails mid-run (Jira API error after partial processing)
- Phase 3 fails (Teams POST fails)
- Processed count < total count at end of run (partial run detected)

---

## 4. Tech Stack

| Component | Choice | Reason |
|-----------|--------|--------|
| Language | Python 3.11+ | Simple, rich ecosystem, readable |
| Snyk API | REST API v1 + `2024-10-15` versioned REST | REST API for projects; v1 for issue counts where needed |
| Jira API | Jira Cloud REST API v3 | Full ticket lifecycle |
| Teams | Incoming Webhook + Adaptive Cards | Rich formatting, one card per run |
| State | JSON file in AWS S3 | Persistent, auditable, free, fits AWS stack |
| Secrets (local) | `.env` file via `python-dotenv` | Simple local development |
| Secrets (prod) | AWS Secrets Manager | Already in use by team |
| Scheduler | Argo Workflows (cron) | Team's existing infrastructure |
| Logging | Python `logging` module → dated log files | Per-run audit trail |
| HTTP client | `requests` with retry adapter | Simple, reliable |
| S3 client | `boto3` | AWS SDK for Python |

### Python Dependencies

```
requests>=2.31.0
boto3>=1.34.0
python-dotenv>=1.0.0
```

No other external dependencies required.

---

## 5. Repository Structure

```
snyk-jira-automation/
├── .env.example                  # Template for local env vars (committed)
├── .env                          # Actual local secrets (gitignored)
├── .gitignore
├── README.md
├── requirements.txt
│
├── main.py                       # Entry point — orchestrates all phases
│
├── config.py                     # Loads and validates all env vars at startup
│
├── state.py                      # S3 state file read/write logic
│
├── phases/
│   ├── __init__.py
│   ├── validation.py             # Phase 0: startup validation
│   ├── collect.py                # Phase 1: Snyk data collection
│   ├── sync.py                   # Phase 2: Jira forward + reverse sync
│   └── notify.py                 # Phase 3: Teams card build + send
│
├── clients/
│   ├── __init__.py
│   ├── snyk.py                   # Snyk API client (paginated fetch, retry logic)
│   ├── jira.py                   # Jira API client (search, create, update)
│   └── teams.py                  # Teams webhook client (send card, size guard)
│
├── models/
│   ├── __init__.py
│   ├── target.py                 # SnykTarget dataclass
│   ├── ticket.py                 # JiraTicket dataclass
│   └── run_result.py             # RunResult dataclass (temp_created, temp_updated, temp_flagged)
│
├── utils/
│   ├── __init__.py
│   ├── logger.py                 # Logger setup (file + console handlers)
│   └── retry.py                  # Exponential backoff decorator
│
└── logs/                         # Auto-created at runtime (gitignored)
    └── YYYY-MM-DD.log
```

---

## 6. Environment Variables

### `.env.example` (Full Template)

Every variable listed here must be present. The script validates all of them at startup and will abort with a clear error if any are missing.

```dotenv
# ─────────────────────────────────────────────
# SNYK
# ─────────────────────────────────────────────

# Snyk API token (personal token or service account)
SNYK_API_TOKEN=

# Snyk Organization ID (UUID format)
# Find it: Snyk UI → Settings → General → Organization ID
SNYK_ORG_ID=

# Snyk API base URL (default shown — change only for self-hosted)
SNYK_API_BASE_URL=https://api.snyk.io


# ─────────────────────────────────────────────
# JIRA
# ─────────────────────────────────────────────

# Jira Cloud base URL (no trailing slash)
JIRA_BASE_URL=https://yourorg.atlassian.net

# Jira user email (the account whose API token is used)
JIRA_USER_EMAIL=

# Jira API token
# Generate: https://id.atlassian.com/manage-profile/security/api-tokens
JIRA_API_TOKEN=

# Jira project key for ticket creation
JIRA_PROJECT_KEY=PSUP

# Jira label applied to all automation-managed tickets
JIRA_TICKET_LABEL=snyk-jolt

# Jira issue type for created tickets (usually "Task" or "Bug" — confirm with your Jira admin)
JIRA_ISSUE_TYPE=Task

# Custom field IDs for the 4 required fields
# Find IDs: GET /rest/api/3/field → look for custom fields you created
# Format: customfield_XXXXX
JIRA_FIELD_SNYK_PROJECT_ID=customfield_
JIRA_FIELD_SNYK_CRITICAL_COUNT=customfield_
JIRA_FIELD_SNYK_HIGH_COUNT=customfield_
JIRA_FIELD_SNYK_LAST_SYNCED=customfield_


# ─────────────────────────────────────────────
# MICROSOFT TEAMS
# ─────────────────────────────────────────────

# Incoming Webhook URL for the target Teams channel
# Create: Teams channel → Connectors → Incoming Webhook → Configure
TEAMS_WEBHOOK_URL=


# ─────────────────────────────────────────────
# AWS / S3 STATE FILE
# ─────────────────────────────────────────────

# S3 bucket name where snyk_state.json is stored
S3_BUCKET_NAME=

# S3 object key (path) for the state file
S3_STATE_FILE_KEY=snyk-automation/snyk_state.json

# AWS region
AWS_REGION=ap-south-1

# AWS credentials (leave blank if using IAM role / instance profile in prod)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=


# ─────────────────────────────────────────────
# SCRIPT BEHAVIOUR
# ─────────────────────────────────────────────

# Max number of retry attempts for any API call before failing
MAX_RETRY_ATTEMPTS=3

# Base delay in seconds for exponential backoff (doubles each retry)
RETRY_BASE_DELAY_SECONDS=2

# Page size for Snyk API paginated calls (max 100 per Snyk docs)
SNYK_PAGE_SIZE=100

# Max results per Jira JQL search page
JIRA_PAGE_SIZE=50

# Teams card size limit in bytes (hard limit is 28672; use 22528 as safe ceiling)
TEAMS_CARD_SIZE_LIMIT_BYTES=22528

# Set to "true" to enable debug-level logging
DEBUG_LOGGING=false
```

### Config Validation (`config.py`)

At startup, `config.py` loads all variables and asserts none are empty. If any required variable is missing or blank:
- Print a clear error listing the missing variable name.
- Exit with code 1 before any API calls are made.

Required variables (all of the above except `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` which may be empty if using IAM role).

---

## 7. Pre-requisites Before First Run

These steps must be completed **manually** by a human before the automation is ever run. The script does not create these — it only validates they exist.

### 7.1 Jira Custom Fields

Create four custom fields in your Jira instance (Jira Settings → Issues → Custom Fields → Add Custom Field):

| Field Name | Field Type | Notes |
|------------|------------|-------|
| `snyk_project_id` | Text Field (single line) | Stores the Snyk Target UUID |
| `snyk_critical_count` | Number Field | Integer — current Critical vuln count |
| `snyk_high_count` | Number Field | Integer — current High vuln count |
| `snyk_last_synced` | Date Picker | Date automation last synced this ticket |

After creation, find each field's ID by calling:
```
GET https://yourorg.atlassian.net/rest/api/3/field
Authorization: Basic <base64(email:token)>
```
Look for fields with matching names. The ID will be in format `customfield_XXXXX`. Enter these IDs into your `.env` file.

**Associate the fields with the PSUP project screen** so they appear on tickets. Without this, the fields exist but cannot be written to on PSUP tickets.

### 7.2 S3 Bucket

- Create an S3 bucket (e.g., `your-team-snyk-automation`).
- Enable **versioning** on the bucket — this gives you a full daily history of state files at zero extra effort.
- Ensure the IAM role/user used by the script has `s3:GetObject` and `s3:PutObject` on the bucket.
- The state file does not need to exist before the first run — the script creates it.

### 7.3 Teams Incoming Webhook

- Go to your target Teams channel → click `...` → Connectors → Incoming Webhook → Configure.
- Name it `Snyk Automation`.
- Copy the webhook URL into `TEAMS_WEBHOOK_URL` in your `.env`.

### 7.4 Snyk API Token

- Go to Snyk UI → Account Settings → API Token.
- Use a service account token if available, not a personal token.
- Confirm the token has read access to the org specified in `SNYK_ORG_ID`.

---

## 8. State File Schema

The state file (`snyk_state.json`) is the single source of truth for delta detection. It lives in S3, is downloaded at the start of every run, modified in memory throughout, and uploaded back at the end.

```json
{
  "schema_version": 1,
  "last_run": "2026-04-22T19:30:00+05:30",
  "run_status": "complete",
  "processed_count": 59,
  "total_count": 59,
  "targets": {
    "<snyk_target_uuid>": {
      "display_name": "smartsense4/jolt-php7-apache",
      "critical": 4,
      "high": 12,
      "jira_ticket": "PSUP-1042",
      "created_today": false,
      "last_changed": "2026-04-22",
      "last_synced": "2026-04-22"
    },
    "<another_target_uuid>": {
      "display_name": "smartsense4/jolt-node-app",
      "critical": 0,
      "high": 3,
      "jira_ticket": "PSUP-1055",
      "created_today": false,
      "last_changed": "2026-04-20",
      "last_synced": "2026-04-22"
    }
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | int | Always `1` for this MVP. Used for future migration handling. |
| `last_run` | ISO 8601 string | Timestamp of when the last run started (with timezone). |
| `run_status` | string | `"partial"` during run, `"complete"` on success, `"failed"` on abort. |
| `processed_count` | int | Number of targets successfully processed in Phase 2. |
| `total_count` | int | Total number of targets fetched in Phase 1. Used to detect partial runs. |
| `targets[id].display_name` | string | Human-readable repo name from Snyk. |
| `targets[id].critical` | int | Last known Critical count from Snyk. Used for delta detection. |
| `targets[id].high` | int | Last known High count from Snyk. Used for delta detection. |
| `targets[id].jira_ticket` | string or null | Jira ticket key (e.g., `PSUP-1042`). Null if no ticket exists yet. |
| `targets[id].created_today` | bool | True if this target's ticket was created in today's run. Idempotency guard. |
| `targets[id].last_changed` | date string | Date when C or H count last changed. Updated only on delta detection. |
| `targets[id].last_synced` | date string | Date of last successful sync for this target. Updated every run. |

### State File Lifecycle

```
Run start → download from S3 (or create empty if first run)
Phase 1   → write total_count, populate/update targets snapshot, run_status="partial", upload
Phase 2   → update per-target fields as work progresses (in memory)
Phase 3   → set run_status="complete", processed_count, upload final state
Any fail  → set run_status="failed", upload, send alert
```

**Important**: The state file is uploaded to S3 after Phase 1 completes (as a checkpoint). If Phase 2 or 3 fails, the Phase 1 snapshot is still preserved. The final upload at Phase 3 end replaces it with the complete state.

### `created_today` Reset Logic

At the start of every run, before Phase 1 begins:
- Load existing state from S3.
- Check `last_run` date. If it matches today's date → this is a re-run of the same day.
  - Keep `created_today` flags as-is (idempotency: skip re-creating already-created tickets).
- If `last_run` date is a previous day → this is a fresh run.
  - Reset **all** `created_today` flags to `false` before proceeding.

---

## 9. Phase 0 — Startup Validation

**File**: `phases/validation.py`  
**Runs**: Before Phase 1, immediately after config loads.  
**Purpose**: Fail fast before any business logic runs if the environment is broken.

### Checks (in order)

1. **Config completeness**: All required env vars are non-empty (done in `config.py`, but re-validated here).

2. **Snyk API reachability**:
   ```
   GET /rest/orgs/{SNYK_ORG_ID}?version=2024-10-15
   Authorization: token {SNYK_API_TOKEN}
   ```
   Expect: HTTP 200. If 401 → token invalid. If 404 → org ID wrong. If timeout → Snyk unreachable.

3. **Jira API reachability**:
   ```
   GET /rest/api/3/myself
   Authorization: Basic base64(email:token)
   ```
   Expect: HTTP 200.

4. **Jira custom fields exist**:
   ```
   GET /rest/api/3/field
   ```
   Parse response. Confirm all four field IDs from env vars appear in the list. If any is missing, list which ones are absent in the error message.

5. **Teams webhook reachability**:
   POST an empty payload `{}` to `TEAMS_WEBHOOK_URL`. Expect HTTP 200 or a Teams-specific acknowledgment. (Teams accepts empty payloads for connectivity checks.)

6. **S3 access**:
   Attempt `s3.head_bucket(Bucket=S3_BUCKET_NAME)`. Expect success. If AccessDenied → IAM permissions wrong.

### On Any Check Failure

- Log the specific failure with detail.
- **If Teams webhook itself is the failure**: log to console/file only, cannot send Teams alert.
- **For all other failures**: send a minimal Teams failure card (see §15), then exit with code 1.

---

## 10. Phase 1 — Data Collection (Snyk API)

**File**: `phases/collect.py`  
**Client**: `clients/snyk.py`

### Step 1.1 — Fetch All Projects (Single Paginated Stream)

```
GET /rest/orgs/{SNYK_ORG_ID}/projects?version=2024-10-15&limit={SNYK_PAGE_SIZE}
Authorization: token {SNYK_API_TOKEN}
```

This returns all projects across all targets for the org. Follow pagination using the `links.next` cursor in the response until there is no `next` link.

**Fields to extract from each project object**:
- `id` — project UUID (not used as anchor, but logged)
- `attributes.name` — project file name (e.g., `Dockerfile`)
- `attributes.status` — skip if not `"active"`
- `attributes.issueCounts.critical` — Critical issue count for this project file
- `attributes.issueCounts.high` — High issue count for this project file
- `relationships.target.data.id` — the target UUID this project belongs to (**key field**)

**Note on API field names**: The exact field path for issue counts may be `attributes.issueCounts` or `attributes.issueCountsBySeverity` depending on API version. Confirm with a test call and adjust accordingly.

### Step 1.2 — Group by Target in Memory

```python
# Pseudocode
target_map = {}  # { target_id: { critical_sum, high_sum, projects: [] } }

for project in all_projects:
    if project.status != "active":
        continue
    tid = project.relationships.target.data.id
    if tid not in target_map:
        target_map[tid] = { "critical": 0, "high": 0, "projects": [] }
    target_map[tid]["critical"] += project.issueCounts.critical
    target_map[tid]["high"] += project.issueCounts.high
    target_map[tid]["projects"].append(project.name)
```

### Step 1.3 — Fetch Target Display Names

```
GET /rest/orgs/{SNYK_ORG_ID}/targets?version=2024-10-15&limit={SNYK_PAGE_SIZE}
```

Paginate similarly. For each target, extract:
- `id` — target UUID
- `attributes.displayName` — repo name (e.g., `smartsense4/jolt-php7-apache`)

Build a lookup dict `{ target_id: display_name }`. Join onto `target_map`.

### Step 1.4 — Filter

Remove targets from `target_map` where `critical == 0 AND high == 0`. These have no action required.

Record `total_count = len(target_map)` (count after filtering).

### Step 1.5 — Write to State File and Upload

Update the in-memory state object:
- Set `last_run` to now (ISO 8601 with timezone).
- Set `run_status` to `"partial"`.
- Set `total_count`.
- For each target in `target_map`: create or update the `targets[id]` entry. Preserve existing fields (`jira_ticket`, `created_today`, `last_changed`) if the target existed before. Set/update `display_name`.

Upload state to S3. This is the Phase 1 checkpoint.

### Error Handling for Phase 1

- On any HTTP error from Snyk: retry with exponential backoff (see §16).
- If all retries exhausted: set `run_status: "failed"` in state, upload to S3, send Teams failure alert, exit.
- Track `processed_count` per target as Phase 2 runs (Phase 1 itself just fetches all at once).

---

## 11. Phase 2 — Jira Sync

**File**: `phases/sync.py`  
**Client**: `clients/jira.py`

Phase 2 runs two sub-phases sequentially: Forward Check, then Reverse Check.

### In-Memory Accumulators

Initialised at the start of Phase 2. These feed Phase 3.

```python
temp_created = []   # List of { target_name, ticket_key, snyk_link, critical, high }
temp_updated = []   # List of { target_name, ticket_key, old_c, old_h, new_c, new_h, snyk_link }
temp_flagged = []   # List of { target_name, ticket_key, reason }  # reason: "project_deleted" | "vulns_resolved"
```

### 11.1 — Forward Check (Snyk → Jira)

Iterate over every target in the Phase 1 snapshot (targets with C/H > 0).

**For each target:**

#### Step A — Idempotency Check

```python
state_entry = state["targets"].get(target_id, {})
if state_entry.get("created_today") == True:
    log("Skipping — ticket already created in this run's earlier attempt")
    processed_count += 1
    continue
```

#### Step B — Search for Existing Open Ticket

**Primary search** (by Snyk project ID custom field):
```
GET /rest/api/3/issue/search
JQL: "{JIRA_FIELD_SNYK_PROJECT_ID}" = "{target_id}" AND labels = "{JIRA_TICKET_LABEL}" AND statusCategory != Done
fields: id,key,summary,status,{JIRA_FIELD_SNYK_PROJECT_ID},{JIRA_FIELD_SNYK_CRITICAL_COUNT},{JIRA_FIELD_SNYK_HIGH_COUNT}
```

**Fallback search** (if primary returns 0 results):
```
JQL: labels = "{JIRA_TICKET_LABEL}" AND summary ~ "{target_display_name}" AND statusCategory != Done
fields: same as above
```

If fallback finds a ticket: **backfill** the `snyk_project_id` custom field on that ticket immediately (one `PUT /rest/api/3/issue/{key}` call setting only that field). This migrates it to the primary lookup for all future runs.

**Note on status filter**: Use `statusCategory != Done` rather than `status != Closed` — this correctly catches all non-terminal statuses (Backlog, In Progress, Selected for Development, etc.) regardless of your Jira workflow's specific status names.

#### Step C — Branch Logic

**Branch A: No ticket found**

```python
# Create new Jira ticket
ticket_key = jira_client.create_ticket(
    summary=build_summary(target_name, critical, high, today),
    description=build_description(target, projects),
    project_key=JIRA_PROJECT_KEY,
    issue_type=JIRA_ISSUE_TYPE,
    labels=[JIRA_TICKET_LABEL],
    custom_fields={
        JIRA_FIELD_SNYK_PROJECT_ID: target_id,
        JIRA_FIELD_SNYK_CRITICAL_COUNT: critical,
        JIRA_FIELD_SNYK_HIGH_COUNT: high,
        JIRA_FIELD_SNYK_LAST_SYNCED: today_date_string
    }
)

# Update state
state["targets"][target_id]["jira_ticket"] = ticket_key
state["targets"][target_id]["created_today"] = True
state["targets"][target_id]["critical"] = critical
state["targets"][target_id]["high"] = high
state["targets"][target_id]["last_changed"] = today_date_string
state["targets"][target_id]["last_synced"] = today_date_string

# Record for Teams card
temp_created.append({
    "target_name": target_display_name,
    "ticket_key": ticket_key,
    "ticket_url": build_jira_url(ticket_key),
    "snyk_url": build_snyk_target_url(target_id),
    "critical": critical,
    "high": high
})
```

**Branch B: Ticket exists, counts CHANGED** (compare C and H individually against state file values)

```python
old_c = state["targets"][target_id].get("critical", 0)
old_h = state["targets"][target_id].get("high", 0)

if critical != old_c or high != old_h:
    # Auto-update only the 3 machine fields — do NOT touch summary or description
    jira_client.update_fields(ticket_key, {
        JIRA_FIELD_SNYK_CRITICAL_COUNT: critical,
        JIRA_FIELD_SNYK_HIGH_COUNT: high,
        JIRA_FIELD_SNYK_LAST_SYNCED: today_date_string
    })

    # Update state
    state["targets"][target_id]["critical"] = critical
    state["targets"][target_id]["high"] = high
    state["targets"][target_id]["last_changed"] = today_date_string
    state["targets"][target_id]["last_synced"] = today_date_string

    # Record for Teams card
    temp_updated.append({
        "target_name": target_display_name,
        "ticket_key": ticket_key,
        "ticket_url": build_jira_url(ticket_key),
        "old_critical": old_c, "old_high": old_h,
        "new_critical": critical, "new_high": high,
        "snyk_url": build_snyk_target_url(target_id)
    })
```

**Branch C: Ticket exists, counts SAME**

```python
# No Jira API call. Just update last_synced in state.
state["targets"][target_id]["last_synced"] = today_date_string
log(f"No change for {target_display_name} — skipping")
```

Increment `processed_count` after each target regardless of branch.

### 11.2 — Reverse Check (Jira → Snyk)

**One JQL query to get all open snyk-jolt tickets:**

```
JQL: labels = "{JIRA_TICKET_LABEL}" AND statusCategory != Done
fields: id, key, summary, {JIRA_FIELD_SNYK_PROJECT_ID}
maxResults: {JIRA_PAGE_SIZE}
```

Paginate through all results.

**For each ticket:**

1. Read `snyk_project_id` custom field value from the ticket.
2. If field is blank/null: log a warning ("ticket missing snyk_project_id — cannot reverse-check"), skip.
3. Check if `snyk_project_id` value exists as a key in the Phase 1 snapshot (`target_map`).

```python
phase1_snapshot = state["targets"]  # populated in Phase 1

if snyk_project_id not in phase1_snapshot:
    # Target completely missing from Snyk
    temp_flagged.append({
        "target_name": extract_name_from_summary(ticket.summary),
        "ticket_key": ticket.key,
        "ticket_url": build_jira_url(ticket.key),
        "reason": "project_deleted"
    })
elif phase1_snapshot[snyk_project_id]["critical"] == 0 and phase1_snapshot[snyk_project_id]["high"] == 0:
    # Target exists in Snyk but has no C/H vulns (was filtered out in Phase 1)
    # Note: This shouldn't normally appear since Phase 1 only keeps targets with C/H > 0
    # But the original full fetch data should be used here if we want to distinguish "clean" vs "missing"
    # Implementation note: Keep a separate full_target_ids set from Phase 1 before filtering
    temp_flagged.append({
        "target_name": extract_name_from_summary(ticket.summary),
        "ticket_key": ticket.key,
        "ticket_url": build_jira_url(ticket.key),
        "reason": "vulns_resolved"
    })
else:
    # Ticket correctly open — forward check handled it
    pass
```

**Implementation note for reverse check accuracy**: In Phase 1, before filtering to only C/H > 0 targets, store the full set of all target IDs in a variable `all_target_ids`. This lets the reverse check distinguish "target exists but is clean" from "target missing from Snyk entirely."

---

## 12. Phase 3 — Teams Notification

**File**: `phases/notify.py`  
**Client**: `clients/teams.py`

### Step 3.1 — Determine if Run Was Partial

```python
is_partial = state["processed_count"] < state["total_count"]
```

### Step 3.2 — Build the Adaptive Card

Build a Python dict representing the Adaptive Card JSON.

**Card structure**:

```
[Header block]
  📅 {date} — Snyk Automation Results
  🔴 New tickets: {len(temp_created)}
  🟡 Count changed: {len(temp_updated)}
  🔵 Flagged for review: {len(temp_flagged)}
  [⚠ WARNING: Partial run — processed {n}/{total}] ← only if partial

[Table 1: New Tickets Created]   ← only if temp_created not empty
  Columns: Project Name | Jira Ticket | Snyk Link | Severity
  One row per entry in temp_created[]

[Table 2: Existing Tickets — Count Changed]   ← only if temp_updated not empty
  Columns: Project Name | Jira Ticket | Old Count | New Count | Snyk Link
  "Old Count" format: C{old_c}H{old_h} → C{new_c}H{new_h}

[Table 3: Tickets to Review for Closure]   ← only if temp_flagged not empty
  Columns: Project Name | Jira Ticket | Reason
  Reason display: "Project deleted/renamed in Snyk" or "All C/H vulns resolved"
  Note: "Please close these tickets manually if appropriate."
```

### Step 3.3 — Card Size Guard

```python
card_json = json.dumps(adaptive_card_payload)
card_size = len(card_json.encode("utf-8"))

if card_size <= TEAMS_CARD_SIZE_LIMIT_BYTES:
    teams_client.send_card(adaptive_card_payload)
else:
    # Split into separate cards, one per table section
    send_card_header_only(summary_counts, is_partial, note="Full details follow in next messages...")
    if temp_created:
        send_card_section("Part 1/3 — New Tickets Created", temp_created, table_type="created")
    if temp_updated:
        send_card_section("Part 2/3 — Count Changed", temp_updated, table_type="updated")
    if temp_flagged:
        send_card_section("Part 3/3 — Flagged for Closure", temp_flagged, table_type="flagged")
```

Each split card is sent with a small delay (0.5 seconds) between them to avoid the Teams 4 req/sec limit.

### Step 3.4 — Finalise State

```python
state["run_status"] = "complete"
state["processed_count"] = processed_count
upload_state_to_s3(state)
```

---

## 13. Jira Ticket Specification

### Summary Format

```
Snyk Vulnerabilities Check Repo Name: {target_display_name}, Severity[C{critical}H{high} as on {DD/MM/YY}]
```

**Example**:
```
Snyk Vulnerabilities Check Repo Name: smartsense4/jolt-php7-apache, Severity[C4H12 as on 22/04/26]
```

**Date semantics**: The date in the summary is the date when the CxHy count was **last checked and confirmed**. It is updated whenever critical OR high count changes. If the count is the same as yesterday, the summary date is NOT updated (only the `snyk_last_synced` custom field is updated).

### Description Format

The description contains two tables. Build using Jira's Atlassian Document Format (ADF) for Jira Cloud v3 API.

**Table 1 — Vulnerability Details**

| Column | Content |
|--------|---------|
| Snyk Vulnerability Link | Link to the specific vuln in Snyk UI |
| Severity | Critical / High |
| Affected Package | Package name and version |
| GitLab File Link | Link to the specific file in GitLab repo |
| Fix Available | Yes / No |

**Table 2 — GitLab Project Details**

| Column | Content |
|--------|---------|
| GitLab Project | Repo name with link to GitLab |
| Snyk Target Link | Link to the target in Snyk UI |
| Total Files Scanned | Number of Snyk projects (files) under this target |

### Jira Fields on Creation

```python
{
    "fields": {
        "project": { "key": JIRA_PROJECT_KEY },
        "issuetype": { "name": JIRA_ISSUE_TYPE },
        "summary": build_summary(target_name, critical, high, today),
        "description": build_adf_description(target, projects),
        "labels": [JIRA_TICKET_LABEL],
        "priority": { "name": "Critical" if critical > 0 else "High" },
        JIRA_FIELD_SNYK_PROJECT_ID: target_id,
        JIRA_FIELD_SNYK_CRITICAL_COUNT: critical,
        JIRA_FIELD_SNYK_HIGH_COUNT: high,
        JIRA_FIELD_SNYK_LAST_SYNCED: today_iso_date
    }
}
```

---

## 14. Teams Card Specification

### Card Style Guidelines

- Header row: bold, dark background
- Table 1 (new tickets): red accent left border
- Table 2 (changed counts): amber accent left border  
- Table 3 (flagged): blue accent left border
- Partial run warning block: prominent red/orange warning color, placed immediately under the header summary
- All ticket keys and Snyk links should be rendered as clickable hyperlinks using Adaptive Card `Action.OpenUrl` or inline markdown link syntax (`[PSUP-1042](url)`)

### Minimal Failure Alert Card

Sent immediately when any phase fails, before the script exits.

```
🚨 Snyk Automation Failed
Phase: {phase_name}
Time: {timestamp}
Error: {error_message}
Action required: Manual Snyk → Jira reconciliation needed.
```

This card must be sendable with minimal dependencies — it should not depend on any data fetched by other phases. Keep the failure alert logic in a standalone function with no imports from other phase modules.

---

## 15. Error Handling & Reliability

### Retry Strategy

All external API calls (Snyk, Jira, Teams, S3) are wrapped with an exponential backoff retry decorator.

```python
# utils/retry.py
def with_retry(func, max_attempts=MAX_RETRY_ATTEMPTS, base_delay=RETRY_BASE_DELAY_SECONDS):
    for attempt in range(max_attempts):
        try:
            return func()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", base_delay * (2 ** attempt)))
                log(f"Rate limited. Waiting {retry_after}s before retry {attempt+1}")
                time.sleep(retry_after)
            elif e.response.status_code >= 500:
                wait = base_delay * (2 ** attempt)
                log(f"Server error {e.response.status_code}. Waiting {wait}s before retry {attempt+1}")
                time.sleep(wait)
            else:
                raise  # 4xx client errors (except 429) are not retried
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            wait = base_delay * (2 ** attempt)
            log(f"Connection error. Waiting {wait}s before retry {attempt+1}")
            time.sleep(wait)
    raise RuntimeError(f"All {max_attempts} retry attempts exhausted for {func.__name__}")
```

### Phase Failure Behaviour

| Phase | On Failure |
|-------|------------|
| Phase 0 | Send Teams alert (unless Teams itself failed), exit code 1 |
| Phase 1 | Upload state with `run_status: "failed"`, send Teams alert, exit code 1 |
| Phase 2 (mid-loop) | Log which target failed, increment error count, continue to next target. After loop, if error count > 0: report in Teams card as "N targets failed to process — see logs" |
| Phase 3 | Log error, attempt one retry, then exit code 1 with console log |

### Partial Run Detection

At the end of Phase 2:
```python
if processed_count < total_count:
    failed_count = total_count - processed_count
    log(f"WARNING: Partial run — only {processed_count}/{total_count} targets processed")
    # This will surface in the Teams card as a warning block
```

### Idempotency on Re-run

If the script is re-run on the same calendar day (e.g., after a Phase 2 failure):
- `created_today` flags from the earlier partial run are preserved in S3 state.
- Targets that were already processed (ticket created or updated) are skipped.
- Processing resumes effectively from where it left off.
- The Teams card at the end reflects the combined results of both run attempts.

---

## 16. Rate Limit Strategy

### Snyk REST API

- **Limit**: ~1,620 requests per minute per token.
- **Our usage**: ~3–6 paginated calls for projects + ~3–6 for targets = ~10 calls total.
- **Risk**: None under normal operation. Risk appears only if someone changes the code to fetch per-target individually.
- **Implementation**: Always use the paginated list endpoints, never loop-and-fetch per target.

### Jira Cloud API

- **Limit**: Points-based (token bucket). ~100,000 points/hour. Each search = ~1 point, each write = ~1 point.
- **Our usage**: ~240 search calls (one per target) + N create/update calls + 1 reverse JQL query.
  Estimated: ~300 total calls per run = well within limits.
- **Optimisation rule**: Always specify `fields=` in every Jira request to fetch only what you need. Never fetch full issue bodies. This reduces point cost per call.
- **On 429**: Read the `Retry-After` header and wait exactly that duration before retry.

### Teams Incoming Webhook

- **Limit**: 4 requests per second per channel.
- **Our usage**: 1 card per run (or 3–4 split cards in the large-payload case).
- **Implementation**: Add `time.sleep(0.5)` between split card sends.

---

## 17. Logging

**File**: `utils/logger.py`

Each run writes a dated log file to `logs/YYYY-MM-DD.log`.

### Log Format

```
2026-04-22 19:30:00 IST [INFO ] Phase 0 — Startup validation started
2026-04-22 19:30:01 IST [INFO ] Snyk API: OK
2026-04-22 19:30:01 IST [INFO ] Jira API: OK
2026-04-22 19:30:01 IST [INFO ] Jira custom fields: all 4 confirmed
2026-04-22 19:30:02 IST [INFO ] Teams webhook: OK
2026-04-22 19:30:02 IST [INFO ] S3 bucket: OK
2026-04-22 19:30:02 IST [INFO ] Phase 0 — Validation passed
2026-04-22 19:30:02 IST [INFO ] Phase 1 — Starting data collection
2026-04-22 19:30:03 IST [INFO ] Fetched 247 projects across 3 pages
2026-04-22 19:30:04 IST [INFO ] Grouped into 62 targets. 59 have C/H vulns.
2026-04-22 19:30:04 IST [INFO ] Phase 1 — Complete. total_count=59. State uploaded to S3.
2026-04-22 19:30:04 IST [INFO ] Phase 2 — Forward check started
2026-04-22 19:30:05 IST [INFO ] [smartsense4/jolt-php7-apache] NO ticket found → creating PSUP-1042
2026-04-22 19:30:06 IST [INFO ] [smartsense4/jolt-node-app] Ticket PSUP-1055 — SAME counts C4H12 → skip
2026-04-22 19:30:07 IST [INFO ] [smartsense4/jolt-redis] Ticket PSUP-1060 — CHANGED C2H5→C4H5 → updating fields
2026-04-22 19:30:30 IST [INFO ] Phase 2 forward check — complete. created=3 updated=11 skipped=45
2026-04-22 19:30:31 IST [INFO ] Phase 2 — Reverse check started
2026-04-22 19:30:32 IST [INFO ] Fetched 61 open snyk-jolt tickets from Jira
2026-04-22 19:30:32 IST [INFO ] [smartsense4/jolt-old-service] PSUP-998 — flagged: vulns_resolved
2026-04-22 19:30:33 IST [INFO ] Phase 2 reverse check — complete. flagged=2
2026-04-22 19:30:33 IST [INFO ] Phase 3 — Building Teams card
2026-04-22 19:30:33 IST [INFO ] Card size: 8.4 KB — within limit, sending single card
2026-04-22 19:30:34 IST [INFO ] Teams notification sent successfully
2026-04-22 19:30:34 IST [INFO ] State finalised. run_status=complete. Uploaded to S3.
2026-04-22 19:30:34 IST [INFO ] ✓ Run complete. Processed 59/59 targets.
```

Log files are gitignored. In the Argo Workflow, stdout logs are captured by the workflow engine.

---

## 18. Argo Workflows Integration

The script is run as a single container step in an Argo Workflow.

### Container Requirements

- Python 3.11+ base image.
- Dependencies installed from `requirements.txt`.
- AWS credentials injected via Argo's `secretKeyRef` (pointing to AWS Secrets Manager values).
- All env vars injected via Argo workflow environment configuration.

### Cron Schedule

```yaml
schedule: "0 14 * * *"   # 14:00 UTC = 19:30 IST
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Complete success |
| 1 | Validation failure or phase abort (alert already sent to Teams) |
| 2 | Partial success (processed_count < total_count — warning in Teams card) |

---

## 19. Non-Goals (Deferred for Future Phases)

The following are explicitly **out of scope for this MVP** and should not be implemented now:

| Feature | Reason Deferred |
|---------|----------------|
| Auto-update Jira ticket summary and description | Being cautious — team wants to verify automation behaviour first before it touches existing tickets |
| Dry-run mode (`--dry-run` flag) | Nice to have, low priority for MVP |
| Snyk webhook (real-time trigger) | Team explicitly does not need real-time — daily batch is sufficient |
| Repo rename detection | Snyk target ID is the primary key, so renames don't cause duplicates. Display name drift is acceptable for MVP. |
| State schema version migration | Schema is locked at v1. No migration needed until schema changes. |
| Run watchdog (alert if job didn't run) | Team monitoring Argo directly |
| Metric dashboards / alerting | Post-MVP observability layer |
| Multi-org Snyk support | Single org for now |

---

*End of MVP Specification — v1.0*

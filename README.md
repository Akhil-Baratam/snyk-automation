# Snyk → Jira → Teams Automation

Daily batch job that replaces the manual workflow of checking Snyk for repos
with Critical/High vulnerabilities, opening/updating Jira tickets on the PSUP
board, and posting a Teams summary.

**Snyk is the source of truth.** The script reads Snyk, reflects its state in
Jira, and posts one consolidated notification per run. It never closes Jira
tickets — closure stays manual.

For the full design spec (data model, ticket formats, rate limits, ADF schema,
etc.) see [snyk_jira_automation_mvp.md](snyk_jira_automation_mvp.md).

---

## The pipeline

| Phase | What it does |
|-------|--------------|
| **0** | Startup validation — Snyk / Jira / Teams reachability checks |
| **1** | Fetch all targets from Snyk, aggregate Critical/High counts per repo |
| **2** | Forward sync — create new Jira tickets, update counts on existing ones |
| **3** | Reverse check — flag open tickets whose Snyk target now has 0 C/H vulns |
| **4** | Send the Teams Adaptive Card |

Each phase is independent. You can run any subset.

---

## Running it

```bash
python main.py                              # full pipeline (phases 0-4)
python main.py --phase 0,1,3,4              # skip Phase 2 — useful for manual checks
python main.py --phase 0,1,3 --dry-run      # full audit, no Jira/Teams writes
python main.py --phase 1,3 --use-cache      # reuse last Phase 1 snapshot, no Snyk calls
```

### Flags

| Flag | Purpose |
|------|---------|
| `--phase` | Range (`0-4`) or set (`0,1,3,4`). Default: `0-4` |
| `--dry-run` | Preview Phase 2/3/4 without writing to Jira or Teams |
| `--use-cache` | Phase 1 reuses `logs/phase1_cache.json` instead of calling Snyk |

`--use-cache` is for fast re-runs within the same day. The cache is written
after every fresh Phase 1, so you always have a recent snapshot on disk.

---

## Helper scripts

| Script | Purpose |
|--------|---------|
| `python dump_targets.py` | Dumps every Snyk target's repo name + UUID + ticket token to `logs/targets_mapping.tsv` |
| `python migrate_summaries.py <PSUP-XXXX> ...` | Backfills the `[snyk:<token>]` token into older tickets' summaries |
| `python resend_notification.py` | Replays a past Teams notification (dry-run by default) |

---

## Files of interest

- `.env` — Snyk / Jira / GitLab / Teams credentials (not committed)
- `logs/` — dated run logs, Phase 1 cache, Phase 1 summary, Phase 2 idempotency cache
- `phases/` — one file per pipeline phase
- `clients/` — thin API wrappers (Snyk, Jira, GitLab, Teams)

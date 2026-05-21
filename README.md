This is snyk-jira-automation project

python main.py --phase 0,1,3 --dry-run    # validate + Snyk + reverse, no Jira writes, no Teams
python main.py --phase 0,1,3              # same but real (Phase 3 is read-only anyway)
python main.py --phase 1,3                # skip validation too
python main.py --phase 0-4                # original full pipeline (unchanged)
python main.py --phase 0,2-4              # full pipeline minus reverse check

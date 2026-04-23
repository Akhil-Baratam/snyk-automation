import json
import requests

TOKEN = "snyk_uat.1fcad39e.eyJlIjoxNzgzNTA5MDY3LCJoIjoic255ay5pbyIsImoiOiJBWjF4LWR3YUpDcmg2SjdBZTZaRndRIiwicyI6InR5cDNtbHFQUUItWkxzRGZVR080ZGciLCJ0aWQiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBIn0.IdSb1iV4LAaivoFxuq5GD29tmSo5ad3QVyCyN-JdTmPGIvWRMnoGDPcSDOhQMbU39hasHgTS5HP9e0NG3OjyBg"
ORG_ID = "7ebd3741-8fc3-4bd2-84ac-c087e3253ad8"
BASE_URL = f"https://api.snyk.io/rest/orgs/{ORG_ID}/targets"

headers = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.api+json",
}

all_targets = []
url = BASE_URL
params = {"version": "2026-03-25", "limit": 100}

page = 1
while url:
    print(f"Fetching page {page} — {url}")
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    targets = data.get("data", [])
    all_targets.extend(targets)
    print(f"  Got {len(targets)} targets (total so far: {len(all_targets)})")

    # Follow next link if present
    next_link = data.get("links", {}).get("next")
    if next_link:
        # next link is a relative path — prepend base
        url = f"https://api.snyk.io{next_link}" if next_link.startswith("/") else next_link
        params = {}  # params are already encoded in the next URL
    else:
        url = None
    page += 1

print(f"\nTotal targets fetched: {len(all_targets)}")

output = {"total": len(all_targets), "data": all_targets}
with open("targetsbyorg.json", "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

print("Saved to targetsbyorg.json")

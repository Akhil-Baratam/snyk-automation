import json
import requests
import os

TOKEN = os.getenv("SNYK_API_TOKEN")
ORG_ID = "7ebd3741-8fc3-4bd2-84ac-c087e3253ad8"
BASE_URL = f"https://api.snyk.io/rest/orgs/{ORG_ID}/projects"

if not TOKEN:
    print("Error: SNYK_API_TOKEN environment variable not set.")
    exit(1)

headers = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.api+json",
}

all_projects = []
url = BASE_URL
params = {
    "version": "2024-10-15",
    "limit": 100,
    "target_id": "78be7800-8200-489c-8bd7-140ecfcc29da"
}

page = 1
while url:
    print(f"Fetching page {page} — {url}")
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        projects = data.get("data", [])
        all_projects.extend(projects)
        print(f"  Got {len(projects)} projects (total so far: {len(all_projects)})")

        # Follow next link if present
        next_link = data.get("links", {}).get("next")
        if next_link:
            # next link can be relative or absolute from Snyk
            if next_link.startswith("http"):
                url = next_link
            else:
                url = f"https://api.snyk.io{next_link}"
            params = {}  # params are already encoded in the next URL
        else:
            url = None
        page += 1
    except Exception as e:
        print(f"Error during fetch: {e}")
        break

print(f"\nTotal projects fetched: {len(all_projects)}")

output = {
    "total": len(all_projects),
    "data": all_projects,
    "jsonapi": {"version": "1.0"}
}

with open("snyk_projects.json", "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)

print("Saved to snyk_projects.json")

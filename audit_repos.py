import requests
import csv
import os
from datetime import datetime

# ========== CONFIG ==========
GITHUB_TOKEN = os.getenv("GH_PAT")          # GitHub Token from secret
ORG_NAME = os.getenv("GITHUB_ACTOR")        # Automatically sets to your GitHub username
IS_ORG = False                              # Your account is a user, not org
REPORT_FILE = 'github-audit-report.csv'
# ============================

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

base_url = f"https://api.github.com/users/{ORG_NAME}/repos"
params = {"per_page": 100}

repos = []
while base_url:
    response = requests.get(base_url, headers=headers, params=params)
    response.raise_for_status()
    repos.extend(response.json())
    base_url = response.links.get('next', {}).get('url')

report = []

for repo in repos:
    name = repo['name']
    default_branch = repo['default_branch']
    is_lowercase = name.islower()
    starts_with_platsup = name.startswith('platsup')

    sec_scan_url = f"https://api.github.com/repos/{ORG_NAME}/{name}/security-and-analysis"
    sec_resp = requests.get(sec_scan_url, headers=headers)

    if sec_resp.status_code == 200:
        sec_data = sec_resp.json()
        secret_scanning_enabled = sec_data.get("secret_scanning", {}).get("status") == "enabled"
        push_protection_enabled = sec_data.get("secret_scanning_push_protection", {}).get("status") == "enabled"
    else:
        secret_scanning_enabled = False
        push_protection_enabled = False

    report.append({
        "Repo": name,
        "Default Branch is 'main'": default_branch == "main",
        "Name Lowercase": is_lowercase,
        "Starts with 'platsup'": starts_with_platsup,
        "Secret Scanning ON": secret_scanning_enabled,
        "Push Protection ON": push_protection_enabled
    })

# Save report
with open(REPORT_FILE, 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=report[0].keys())
    writer.writeheader()
    writer.writerows(report)

print(f"✅ Report written to {REPORT_FILE}")

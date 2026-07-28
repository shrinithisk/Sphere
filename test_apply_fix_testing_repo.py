import os
import json
import httpx

# Test parsing repo url
repo_url = "https://github.com/shrinithisk/testing"
url_clean = repo_url.rstrip("/")
parts = url_clean.split("github.com/")[-1].split("/")
owner = parts[0]
repo = parts[1].replace(".git", "")

print(f"Owner: {owner}, Repo: {repo}")

# Test sample findings for requirements.txt in testing repo
findings = [
    {
        "file": "requirements.txt",
        "package": "flask",
        "original_block": "flask==0.12.2",
        "patched_block": "flask==1.0.2"
    },
    {
        "file": "Dockerfile",
        "code_snippet": "FROM python:3.9-slim",
        "fix_suggestion": "FROM python:3.9-slim\nUSER appuser"
    }
]

for idx, finding in enumerate(findings):
    file_path = finding.get("file")
    original_block = finding.get("original_block") or finding.get("code_snippet")
    patched_block = finding.get("patched_block") or finding.get("fix_suggestion")
    print(f"Finding {idx}: file={file_path}, orig={original_block!r}, patch={patched_block!r}")

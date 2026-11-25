import asyncio
import os
import re
from typing import Dict, Any, Optional
from app.scanners.gitleaks_wrapper import run_gitleaks, is_gitleaks_available
from app.scanners.hadolint_wrapper import run_hadolint, is_hadolint_available
from app.scanners.actionlint_wrapper import run_actionlint, is_actionlint_available
from app.scanners.semgrep_wrapper import run_semgrep, is_semgrep_available
from app.scanners.osv_wrapper import scan_dependencies
from app.planner.deduper import deduplicate_and_group

def get_scanners_status():
    return {
        "gitleaks": is_gitleaks_available(),
        "hadolint": is_hadolint_available(),
        "actionlint": is_actionlint_available(),
        "semgrep": is_semgrep_available(),
        "osv": True # Always active (uses python parsing + free API)
    }

def extract_line_content(repo_path, relative_file_path, line_number):
    try:
        # Resolve absolute path safely and check bounds
        abs_path = os.path.abspath(os.path.join(repo_path, relative_file_path))
        if not abs_path.startswith(os.path.abspath(repo_path)):
            return None
        if os.path.exists(abs_path) and os.path.isfile(abs_path):
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                if 0 < line_number <= len(lines):
                    return lines[line_number - 1].strip()
    except Exception as e:
        print(f"Error extracting line snippet: {e}")
    return None

# Active Scanner Status & Percentage Tracking State (Per-Session + Global Fallback)
_scan_status_store: Dict[str, Dict[str, Any]] = {}
_latest_status = {"status": "Idle", "percentage": 0}

def get_current_status(session_id: Optional[str] = None):
    if session_id:
        if session_id in _scan_status_store:
            return _scan_status_store[session_id].get("status", "Idle")
        return "Idle"
    return _latest_status.get("status", "Idle")

def get_current_percentage(session_id: Optional[str] = None):
    if session_id:
        if session_id in _scan_status_store:
            return _scan_status_store[session_id].get("percentage", 0)
        return 0
    return _latest_status.get("percentage", 0)

def set_current_status(status: str, percentage: int = 0, session_id: Optional[str] = None):
    global _latest_status
    _latest_status = {"status": status, "percentage": percentage}
    if session_id:
        _scan_status_store[session_id] = {"status": status, "percentage": percentage}

def cleanup_scan_status(session_id: Optional[str] = None):
    """Requirement A5: Clean up per-scan status entries when scan finishes."""
    if session_id:
        _scan_status_store.pop(session_id, None)

def mask_credentials_in_text(text: str) -> str:
    if not text:
        return text
    # Mask private keys
    text = re.sub(
        r'-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----\s*[\s\S]+?\s*-----END[ A-Z0-9_-]+PRIVATE KEY-----',
        '-----BEGIN PRIVATE KEY-----\n****************************************\n-----END PRIVATE KEY-----',
        text
    )
    # Mask GitHub Personal Access Tokens
    text = re.sub(
        r'(ghp_[a-zA-Z0-9_]{4})[a-zA-Z0-9_]{20,255}',
        r'\1************************',
        text
    )
    # Mask AWS Access Keys
    text = re.sub(
        r'(AKIA[0-9A-Z]{4})[0-9A-Z]{12}',
        r'\1************',
        text
    )
    # Mask Slack webhook URLs
    text = re.sub(
        r'(https://hooks\.slack\.com/services/T[A-Z0-9_]+/B[A-Z0-9_]+/)[a-zA-Z0-9_]+',
        r'\1************************',
        text
    )
    # Mask raw variable assignments in code snippets
    keywords = r'(password|passwd|secret|token|api_key|apikey|access_key|private_key|key|pwd)'
    text = re.sub(
        rf'({keywords}\s*[:=]\s*")[^"]{{8,}}(")',
        r'\1********\2',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        rf"({keywords}\s*[:=]\s*')[^']{{8,}}(')",
        r"\1********\2",
        text,
        flags=re.IGNORECASE
    )
    return text

async def run_all_scans(repo_path: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    print(f"Starting aggregate scan on: {repo_path} (session={session_id})")
    
    loop = asyncio.get_event_loop()
    
    set_current_status("Gitleaks: Auditing Git commit history and files for leaked secrets...", 20, session_id)
    print("Executing Gitleaks scan...")
    gitleaks_res = await loop.run_in_executor(None, run_gitleaks, repo_path)
    
    set_current_status("Hadolint: Verifying Dockerfile container base image instructions...", 30, session_id)
    print("Executing Hadolint scan...")
    hadolint_res = await loop.run_in_executor(None, run_hadolint, repo_path)
    
    set_current_status("Actionlint: Validating GitHub Actions workflows in .github/workflows/...", 40, session_id)
    print("Executing Actionlint scan...")
    actionlint_res = await loop.run_in_executor(None, run_actionlint, repo_path)
    
    set_current_status("Semgrep: Analyzing Python/JS code modules for application vulnerabilities...", 50, session_id)
    print("Executing Semgrep scan...")
    semgrep_res = await loop.run_in_executor(None, run_semgrep, repo_path)
    
    set_current_status("OSV Scanner: Auditing external package dependencies and lockfiles...", 60, session_id)
    print("Executing OSV dependency scan...")
    osv_res_tuple = await scan_dependencies(repo_path)
    
    osv_findings, osv_deps = osv_res_tuple
    
    raw_findings = []
    raw_findings.extend(gitleaks_res)
    raw_findings.extend(hadolint_res)
    raw_findings.extend(actionlint_res)
    raw_findings.extend(semgrep_res)
    raw_findings.extend(osv_findings)
    
    # Extract code snippets where applicable
    for f in raw_findings:
        file_path = f.get("file", "")
        line_num = f.get("line")
        if file_path and line_num is not None:
            snippet = extract_line_content(repo_path, file_path, int(line_num))
            if snippet:
                f["code_snippet"] = snippet
                
        # Path normalization
        if f.get("file"):
            raw_f = str(f["file"]).strip().replace("\\", "/")
            f["file"] = re.sub(r'^(?:\.\./|\./|/)+', '', raw_f)
            
        for field in ["description", "code_snippet", "original_block", "patched_block"]:
            if f.get(field):
                f[field] = mask_credentials_in_text(f[field])

    # Run unified normalization, multi-CVE grouping, and deduplication
    deduped_unified, score_metrics = deduplicate_and_group(raw_findings)
    
    # Convert UnifiedFinding models to dictionaries for backwards compatibility
    findings_dicts = [f.model_dump() for f in deduped_unified]
    
    print(f"Aggregation complete. Found {len(findings_dicts)} unique findings (Repo score: {score_metrics['repo_score']}).")
    return {
        "findings": findings_dicts,
        "unified_findings": deduped_unified,
        "score_metrics": score_metrics,
        "dependencies": osv_deps
    }

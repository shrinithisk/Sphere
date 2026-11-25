import os
import subprocess
import json
import shutil
import tempfile

def is_gitleaks_available():
    return shutil.which("gitleaks") is not None

def run_gitleaks(repo_path):
    findings = []
    
    if not is_gitleaks_available():
        print("Gitleaks binary not found on local path. Skipping secret scan.")
        return findings
        
    # Set up a temporary file for the report
    fd, report_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    try:
        has_git = os.path.isdir(os.path.join(repo_path, ".git"))
        
        # Requirement A3: Run gitleaks with --redact to ensure raw secret values are never in report
        cmd = ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--report-path", report_path, "--redact"]
        if not has_git:
            cmd.append("--no-git")
            
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        
        # If report file is non-empty, leaks were found
        if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
            with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_findings = json.load(f)
                for leak in raw_findings:
                    file_val = leak.get("File", "")
                    relative_path = os.path.relpath(file_val, repo_path) if file_val and repo_path in file_val else file_val
                    
                    commit_sha = leak.get("Commit")
                    rule_id = leak.get("RuleID", "credential")
                    
                    # Requirement A2: Secrets in Git history reported as "found in commit X, rotate"
                    is_history = bool(commit_sha and not str(commit_sha).startswith("0000000"))
                    if is_history:
                        short_commit = str(commit_sha)[:7]
                        desc = f"Potential leak of {rule_id} found in commit {short_commit}. Secret rotation required immediately; removing from code does not remove it from Git history."
                        fix_sugg = f"Secret found in commit {short_commit}. Revoke and rotate this credential immediately at its provider. Scrub Git history with git-filter-repo."
                    else:
                        desc = f"Potential leak of {rule_id} (Secret: [REDACTED])"
                        fix_sugg = "Revoke the exposed token/key immediately, delete it from file configuration, and rotate credentials at provider."

                    findings.append({
                        "id": f"leak-{rule_id}-{relative_path}-{leak.get('StartLine', 1)}",
                        "rule_id": rule_id,
                        "cve": "N/A",
                        "tool": "gitleaks",
                        "type": "Hardcoded Secret",
                        "severity": "Critical",
                        "file": relative_path,
                        "line": leak.get("StartLine", 1),
                        "commit": str(commit_sha) if commit_sha else None,
                        "is_history_leak": is_history,
                        "description": desc,
                        "fix_suggestion": fix_sugg
                    })
    except Exception as e:
        print(f"Error executing Gitleaks: {e}")
    finally:
        # Clean up temp report file
        if os.path.exists(report_path):
            os.remove(report_path)
            
    return findings

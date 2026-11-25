import os
import shutil
import zipfile
import uuid
import json
import re
import time
import asyncio
from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form, Header, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import git

from app.database import init_db, get_db_connection
from app.auth import get_password_hash, verify_password, create_access_token, verify_token
from app.scanners.aggregator import get_scanners_status, get_current_status, get_current_percentage, cleanup_scan_status
from app.orchestrator import run_security_pipeline, get_llm, get_chatbot_llm
from app.security import validate_github_url, extract_zip_safely, mask_pat
from app.planner.planner import create_fix_plan
from app.planner.schema import normalize_finding, UnifiedFinding
from app.verifier.runner import run_verification_loop, PER_SCAN_TIMEOUT_SECONDS, VerificationCancelToken
from app.pr_builder.publisher import publish_verified_fixes_to_github
from app.pr_builder.github_client import GitHubClient

app = FastAPI(title="Sphere API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*", "X-GitHub-Token", "Authorization", "Content-Type"],
)

# Base Paths
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLONES_DIR = os.path.join(BACKEND_DIR, "temp_clones")
UPLOADS_DIR = os.path.join(BACKEND_DIR, "temp_uploads")

os.makedirs(CLONES_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)


def cleanup_stale_running_jobs(db_path: Optional[str] = None):
    """
    Requirement 2: On startup, marks any stale RUNNING scan rows and verification jobs
    as FAILED (interrupted). Guarantees no orphaned RUNNING states if Render restarts mid-run.
    """
    try:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET status = 'FAILED (interrupted)' WHERE status = 'RUNNING'")
        cursor.execute("SELECT id, verification_json FROM scans WHERE verification_json LIKE '%\"status\": \"RUNNING\"%'")
        rows = cursor.fetchall()
        for r in rows:
            v_id = r["id"]
            try:
                v_data = json.loads(r["verification_json"])
                if v_data.get("status") == "RUNNING":
                    v_data["status"] = "FAILED (interrupted)"
                    v_data["verification_label"] = "UNVERIFIED"
                    v_data["message"] = "Verification interrupted by backend server restart."
                    cursor.execute("UPDATE scans SET verification_json = ? WHERE id = ?", (json.dumps(v_data), v_id))
            except Exception:
                pass
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: Failed to clean up stale running jobs: {e}")


def cleanup_expired_zip_archives(max_age_hours: int = 24):
    """
    Requirement 6: Cleans up uploaded and persistent ZIP archives older than retention period (default 24h).
    """
    if not os.path.exists(UPLOADS_DIR):
        return
    now = time.time()
    cutoff = now - (max_age_hours * 3600)
    try:
        for fname in os.listdir(UPLOADS_DIR):
            if fname.endswith(".zip"):
                fpath = os.path.join(UPLOADS_DIR, fname)
                try:
                    if os.path.isfile(fpath) and os.path.getmtime(fpath) < cutoff:
                        os.remove(fpath)
                except Exception as ex:
                    print(f"Warning: Could not remove expired zip {fpath}: {ex}")
    except Exception as e:
        print(f"Warning: Failed to clean up expired zip archives: {e}")


# Run DB migration and startup maintenance on startup
@app.on_event("startup")
def startup_event():
    init_db()
    cleanup_stale_running_jobs()
    cleanup_expired_zip_archives(24)

# Pydantic Schemas
class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ScanRequest(BaseModel):
    repo_url: str

class ChatRequest(BaseModel):
    question: str
    findings_context: List[dict]

# ================= AUTHENTICATION ROUTES =================

@app.post("/api/auth/register")
def register(user: UserRegister):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (user.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already registered")
        
    password_hash = get_password_hash(user.password)
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (user.username, password_hash))
    conn.commit()
    conn.close()
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
def login(user: UserLogin):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (user.username,))
    db_user = cursor.fetchone()
    conn.close()
    
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
        
    token = create_access_token(data={"sub": user.username, "user_id": db_user["id"]})
    return {"access_token": token, "token_type": "bearer", "username": user.username}

@app.get("/api/auth/me")
def me(current_user: dict = Depends(verify_token)):
    return current_user

# ================= SCANNER STATUS ROUTE =================

@app.get("/api/scanners/status")
def scanners_status():
    return get_scanners_status()

@app.get("/api/scans/active-status")
def active_scan_status(session_id: Optional[str] = None):
    return {
        "status": get_current_status(session_id),
        "percentage": get_current_percentage(session_id)
    }

# ================= CODE SCANNING ROUTES =================

@app.post("/api/scan/url")
async def scan_url(req: ScanRequest, current_user: dict = Depends(verify_token)):
    raw_url = req.repo_url.strip()
    try:
        repo_url = validate_github_url(raw_url)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Invalid GitHub repository URL: {str(ve)}")
        
    # Generate unique folder name & session ID
    session_id = str(uuid.uuid4())
    clone_path = os.path.join(CLONES_DIR, session_id)
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    
    try:
        print(f"Cloning repo: {repo_url} into {clone_path} (depth=50 for commit history scan)")
        # Requirement A8: Clone with GIT_TERMINAL_PROMPT=0 and no submodules
        clone_env = os.environ.copy()
        clone_env["GIT_TERMINAL_PROMPT"] = "0"
        cloned_repo = git.Repo.clone_from(
            repo_url,
            clone_path,
            depth=50,
            multi_options=["--no-recurse-submodules"],
            env=clone_env
        )
        scanned_commit_sha = cloned_repo.head.commit.hexsha
        
        # Execute LangGraph Pipeline
        result = await run_security_pipeline(clone_path, session_id=session_id)
        result["scanned_commit_sha"] = scanned_commit_sha
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (user_id, repo_url, repo_name, status, score, pipeline_score, report_json, commit_sha, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'github')
        """, (
            current_user["user_id"],
            repo_url,
            repo_name,
            "Completed",
            result["health_scores"]["repo_score"],
            result["health_scores"]["pipeline_score"],
            json.dumps(result),
            scanned_commit_sha
        ))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

        result["repo_name"] = repo_name
        result["repo_url"] = repo_url
        result["id"] = scan_id
        import datetime
        result["created_at"] = datetime.datetime.now().isoformat()
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        print(f"URL Scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Scanning failed: {str(e)}")
    finally:
        # Requirement A5: Clean up per-scan status entries
        cleanup_scan_status(session_id)
        # Clean up cloned files
        if os.path.exists(clone_path):
            shutil.rmtree(clone_path)

@app.post("/api/scan/zip")
async def scan_zip(file: UploadFile = File(...), current_user: dict = Depends(verify_token)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP format repositories are supported.")
        
    # Requirement 6: Enforce per-user ZIP quota (default 5 max) and prune expired uploads
    cleanup_expired_zip_archives(24)
    max_user_zips = int(os.getenv("MAX_USER_ZIPS", "5"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND source_type = 'zip'", (current_user["user_id"],))
    count_row = cursor.fetchone()
    if count_row and count_row["count"] >= max_user_zips:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail=f"User ZIP upload quota exceeded ({max_user_zips} max). Please delete older scans or wait 24h for expiration."
        )
    conn.close()

    session_id = str(uuid.uuid4())
    zip_path = os.path.join(UPLOADS_DIR, f"{session_id}.zip")
    extract_path = os.path.join(CLONES_DIR, session_id)
    repo_name = file.filename.replace(".zip", "")
    
    try:
        # Save upload to disk
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Extract files safely with Zip Slip & zip bomb defenses
        try:
            scan_target = extract_zip_safely(zip_path, extract_path)
        except Exception as ve:
            raise HTTPException(status_code=400, detail=f"ZIP validation error: {str(ve)}")
            
        # Execute LangGraph pipeline
        result = await run_security_pipeline(scan_target, session_id=session_id)
        
        # Save to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (user_id, repo_url, repo_name, status, score, pipeline_score, report_json, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'zip')
        """, (
            current_user["user_id"],
            "ZIP Upload: " + file.filename,
            repo_name,
            "Completed",
            result["health_scores"]["repo_score"],
            result["health_scores"]["pipeline_score"],
            json.dumps(result)
        ))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Requirement 4: Store persistent ZIP archive for /verify and /patch operations
        persistent_zip_path = os.path.join(UPLOADS_DIR, f"scan_{scan_id}.zip")
        try:
            shutil.copy2(zip_path, persistent_zip_path)
        except Exception as ze:
            print(f"Warning: Failed to persist scan zip archive: {ze}")

        result["repo_name"] = repo_name
        result["repo_url"] = "ZIP Upload: " + file.filename
        result["id"] = scan_id
        import datetime
        result["created_at"] = datetime.datetime.now().isoformat()
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        print(f"ZIP Scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Scanning failed: {str(e)}")
    finally:
        # Requirement A5: Clean up per-scan status entries
        cleanup_scan_status(session_id)
        # Clean up zip and extracted folders
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)

@app.get("/api/scans/history")
def get_history(current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, repo_url, repo_name, status, score, pipeline_score, created_at 
        FROM scans 
        WHERE user_id = ? 
        ORDER BY created_at DESC
    """, (current_user["user_id"],))
    scans = cursor.fetchall()
    conn.close()
    
    return [dict(scan) for scan in scans]

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT repo_name, repo_url, created_at, report_json FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")
        
    report = json.loads(row["report_json"])
    if "risk_assessment" in report and isinstance(report["risk_assessment"], dict):
        from app.orchestrator import format_field_to_markdown
        if "summary" in report["risk_assessment"]:
            report["risk_assessment"]["summary"] = format_field_to_markdown(report["risk_assessment"]["summary"])
        if "threat_scenario" in report["risk_assessment"]:
            report["risk_assessment"]["threat_scenario"] = format_field_to_markdown(report["risk_assessment"]["threat_scenario"])
            
    report["repo_name"] = row["repo_name"]
    report["repo_url"] = row["repo_url"]
    report["created_at"] = row["created_at"]
    report["id"] = scan_id
    return report

@app.get("/api/scans/{scan_id}/plan")
def get_scan_plan(scan_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT report_json FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()
    
    # Requirement A5: Strictly check scan ownership (return 404 if scan belongs to another user or does not exist)
    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")
        
    report = json.loads(row["report_json"])
    raw_findings = report.get("findings", [])
    unified_findings = [normalize_finding(f) for f in raw_findings]
    plan = create_fix_plan(unified_findings, baseline_status="STATIC-VERIFIED (tests not run)")
    return plan.model_dump()

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan report not found")

    # Clean up associated ZIP archive if it exists
    scan_zip_file = os.path.join(UPLOADS_DIR, f"scan_{scan_id}.zip")
    if os.path.exists(scan_zip_file):
        try:
            os.remove(scan_zip_file)
        except Exception:
            pass

    return {"message": "Scan report deleted successfully"}

@app.delete("/api/scans/clear-all")
def clear_all_scans(current_user: dict = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM scans WHERE user_id = ?", (current_user["user_id"],))
        conn.commit()
        
        # Physically delete temporary directories
        for folder in [CLONES_DIR, UPLOADS_DIR]:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    try:
                        if os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                        else:
                            os.remove(item_path)
                    except Exception as err:
                        print(f"Failed to delete {item_path}: {err}")
                        
        return {"message": "All scan history and temporary files cleared successfully!"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to clear scans: {str(e)}")
    finally:
        conn.close()

def extract_github_pat(
    x_github_token: Optional[str] = Header(None, alias="X-GitHub-Token"),
) -> Optional[str]:
    """
    Requirement 2: Use ONLY dedicated X-GitHub-Token header (never Authorization, which carries login JWT).
    """
    token_str = x_github_token if isinstance(x_github_token, str) else None
    if token_str and token_str.strip():
        return token_str.strip()
    return None

class ApplyFixRequest(BaseModel):
    finding_index: int

@app.post("/api/scans/{scan_id}/apply-fix")
def apply_fix(
    scan_id: int,
    request: ApplyFixRequest,
    x_github_token: Optional[str] = Header(None, alias="X-GitHub-Token"),
    current_user: dict = Depends(verify_token)
):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT repo_url, report_json FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    
    # Requirement 7: Strictly enforce ownership
    if not row:
        conn.close()
        raise HTTPException(
            status_code=404, 
            detail="Scan report not found in database. If the backend server restarted, please click 'Scan URL' to refresh your scan."
        )
        
    report_data = json.loads(row["report_json"])
    findings = report_data.get("findings", [])
    
    idx = request.finding_index
    if idx < 0 or idx >= len(findings):
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid finding index")
        
    # Mark finding as fixed
    findings[idx]["fixed"] = True
    
    # Recalculate score
    weights = {"Critical": 25, "High": 15, "Medium": 5, "Low": 1}
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f.get("fixed") is True:
            continue
        sev = f.get("severity", "Medium")
        if sev in severity_counts:
            severity_counts[sev] += 1
            
    deduction = sum(weights[k] * severity_counts[k] for k in weights)
    new_score = max(0, 100 - deduction)
    
    # Update report payload and scores
    report_data["findings"] = findings
    if "health_scores" in report_data:
        report_data["health_scores"]["repo_score"] = new_score
    else:
        report_data["health_scores"] = {"repo_score": new_score, "pipeline_score": 100}
        
    # Requirement 2: Extract GitHub PAT strictly from X-GitHub-Token header
    github_token = extract_github_pat(x_github_token)
    repo_url = row["repo_url"]
    
    if github_token and repo_url and "github.com" in repo_url:
        import base64
        import httpx
        import uuid
        try:
            url_clean = repo_url.rstrip("/")
            parts = url_clean.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace(".git", "")
                
                finding = findings[idx]
                raw_file_path = finding.get("file", "app.py") or "app.py"
                raw_file_path = str(raw_file_path).strip().replace("\\", "/")
                file_path = re.sub(r'^(?:\.\./|\./|/)+', '', raw_file_path)
                if repo and file_path.startswith(f"{repo}/"):
                    file_path = file_path[len(repo)+1:]
                findings[idx]["file"] = file_path

                package_name = finding.get("package", "dependency")
                
                # Retrieve original and patched code blocks
                original_block = finding.get("original_block")
                patched_block = finding.get("patched_block")
                
                if not original_block:
                    remediations = report_data.get("remediations", [])
                    clean_file_path = file_path.strip().lstrip("./").lstrip("/")
                    for rem in remediations:
                        rem_file = rem.get("file", "").strip().lstrip("./").lstrip("/")
                        if rem_file == clean_file_path or rem_file.endswith(clean_file_path) or clean_file_path.endswith(rem_file):
                            original_block = rem.get("original")
                            patched_block = rem.get("patched")
                            break
                            
                    if not original_block and finding.get("code_snippet"):
                        original_block = finding.get("code_snippet")
                        if finding.get("fix_suggestion"):
                            patched_block = finding.get("fix_suggestion")
                            
                    if not original_block:
                        original_block = finding.get("description", "vulnerability")
                        patched_block = finding.get("fix_suggestion", f"# Sphere Hardening Patch for {package_name}")

                    findings[idx]["original_block"] = original_block
                    findings[idx]["patched_block"] = patched_block
                    
                if file_path and original_block and patched_block:
                    print(f"Applying branch-based PR fix for {owner}/{repo}: {file_path}")
                    
                    headers = {
                        "Authorization": f"token {github_token}",
                        "Accept": "application/vnd.github.v3+json"
                    }
                    
                    with httpx.Client() as client:
                        # 1. Fetch Repository default branch
                        repo_info_url = f"https://api.github.com/repos/{owner}/{repo}"
                        repo_resp = client.get(repo_info_url, headers=headers, timeout=10.0)
                        if repo_resp.status_code != 200:
                            conn.close()
                            if repo_resp.status_code in (401, 403):
                                raise HTTPException(
                                    status_code=403,
                                    detail="Token Access Required: Your Personal Access Token requires 'Contents (Read and write)' and 'Pull Requests (Read and write)' permissions enabled on GitHub."
                                )
                            raise HTTPException(
                                status_code=400,
                                detail=f"Failed to fetch repository metadata ({repo_resp.status_code}). Check your PAT permissions."
                            )
                        default_branch = repo_resp.json().get("default_branch", "main")
                        
                        # 2. Get Ref of the default branch
                        ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{default_branch}"
                        ref_resp = client.get(ref_url, headers=headers, timeout=10.0)
                        if ref_resp.status_code != 200:
                            conn.close()
                            raise HTTPException(
                                status_code=400,
                                detail=f"Failed to fetch branch reference for {default_branch} ({ref_resp.status_code})."
                            )
                        base_sha = ref_resp.json().get("object", {}).get("sha")
                        
                        # 3. Create a unique feature branch name
                        rand_suffix = uuid.uuid4().hex[:6]
                        clean_pkg = re.sub(r'[^a-zA-Z0-9_\-]', '', package_name)
                        new_branch = f"secureflow/patch-{clean_pkg}-{rand_suffix}"
                        
                        # 4. Create new branch reference on GitHub
                        create_ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
                        ref_body = {
                            "ref": f"refs/heads/{new_branch}",
                            "sha": base_sha
                        }
                        create_ref_resp = client.post(create_ref_url, headers=headers, json=ref_body, timeout=10.0)
                        if create_ref_resp.status_code not in [200, 201]:
                            conn.close()
                            gh_msg = create_ref_resp.json().get("message", "")
                            if create_ref_resp.status_code == 403:
                                raise HTTPException(
                                    status_code=403,
                                    detail="Token Access Required: Your Personal Access Token requires 'Contents (Read and write)' and 'Pull Requests (Read and write)' permissions enabled on GitHub."
                                )
                            raise HTTPException(
                                status_code=400,
                                detail=f"Failed to create new feature branch ({create_ref_resp.status_code}: {gh_msg})."
                            )
                            
                        # 5. Fetch current file content on the newly created branch
                        github_api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={new_branch}"
                        get_resp = client.get(github_api_url, headers=headers, timeout=10.0)
                        if get_resp.status_code == 200:
                            file_meta = get_resp.json()
                            file_sha = file_meta.get("sha")
                            encoded_content = file_meta.get("content", "")
                            
                            current_content = base64.b64decode(encoded_content).decode("utf-8", errors="ignore")
                            
                            # Multi-stage resilient replacement
                            clean_orig = str(original_block).strip()
                            clean_patch = str(patched_block).strip()
                            
                            if original_block in current_content:
                                updated_content = current_content.replace(original_block, patched_block)
                            elif clean_orig in current_content:
                                updated_content = current_content.replace(clean_orig, clean_patch)
                            else:
                                # Fuzzy line-by-line matching for package names and code lines
                                lines = current_content.splitlines(True)
                                new_lines = []
                                replaced = False
                                for line in lines:
                                    if not replaced and package_name and package_name != "dependency" and package_name.lower() in line.lower():
                                        new_lines.append(clean_patch + ("\n" if not clean_patch.endswith("\n") else ""))
                                        replaced = True
                                    elif not replaced and clean_orig.lower() in line.lower():
                                        new_lines.append(clean_patch + ("\n" if not clean_patch.endswith("\n") else ""))
                                        replaced = True
                                    else:
                                        new_lines.append(line)
                                        
                                if replaced:
                                    updated_content = "".join(new_lines)
                                else:
                                    # Append patch if direct line match was not found
                                    updated_content = current_content.rstrip() + f"\n\n# Sphere Patch: {package_name}\n{clean_patch}\n"
                                    
                            if updated_content != current_content:
                                # 6. Commit the modified file to the new feature branch
                                put_body = {
                                    "message": f"Sphere: Automated code hardening patch for {os.path.basename(file_path)}",
                                    "content": base64.b64encode(updated_content.encode("utf-8")).decode("utf-8"),
                                    "sha": file_sha,
                                    "branch": new_branch
                                }
                                put_resp = client.put(f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}", headers=headers, json=put_body, timeout=10.0)
                                if put_resp.status_code not in [200, 201]:
                                    conn.close()
                                    raise HTTPException(
                                        status_code=400,
                                        detail=f"GitHub Commit failed to branch {new_branch} ({put_resp.status_code})."
                                    )
                                    
                                # 7. Create Pull Request from feature branch to default base branch
                                pulls_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
                                pr_body = {
                                    "title": f"Security Fix: Harden {package_name} in {os.path.basename(file_path)}",
                                    "head": new_branch,
                                    "base": default_branch,
                                    "body": f"### 🛡️ Sphere: Vulnerability Remediation PR\n\nThis Pull Request was automatically generated by **Sphere** to resolve security vulnerabilities detected in your codebase.\n\n#### 🩹 Fix Details:\n* **Target File**: `{file_path}`\n* **Hardened Package**: `{package_name}`\n* **Vulnerability Description**: {finding.get('description', 'N/A')}\n\n*Please review these changes, run your test suites, and merge when ready!*"
                                }
                                pr_resp = client.post(pulls_url, headers=headers, json=pr_body, timeout=10.0)
                                if pr_resp.status_code in [200, 201]:
                                    pr_url = pr_resp.json().get("html_url")
                                    findings[idx]["pr_url"] = pr_url
                                    findings[idx]["branch_name"] = new_branch
                                    print(f"PR Successfully created: {pr_url}")
                                else:
                                    print(f"GitHub PR creation failed ({pr_resp.status_code}). Using compare URL fallback.")
                                    pr_url = f"https://github.com/{owner}/{repo}/compare/{default_branch}...{new_branch}?expand=1"
                                    findings[idx]["pr_url"] = pr_url
                                    findings[idx]["branch_name"] = new_branch
                            else:
                                conn.close()
                                raise HTTPException(
                                    status_code=400,
                                    detail="No changes detected in file contents (replacement block did not match)."
                                )
                        else:
                            conn.close()
                            raise HTTPException(
                                status_code=400,
                                detail=f"Failed to fetch file from GitHub on branch {new_branch} ({get_resp.status_code})."
                            )
        except HTTPException:
            raise
        except Exception as ex:
            print(f"Failed to apply patch directly to GitHub: {ex}")
            conn.close()
            raise HTTPException(status_code=500, detail=f"Failed to apply patch directly to GitHub: {str(ex)}")
            
    updated_report_json = json.dumps(report_data)
    
    cursor.execute("""
        UPDATE scans 
        SET score = ?, report_json = ? 
        WHERE id = ? AND user_id = ?
    """, (new_score, updated_report_json, scan_id, current_user["user_id"]))
    
    conn.commit()
    conn.close()
    
    return report_data

class CommitWorkflowRequest(BaseModel):
    pass

@app.post("/api/scans/{scan_id}/commit-workflow")
def commit_workflow(
    scan_id: int,
    request: CommitWorkflowRequest,
    x_github_token: Optional[str] = Header(None, alias="X-GitHub-Token"),
    current_user: dict = Depends(verify_token)
):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT repo_url, report_json FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan report not found")
        
    repo_url = row["repo_url"]
    report_data = json.loads(row["report_json"])
    optimized_workflows = report_data.get("optimized_workflows", [])
    
    if not optimized_workflows:
        conn.close()
        raise HTTPException(status_code=400, detail="No secure workflow found in scan report data to commit.")
        
    # Get details of the first secure workflow
    workflow = optimized_workflows[0]
    filename = workflow.get("new_filename", "secure-pipeline.yml")
    content = workflow.get("content", "")
    
    if not content:
        conn.close()
        raise HTTPException(status_code=400, detail="Secure workflow content is empty.")
        
    github_token = extract_github_pat(x_github_token)
    if not repo_url or "github.com" not in repo_url:
        conn.close()
        raise HTTPException(status_code=400, detail="Direct commits are only supported for GitHub repository scans.")
        
    import base64
    import httpx
    
    try:
        url_clean = repo_url.rstrip("/")
        parts = url_clean.split("github.com/")[-1].split("/")
        if len(parts) >= 2:
            owner = parts[0]
            repo = parts[1].replace(".git", "")
            
            file_path = f".github/workflows/{filename}"
            github_api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
            headers = {
                "Authorization": f"token {github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            file_sha = None
            with httpx.Client() as client:
                # Check if the file already exists to get its blob SHA
                get_resp = client.get(github_api_url, headers=headers, timeout=10.0)
                if get_resp.status_code == 200:
                    file_meta = get_resp.json()
                    file_sha = file_meta.get("sha")
                
                # Base64 encode the new workflow content
                encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
                
                # Build commit payload
                put_body = {
                    "message": f"Sphere: Automated secure CI/CD pipeline deploy ({filename})",
                    "content": encoded_content
                }
                if file_sha:
                    put_body["sha"] = file_sha
                    
                # PUT request to commit/update
                put_resp = client.put(github_api_url, headers=headers, json=put_body, timeout=10.0)
                if put_resp.status_code in [200, 201]:
                    conn.close()
                    return {"status": "success", "message": f"Successfully committed secure workflow to .github/workflows/{filename}"}
                else:
                    conn.close()
                    raise HTTPException(
                        status_code=400,
                        detail=f"GitHub API returned error: {put_resp.status_code}. Make sure your PAT has repository write permissions."
                    )
        else:
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid GitHub repository URL structure.")
    except HTTPException:
        raise
    except Exception as ex:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Failed to commit workflow to GitHub: {str(ex)}")

# ================= M3: VERIFICATION & PR BUILDER ROUTES =================

_verification_tasks: Dict[int, Dict[str, Any]] = {}

def _execute_verification_in_worker(
    target_path: str,
    plan_obj: Any,
    deadline: Optional[float] = None,
    cancel_token: Optional[VerificationCancelToken] = None,
):
    """Executes the verification loop in a dedicated worker thread with cooperative deadline/cancel token."""
    return asyncio.run(
        run_verification_loop(
            target_path,
            plan_obj,
            deadline=deadline,
            cancel_token=cancel_token,
        )
    )

async def run_scan_verification_background(scan_id: int, scan_row: dict, user_id: int):
    session_id = str(uuid.uuid4())
    temp_dir = os.path.join(CLONES_DIR, f"verify_{session_id}")
    cancel_token = VerificationCancelToken()
    deadline = time.time() + PER_SCAN_TIMEOUT_SECONDS

    initial_status = {
        "status": "RUNNING",
        "verification_label": "UNVERIFIED",
        "total_applied": 0,
        "total_reverted": 0,
        "message": "Verification in progress...",
    }
    _verification_tasks[scan_id] = {
        **initial_status,
        "_cancel_token": cancel_token,
    }

    # Requirement 2: Persist job status in DB immediately
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scans SET verification_json = ? WHERE id = ? AND user_id = ?
        """, (json.dumps(initial_status), scan_id, user_id))
        conn.commit()
        conn.close()
    except Exception as dbe:
        print(f"Warning: Failed to persist initial verification status: {dbe}")

    try:
        report = json.loads(scan_row["report_json"])
        raw_findings = report.get("findings", [])
        unified_findings = [normalize_finding(f) for f in raw_findings]
        plan = create_fix_plan(unified_findings)

        repo_url = scan_row.get("repo_url", "")
        commit_sha = scan_row.get("commit_sha")
        source_type = scan_row.get("source_type") or ("zip" if repo_url.startswith("ZIP Upload:") else "github")

        # If it's a GitHub repo, clone pinned commit SHA
        if source_type == "github" and repo_url and "github.com" in repo_url:
            clone_env = os.environ.copy()
            clone_env["GIT_TERMINAL_PROMPT"] = "0"
            cloned = git.Repo.clone_from(
                repo_url,
                temp_dir,
                depth=50,
                multi_options=["--no-recurse-submodules"],
                env=clone_env
            )
            if commit_sha:
                try:
                    cloned.git.checkout(commit_sha)
                except Exception:
                    pass
            target_repo_path = temp_dir
        elif source_type == "zip":
            # Requirement 4: Extract source for ZIP scans from persistent scan archive
            persistent_zip = os.path.join(UPLOADS_DIR, f"scan_{scan_id}.zip")
            if os.path.isfile(persistent_zip):
                extract_zip_safely(persistent_zip, temp_dir)
            else:
                os.makedirs(temp_dir, exist_ok=True)
            target_repo_path = temp_dir
        else:
            os.makedirs(temp_dir, exist_ok=True)
            target_repo_path = temp_dir

        # Requirement 2: Run verification in asyncio.to_thread with deadline & cancel token
        result = await asyncio.wait_for(
            asyncio.to_thread(_execute_verification_in_worker, target_repo_path, plan, deadline, cancel_token),
            timeout=PER_SCAN_TIMEOUT_SECONDS,
        )

        # Worker protection: if token cancelled, do not write results
        if cancel_token.is_cancelled():
            return

        # Check DB status: if marked TIMEOUT while thread was running, do not overwrite
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT verification_json FROM scans WHERE id = ?", (scan_id,))
        curr_row = cursor.fetchone()
        if curr_row and curr_row["verification_json"]:
            try:
                curr_status = json.loads(curr_row["verification_json"]).get("status")
                if curr_status in ("TIMEOUT", "CANCELLED", "FAILED", "FAILED (interrupted)"):
                    conn.close()
                    return
            except Exception:
                pass

        res_status = result.status if isinstance(getattr(result, "status", None), str) else "COMPLETED"
        res_dict = {
            "status": res_status,
            "verification_label": result.verification_label,
            "total_applied": result.total_applied,
            "total_reverted": result.total_reverted,
            "commit_count": result.commit_count,
            "unified_diff": result.unified_diff,
            "applied_fixes": [f.model_dump() for f in result.applied_fixes],
            "reverted_fixes": [f.model_dump() for f in result.reverted_fixes],
            "manual_only_fixes": [f.model_dump() for f in result.manual_only_fixes],
            "major_bump_fixes": [f.model_dump() for f in result.major_bump_fixes],
            "logs": result.logs,
        }
        _verification_tasks[scan_id] = res_dict

        # Requirement 2: Persist completed result to database
        cursor.execute("""
            UPDATE scans SET verification_json = ? WHERE id = ? AND user_id = ?
        """, (json.dumps(res_dict), scan_id, user_id))
        conn.commit()
        conn.close()

    except asyncio.TimeoutError:
        cancel_token.cancel()
        fail_dict = {
            "status": "TIMEOUT",
            "verification_label": "UNVERIFIED",
            "message": f"Verification timed out after {PER_SCAN_TIMEOUT_SECONDS}s.",
        }
        _verification_tasks[scan_id] = fail_dict
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scans SET verification_json = ? WHERE id = ? AND user_id = ?
            """, (json.dumps(fail_dict), scan_id, user_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
    except Exception as e:
        fail_dict = {
            "status": "FAILED",
            "verification_label": "UNVERIFIED",
            "message": f"Verification failed: {str(e)}",
        }
        _verification_tasks[scan_id] = fail_dict
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE scans SET verification_json = ? WHERE id = ? AND user_id = ?
            """, (json.dumps(fail_dict), scan_id, user_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/scans/{scan_id}/verify")
async def trigger_verification(
    scan_id: int,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(verify_token),
):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, repo_url, repo_name, report_json, commit_sha, source_type FROM scans
        WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")

    scan_data = dict(row)
    curr_task = _verification_tasks.get(scan_id)
    if curr_task and curr_task.get("status") == "RUNNING":
        return {"status": "RUNNING", "scan_id": scan_id, "message": "Verification already in progress"}

    _verification_tasks[scan_id] = {"status": "RUNNING", "scan_id": scan_id}
    background_tasks.add_task(run_scan_verification_background, scan_id, scan_data, current_user["user_id"])
    return {"status": "RUNNING", "scan_id": scan_id, "message": "Verification background job started"}


@app.get("/api/scans/{scan_id}/verify/status")
def get_verification_status(
    scan_id: int,
    current_user: dict = Depends(verify_token),
):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, verification_json FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")

    if scan_id in _verification_tasks:
        return _verification_tasks[scan_id]

    if row["verification_json"]:
        return json.loads(row["verification_json"])

    return {
        "status": "IDLE",
        "verification_label": "UNVERIFIED",
        "total_applied": 0,
        "total_reverted": 0,
    }


@app.get("/api/scans/{scan_id}/patch")
def get_verification_patch(
    scan_id: int,
    current_user: dict = Depends(verify_token),
):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, repo_url, verification_json, source_type FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")

    diff = ""
    if scan_id in _verification_tasks:
        diff = _verification_tasks[scan_id].get("unified_diff", "")
    elif row["verification_json"]:
        data = json.loads(row["verification_json"])
        diff = data.get("unified_diff", "")

    if not diff:
        diff = "# Sphere: No verified automated patches available for this scan.\n"

    return Response(
        content=diff,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=sphere-scan-{scan_id}.patch"},
    )


@app.post("/api/scans/{scan_id}/publish-prs")
async def publish_pull_requests(
    scan_id: int,
    x_github_token: Optional[str] = Header(None, alias="X-GitHub-Token"),
    current_user: dict = Depends(verify_token),
):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, repo_url, repo_name, report_json, commit_sha, verification_json, source_type 
        FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")

    repo_url = row["repo_url"]
    source_type = dict(row).get("source_type") or ("zip" if repo_url.startswith("ZIP Upload:") else "github")
    # Requirement: ZIP scans cannot open PRs: return a downloadable patch/diff instead
    if source_type == "zip" or not repo_url or "github.com" not in repo_url:
        raise HTTPException(
            status_code=400,
            detail="ZIP scans cannot open Pull Requests. Download the verified patch/diff instead.",
        )

    pat = extract_github_pat(x_github_token)
    if not pat:
        raise HTTPException(
            status_code=400,
            detail="X-GitHub-Token header is required to open Pull Requests.",
        )

    # Fetch verified fixes
    v_data = _verification_tasks.get(scan_id)
    if not v_data and row["verification_json"]:
        v_data = json.loads(row["verification_json"])

    if not v_data or not v_data.get("applied_fixes"):
        raise HTTPException(
            status_code=400,
            detail="Scan fixes must be verified before publishing PRs. Please run verification first.",
        )

    verified_findings = [UnifiedFinding(**f) for f in v_data["applied_fixes"]]
    label = v_data.get("verification_label", "STATIC-VERIFIED (tests not run)")

    result = await publish_verified_fixes_to_github(
        repo_url=repo_url,
        verified_fixes=verified_findings,
        token=pat,
        scanned_commit_sha=row["commit_sha"],
        verification_label=label,
    )

    # Persist published PR records into verification_json for background CI tracking
    if result.get("pull_requests"):
        v_data["published_prs"] = result["pull_requests"]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE scans SET verification_json = ? WHERE id = ?", (json.dumps(v_data), scan_id))
        conn.commit()
        conn.close()

    return result


@app.post("/api/scans/{scan_id}/prs/refresh-ci")
async def refresh_prs_ci_status(
    scan_id: int,
    x_github_token: Optional[str] = Header(None, alias="X-GitHub-Token"),
    current_user: dict = Depends(verify_token),
):
    """
    Requirement 3: Background / on-demand CI refresh endpoint.
    Refreshes CI status for all published PRs in a scan:
    - Queries combined check-runs + commit status.
    - Zero checks never means passed.
    - A red baseline blocks auto-ready.
    - Major bumps and code patches always remain draft.
    - When CI passes, mutates PR ready for review via GraphQL.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, repo_url, repo_name, verification_json, source_type
        FROM scans WHERE id = ? AND user_id = ?
    """, (scan_id, current_user["user_id"]))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Scan report not found")

    pat = extract_github_pat(x_github_token)
    if not pat:
        raise HTTPException(status_code=400, detail="X-GitHub-Token header is required to refresh CI status.")

    v_json_str = row["verification_json"]
    v_data = json.loads(v_json_str) if v_json_str else {}
    published_prs = v_data.get("published_prs", [])
    if not published_prs:
        return {"status": "NO_PRS", "published_prs": [], "message": "No published PRs to refresh."}

    repo_url = row["repo_url"]
    clean_url = repo_url.rstrip("/").replace(".git", "")
    parts = clean_url.split("github.com/")[-1].split("/")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid GitHub repository URL.")
    owner, repo = parts[0], parts[1]

    client = GitHubClient(token=pat)
    default_branch = await client.get_default_branch(owner, repo)
    baseline_ci = await client.get_default_branch_ci_details(owner, repo, default_branch)
    baseline_red = (baseline_ci.get("status") == "FAILED")

    updated_prs = []
    for pr in published_prs:
        head_sha = pr.get("head_sha") or (pr.get("commits", [None])[-1] if pr.get("commits") else None)
        if not head_sha:
            updated_prs.append(pr)
            continue

        ci_res = await client.get_combined_ci_status(owner, repo, head_sha)
        pr["ci_status"] = ci_res

        # Conditions to mark ready:
        # 1. CI must be passing (all_passed is True)
        # 2. Total checks > 0 (zero checks cannot pass)
        # 3. Baseline CI is not red
        # 4. Not a major version bump PR
        # 5. Not a Semgrep/LLM code patch PR
        if (
            pr.get("draft", True)
            and ci_res.get("all_passed") is True
            and ci_res.get("total_count", 0) > 0
            and not baseline_red
            and not pr.get("is_major_pr", False)
            and not pr.get("is_code_pr", False)
        ):
            node_id = pr.get("pr_node_id")
            if node_id:
                try:
                    marked = await client.mark_pr_ready_for_review(node_id)
                    if marked:
                        pr["draft"] = False
                except Exception as me:
                    print(f"Warning: GraphQL mark ready failed: {me}")

        updated_prs.append(pr)

    v_data["published_prs"] = updated_prs
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans SET verification_json = ? WHERE id = ? AND user_id = ?
    """, (json.dumps(v_data), scan_id, current_user["user_id"]))
    conn.commit()
    conn.close()

    return {
        "status": "SUCCESS",
        "baseline_ci": baseline_ci,
        "baseline_red": baseline_red,
        "published_prs": updated_prs,
    }

# ================= INTERACTIVE CHAT ROUTE =================

def get_local_chatbot_response(question: str) -> str:
    q = question.lower()
    
    if "secret" in q or "leak" in q or "gitleaks" in q or "credential" in q:
        return (
            "🔒 **Git Secrets & Credential Leakage Prevention**\n\n"
            "Secrets leakage happens when sensitive tokens, API keys, or private keys are accidentally committed to Git history. "
            "Even if you delete the file in a later commit, the key remains visible in the repository's historical commits.\n\n"
            "**How to mitigate and prevent this:**\n"
            "1. **Rotate the Secret immediately**: Consider the leaked token compromised and generate a new one.\n"
            "2. **Purge Git History**: Use tools like `git filter-repo` or BFG Repo-Cleaner to completely remove the file from all historical commits.\n"
            "3. **Use .gitignore**: Always add configuration files containing keys to your `.gitignore`.\n"
            "4. **Integrate Gitleaks in CI/CD**: Add Gitleaks to your GitHub Actions workflows to block commits containing secrets before they are pushed."
        )
        
    elif "docker" in q or "hadolint" in q or "container" in q:
        return (
            "🐳 **Dockerfile Hardening & Security Best Practices**\n\n"
            "Insecure Dockerfiles can lead to container escape attacks, bloated image sizes, and privilege escalation vulnerabilities.\n\n"
            "**Key recommendations for hardening:**\n"
            "1. **Never run as root**: Always define a non-privileged user (e.g. `USER appuser`) at the end of your Dockerfile.\n"
            "2. **Pin Image Versions**: Avoid using mutable tags like `latest`. Use specific version tags or digests (e.g. `python:3.9-slim@sha256:...`).\n"
            "3. **Clean Cache Directories**: When running package managers, clear cache to reduce image size (e.g. `pip install --no-cache-dir` or `apt-get clean`).\n"
            "4. **Scan Base Images**: Use Hadolint to lint your Dockerfile structure and Trivy to scan your base image layers."
        )
        
    elif "action" in q or "workflow" in q or "github" in q or "ci/cd" in q or "actionlint" in q:
        return (
            "🚀 **GitHub Actions & CI/CD Pipeline Security**\n\n"
            "CI/CD pipelines have access to deployment environments, making them prime targets for supply-chain attacks.\n\n"
            "**Best practices for secure workflows:**\n"
            "1. **Pin Actions to SHA**: Instead of `uses: actions/checkout@v4`, pin to the commit hash: `uses: actions/checkout@1d96c772d19495a3b5c517cd2bc0cb401ea0529f`.\n"
            "2. **Restrict GITHUB_TOKEN Permissions**: Set top-level read-only permissions: `permissions: { contents: read }`.\n"
            "3. **Never output secrets**: Avoid using `echo` to print secrets in debug logs.\n"
            "4. **Use Actionlint**: Integrate Actionlint in your workspace to catch syntax errors and security flaws in actions YAML files."
        )
        
    elif "dependency" in q or "osv" in q or "sca" in q or "cve" in q or "package" in q:
        return (
            "📦 **Software Composition Analysis (SCA) & Dependency Auditing**\n\n"
            "Open-source packages often contain known vulnerabilities (CVEs) that attackers can exploit if your project runs outdated library versions.\n\n"
            "**How to manage dependency risks:**\n"
            "1. **Automate Scanning**: Use the Google OSV API or `pip-audit` / `npm audit` to check manifest files (`package.json`, `requirements.txt`).\n"
            "2. **Enable Dependabot**: Turn on GitHub Dependabot to receive automated pull requests for vulnerable packages.\n"
            "3. **Lock Package Versions**: Always commit lock files (like `package-lock.json` or `poetry.lock`) to ensure consistent builds.\n"
            "4. **Prune devDependencies**: Ensure production builds do not include developmental libraries."
        )
        
    elif "semgrep" in q or "sast" in q or "sql" in q or "injection" in q or "xss" in q:
        return (
            "🔍 **Static Application Security Testing (SAST) & Code Quality**\n\n"
            "SAST analyzes source code to identify patterns that match security flaws (like SQL injections, Cross-Site Scripting, or weak cryptography) before the app runs.\n\n"
            "**How to write secure code:**\n"
            "1. **Avoid Parameter Concatenation**: Never build SQL queries by joining strings (e.g. `execute(f'SELECT * FROM users WHERE name = {name}')`). Use parameterized queries.\n"
            "2. **Sanitize Inputs**: Validate and escape all user-supplied data before rendering it in HTML to prevent XSS.\n"
            "3. **Run Semgrep**: Integrate Semgrep rulesets into your pre-commit hooks to block insecure code from being committed."
        )
        
    # Default high-quality fallback
    return (
        "💡 **Sphere Security Assistant Support**\n\n"
        "Here are some critical security measures we recommend for your repository:\n"
        "* **Credential Hygiene**: Ensure no passwords or API keys are committed to Git history. Use environment variables instead.\n"
        "* **Docker Hardening**: Always specify a non-root `USER` and pin your base image tag using SHA digests.\n"
        "* **Workflow Security**: Set minimal permissions (`permissions: { contents: read }`) in your GitHub Actions YAML.\n"
        "* **Static Analysis**: Integrate Semgrep and Gitleaks into your CI/CD pipeline to automatically block vulnerabilities on every pull request.\n\n"
        "*Feel free to ask me questions specifically about Gitleaks, Hadolint, Actionlint, Semgrep, or OSV dependencies!*"
    )

@app.post("/api/chat")
async def chat(req: ChatRequest, current_user: dict = Depends(verify_token)):
    import asyncio
    import httpx
    
    prompt = f"""
    You are Sphere, an intelligent DevSecOps security assistant.
    The developer is asking a question about their code scan or CI/CD workflow security.
    
    Here is the context of current vulnerability findings:
    {json.dumps(req.findings_context, indent=2)}
    
    Developer Question: "{req.question}"
    
    Provide a clear, educational, and developer-friendly answer explaining security concepts, risks, and how to remediate them. Keep code snippets clean and concise.
    """
    
    # 1. Try Groq first if key is present (super-fast, high limit)
    groq_key = os.environ.get("GROQ_API_KEY")
    if groq_key:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {groq_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": [
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.7
                    },
                    timeout=12.0
                )
                if resp.status_code == 200:
                    result = resp.json()
                    return {"response": result["choices"][0]["message"]["content"]}
                else:
                    print(f"Groq API returned error status {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"Groq query failed: {e}")

    # 2. Fall back to Gemini if Groq is not set or fails
    llm = get_chatbot_llm()
    if llm:
        try:
            response = await asyncio.wait_for(llm.ainvoke(prompt), timeout=12.0)
            return {"response": response.content}
        except Exception as e:
            print(f"Gemini Chatbot query failed: {e}")

    # 3. Fall back to smart local knowledge base if all APIs fail
    return {"response": get_local_chatbot_response(req.question)}

if __name__ == "__main__":
    import uvicorn
    # Make sure DB is initialized
    init_db()
    # Start FastAPI
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)

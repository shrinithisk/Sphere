import os
import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient

from app.main import app, UPLOADS_DIR, run_scan_verification_background, _verification_tasks
from app.auth import create_access_token
from app.database import get_db_connection


@pytest.fixture
def auth_headers():
    token = create_access_token(data={"sub": "zipuser", "user_id": 501})
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_zip_scan_source_retention_and_verification_patch_flow(tmp_path, auth_headers):
    """
    Requirement 4: Explains and tests how /verify and /patch get the source for ZIP scans.
    Since the initial extracted directory is deleted in finally after scanning to save space,
    the uploaded ZIP archive is persisted under UPLOADS_DIR/scan_{id}.zip.
    When /verify is called, the background worker extracts this retained archive into
    an isolated temporary verification directory, runs the verification loop, records the
    verified diff in verification_json, and /patch serves the downloadable diff.
    """
    scan_id = 888
    user_id = 501

    # 1. Create a dummy in-memory zip file with an insecure app.py
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app.py", "DEBUG = True\nSECRET_KEY = 'insecure_dev_key'\n")
    zip_bytes = zip_buffer.getvalue()

    # Save to persistent UPLOADS_DIR/scan_{id}.zip
    persistent_zip_path = os.path.join(UPLOADS_DIR, f"scan_{scan_id}.zip")
    with open(persistent_zip_path, "wb") as f:
        f.write(zip_bytes)

    # 2. Insert scan row into database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    c.execute("""
        INSERT INTO scans (id, user_id, repo_url, repo_name, status, score, pipeline_score, report_json, commit_sha, verification_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        user_id,
        "ZIP Upload: test_project.zip",
        "test_project",
        "Completed",
        70,
        80,
        json.dumps({
            "findings": [
                {
                    "id": "SEMGREP-debug",
                    "tool": "semgrep",
                    "rule_id": "python.flask.debug-mode",
                    "file": "app.py",
                    "line": 1,
                    "severity": "High",
                    "description": "Flask debug mode enabled in production",
                    "code_snippet": "DEBUG = True",
                    "original_block": "DEBUG = True",
                    "patched_block": "DEBUG = False",
                    "suggested_fix": "Set DEBUG to False",
                }
            ]
        }),
        None,
        None,
    ))
    conn.commit()
    conn.close()

    try:
        # 3. Execute background verification worker for ZIP scan
        scan_row = {
            "id": scan_id,
            "user_id": user_id,
            "repo_url": "ZIP Upload: test_project.zip",
            "repo_name": "test_project",
            "commit_sha": None,
            "report_json": json.dumps({
                "findings": [
                    {
                        "id": "SEMGREP-debug",
                        "tool": "semgrep",
                        "rule_id": "python.flask.debug-mode",
                        "file": "app.py",
                        "line": 1,
                        "severity": "High",
                        "description": "Flask debug mode enabled in production",
                        "code_snippet": "DEBUG = True",
                        "original_block": "DEBUG = True",
                        "patched_block": "DEBUG = False",
                        "suggested_fix": "Set DEBUG to False",
                    }
                ]
            }),
        }

        await run_scan_verification_background(scan_id, scan_row, user_id)

        # 4. Verify in-memory task status and DB persistence
        assert scan_id in _verification_tasks
        task_res = _verification_tasks[scan_id]
        assert task_res["status"] == "COMPLETED"
        assert task_res["total_applied"] == 1
        assert "diff --git a/app.py b/app.py" in task_res["unified_diff"]
        assert "+DEBUG = False" in task_res["unified_diff"]

        # Check DB persistence
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT verification_json FROM scans WHERE id = ?", (scan_id,))
        row = c.fetchone()
        conn.close()
        db_res = json.loads(row["verification_json"])
        assert db_res["status"] == "COMPLETED"
        assert db_res["total_applied"] == 1

        # 5. Test GET /api/scans/{id}/patch endpoint returns downloadable diff
        client = TestClient(app)
        patch_resp = client.get(f"/api/scans/{scan_id}/patch", headers=auth_headers)
        assert patch_resp.status_code == 200
        assert patch_resp.headers["content-type"].startswith("text/plain")
        assert f"attachment; filename=sphere-scan-{scan_id}.patch" in patch_resp.headers["content-disposition"]
        assert "-DEBUG = True" in patch_resp.text
        assert "+DEBUG = False" in patch_resp.text

    finally:
        # Cleanup
        if os.path.exists(persistent_zip_path):
            os.remove(persistent_zip_path)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

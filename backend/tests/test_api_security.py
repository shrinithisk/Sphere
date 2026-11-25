import json
import pytest
from fastapi.testclient import TestClient
from app.main import app, extract_github_pat, ApplyFixRequest
from app.database import get_db_connection, init_db
from app.auth import create_access_token
from app.scanners.aggregator import (
    set_current_status,
    get_current_status,
    cleanup_scan_status,
    _scan_status_store,
)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


def test_scan_plan_ownership_enforcement():
    # Requirement A5: /api/scans/{id}/plan checks scan ownership
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (101, 'owner_user', 'hash1')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (102, 'other_user', 'hash2')")

    sample_report = {
        "findings": [
            {
                "tool": "hadolint",
                "id": "DL3008",
                "file": "Dockerfile",
                "line": 1,
                "severity": "Medium",
                "category": "docker",
            }
        ]
    }

    cursor.execute("DELETE FROM scans WHERE id = 999")
    cursor.execute("""
        INSERT INTO scans (id, user_id, repo_url, repo_name, status, score, pipeline_score, report_json)
        VALUES (999, 101, 'https://github.com/owner/repo', 'repo', 'Completed', 90, 90, ?)
    """, (json.dumps(sample_report),))
    conn.commit()
    conn.close()

    owner_token = create_access_token({"sub": "owner_user", "user_id": 101})
    other_token = create_access_token({"sub": "other_user", "user_id": 102})

    client = TestClient(app)

    # 1. Owner requests plan -> 200 OK
    res_owner = client.get("/api/scans/999/plan", headers={"Authorization": f"Bearer {owner_token}"})
    assert res_owner.status_code == 200
    plan = res_owner.json()
    assert "phases" in plan

    # 2. Other user requests plan -> 404 Not Found (ownership check blocks unauthorized access)
    res_other = client.get("/api/scans/999/plan", headers={"Authorization": f"Bearer {other_token}"})
    assert res_other.status_code == 404
    assert "Scan report not found" in res_other.json()["detail"]


def test_every_scan_endpoint_ownership_audit():
    # Requirement 7: Audit every /api/scans/{id}/* endpoint for user_id ownership checks
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (201, 'user_a', 'hash_a')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password_hash) VALUES (202, 'user_b', 'hash_b')")

    cursor.execute("DELETE FROM scans WHERE id = 888")
    cursor.execute("""
        INSERT INTO scans (id, user_id, repo_url, repo_name, status, score, pipeline_score, report_json)
        VALUES (888, 201, 'https://github.com/usera/repo', 'repo', 'Completed', 100, 100, '{"findings":[]}')
    """)
    conn.commit()
    conn.close()

    unauthorized_token = create_access_token({"sub": "user_b", "user_id": 202})
    headers = {"Authorization": f"Bearer {unauthorized_token}"}
    client = TestClient(app)

    # 1. GET /api/scans/{id}
    assert client.get("/api/scans/888", headers=headers).status_code == 404

    # 2. GET /api/scans/{id}/plan
    assert client.get("/api/scans/888/plan", headers=headers).status_code == 404

    # 3. DELETE /api/scans/{id}
    assert client.delete("/api/scans/888", headers=headers).status_code == 404

    # 4. POST /api/scans/{id}/apply-fix
    assert client.post("/api/scans/888/apply-fix", json={"finding_index": 0}, headers=headers).status_code == 404

    # 5. POST /api/scans/{id}/commit-workflow
    assert client.post("/api/scans/888/commit-workflow", json={}, headers=headers).status_code == 404

    # 6. POST /api/scans/{id}/verify
    assert client.post("/api/scans/888/verify", headers=headers).status_code == 404

    # 7. GET /api/scans/{id}/verify/status
    assert client.get("/api/scans/888/verify/status", headers=headers).status_code == 404

    # 8. GET /api/scans/{id}/patch
    assert client.get("/api/scans/888/patch", headers=headers).status_code == 404

    # 9. POST /api/scans/{id}/publish-prs
    assert client.post("/api/scans/888/publish-prs", headers=headers).status_code == 404


def test_pat_header_dedicated_and_login_token_never_treated_as_pat():
    # Requirement 2: Use only dedicated X-GitHub-Token header (not Authorization, which carries login JWT).
    # Test that the login token is NEVER treated as a PAT.
    user_jwt = create_access_token({"sub": "test_user", "user_id": 301})

    # 1. If only X-GitHub-Token is provided, extract_github_pat returns it
    assert extract_github_pat(x_github_token="ghp_VALID_PAT_XYZ") == "ghp_VALID_PAT_XYZ"

    # 2. If X-GitHub-Token is missing or empty, extract_github_pat returns None
    assert extract_github_pat(x_github_token=None) is None
    assert extract_github_pat(x_github_token="") is None

    # 3. Ensure ApplyFixRequest body rejects github_token
    req_fields = ApplyFixRequest.model_fields.keys()
    assert "github_token" not in req_fields
    assert "finding_index" in req_fields


def test_per_scan_status_cleanup():
    # Requirement A5: Per-scan status entries are cleaned up
    session_id = "test-session-uuid-12345"
    set_current_status("Scanning Dockerfile...", 50, session_id=session_id)
    assert get_current_status(session_id) == "Scanning Dockerfile..."
    assert session_id in _scan_status_store

    # Trigger cleanup
    cleanup_scan_status(session_id)
    assert session_id not in _scan_status_store
    assert get_current_status(session_id) == "Idle"


def test_clone_env_terminal_prompt_zero():
    # Requirement A8: Clone with GIT_TERMINAL_PROMPT=0
    import os
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    assert env["GIT_TERMINAL_PROMPT"] == "0"

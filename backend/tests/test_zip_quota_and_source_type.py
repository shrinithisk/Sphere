import os
import io
import zipfile
import json
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import init_db, get_db_connection
from app.auth import create_access_token


@pytest.fixture
def client_and_auth(tmp_path, monkeypatch):
    test_db = tmp_path / "test_zip_quota.db"
    monkeypatch.setenv("SPHERE_DB_PATH", str(test_db))
    monkeypatch.setattr("app.database.DB_PATH", str(test_db))
    init_db(str(test_db))

    conn = get_db_connection(str(test_db))
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("zipuser", "hash"))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    token = create_access_token({"sub": "zipuser", "user_id": user_id})
    return TestClient(app), token, user_id, str(test_db)


def test_zip_quota_enforcement(client_and_auth, monkeypatch):
    """
    Requirement 6: Enforce per-user quota on ZIP uploads (default 5).
    """
    test_client, auth_token, user_id, db_path = client_and_auth

    # Insert 5 existing ZIP scans for this user
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    for i in range(5):
        cursor.execute("""
            INSERT INTO scans (user_id, repo_url, repo_name, status, source_type)
            VALUES (?, ?, ?, ?, 'zip')
        """, (user_id, f"ZIP Upload: test_{i}.zip", f"test_{i}", "Completed"))
    conn.commit()
    conn.close()

    # Create dummy zip bytes
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("app.py", "print('hello')\n")
    zip_bytes = zip_buffer.getvalue()

    # Attempt to upload 6th zip
    resp = test_client.post(
        "/api/scan/zip",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("test_6.zip", zip_bytes, "application/zip")},
    )
    assert resp.status_code == 400
    assert "User ZIP upload quota exceeded" in resp.json()["detail"]


def test_source_type_saved_accurately_in_db(client_and_auth, monkeypatch):
    """
    Requirement 6: Add source_type column (zip | github) instead of checking repo_url prefix.
    """
    test_client, auth_token, user_id, db_path = client_and_auth

    # Mock pipeline and clone for URL scan
    with patch("app.main.git.Repo.clone_from") as mock_clone, \
         patch("app.main.run_security_pipeline", new_callable=AsyncMock) as mock_pipe:
        mock_pipe.return_value = {
            "health_scores": {"repo_score": 90, "pipeline_score": 100},
            "findings": [],
        }
        mock_repo = mock_clone.return_value
        mock_repo.head.commit.hexsha = "abc1234567890abcdef1234567890abcdef1234"

        resp = test_client.post(
            "/api/scan/url",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"repo_url": "https://github.com/shrinithisk/Sphere"},
        )
        assert resp.status_code == 200
        scan_id = resp.json()["id"]

        # Check DB source_type
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT source_type FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        assert row["source_type"] == "github"

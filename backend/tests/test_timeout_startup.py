import os
import json
import time
import pytest
from unittest.mock import patch, MagicMock

from app.database import init_db, get_db_connection
from app.verifier.runner import VerificationCancelToken, run_verification_loop
from app.planner.schema import UnifiedFinding, Category, FixType, FixClass, FixStatus
from app.planner.planner import FixPlan, PhasePlan
from app.main import cleanup_stale_running_jobs, cleanup_expired_zip_archives, UPLOADS_DIR


@pytest.mark.asyncio
async def test_verification_cancel_token_stops_execution(tmp_path):
    """
    Requirement 2: Threads can't be cancelled by asyncio.wait_for.
    A cancel token / deadline checked between fixes immediately halts the verification loop.
    """
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "test.py").write_text("x = 1\n")
    import git
    r = git.Repo.init(repo_dir)
    r.index.add(["test.py"])
    r.index.commit("Initial commit")

    cancel_token = VerificationCancelToken()
    cancel_token.cancel()  # Signal cancellation before/at start

    f1 = UnifiedFinding(
        id="FIND-1",
        tool="semgrep",
        rule_id="rule-1",
        file="test.py",
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Fix code issue",
        original_block="x = 1\n",
        patched_block="x = 2\n",
    )
    from app.planner.planner import create_fix_plan

    plan = create_fix_plan([f1])

    result = await run_verification_loop(str(repo_dir), plan, cancel_token=cancel_token)
    assert result.status == "CANCELLED"
    assert result.total_applied == 0
    assert result.verification_label == "UNVERIFIED"


def test_startup_marks_stale_running_jobs_interrupted(tmp_path):
    """
    Requirement 2: On startup, mark any stale RUNNING rows as FAILED (interrupted)
    so Render restart mid-run does not leave orphaned RUNNING records.
    """
    db_file = tmp_path / "test_startup.db"
    init_db(str(db_file))

    conn = get_db_connection(str(db_file))
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("testuser", "hash"))
    user_id = cursor.lastrowid

    # Insert a scan stuck in RUNNING
    cursor.execute("""
        INSERT INTO scans (user_id, repo_url, repo_name, status, verification_json)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        "https://github.com/test/repo",
        "repo",
        "RUNNING",
        json.dumps({"status": "RUNNING", "verification_label": "UNVERIFIED", "message": "In progress"}),
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Run startup cleanup
    cleanup_stale_running_jobs(str(db_file))

    # Verify rows were marked as FAILED (interrupted)
    conn = get_db_connection(str(db_file))
    cursor = conn.cursor()
    cursor.execute("SELECT status, verification_json FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    assert row["status"] == "FAILED (interrupted)"
    v_data = json.loads(row["verification_json"])
    assert v_data["status"] == "FAILED (interrupted)"
    assert "interrupted by backend server restart" in v_data["message"]


def test_cleanup_expired_zip_archives(tmp_path, monkeypatch):
    """
    Requirement 6: Retention limit for ZIP scans (delete after 24h).
    """
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    monkeypatch.setattr("app.main.UPLOADS_DIR", str(uploads))

    # 1. Old zip (48 hours ago)
    old_zip = uploads / "scan_1.zip"
    old_zip.write_text("dummy zip content")
    old_time = time.time() - (48 * 3600)
    os.utime(old_zip, (old_time, old_time))

    # 2. Fresh zip (1 hour ago)
    fresh_zip = uploads / "scan_2.zip"
    fresh_zip.write_text("fresh zip content")

    # Run cleanup with 24h retention
    cleanup_expired_zip_archives(max_age_hours=24)

    assert not old_zip.exists(), "Old zip (>24h) should have been pruned."
    assert fresh_zip.exists(), "Fresh zip (<24h) must be preserved."

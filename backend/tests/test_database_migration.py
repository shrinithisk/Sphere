import os
import sqlite3
import pytest
from app.database import init_db, get_db_connection


def test_legacy_database_migration_guarded_alter_table(tmp_path):
    """
    Requirement 3: DB migration adds commit_sha and verification_json via guarded ALTER TABLE
    so an existing legacy secureflow.db continues to work without data loss or crashes.
    """
    legacy_db_file = tmp_path / "legacy_secureflow.db"
    legacy_db_path = str(legacy_db_file)

    # 1. Create a legacy database with the OLD schema (WITHOUT commit_sha and verification_json)
    conn = sqlite3.connect(legacy_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            repo_url TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER,
            pipeline_score INTEGER,
            report_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    # Insert legacy user and scan
    cursor.execute("INSERT INTO users (username, password_hash) VALUES ('legacy_user', 'hash123')")
    cursor.execute("""
        INSERT INTO scans (user_id, repo_url, repo_name, status, score, pipeline_score, report_json)
        VALUES (1, 'https://github.com/shrinithisk/Sphere', 'Sphere', 'Completed', 88, 92, '{"findings":[]}')
    """)
    conn.commit()
    conn.close()

    # Verify old schema columns do not have commit_sha or verification_json
    conn = sqlite3.connect(legacy_db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("PRAGMA table_info(scans)")
    initial_cols = {r["name"] for r in c.fetchall()}
    assert "commit_sha" not in initial_cols
    assert "verification_json" not in initial_cols
    conn.close()

    # 2. Run init_db() migration on legacy database
    init_db(legacy_db_path)

    # 3. Assert new columns were safely added via guarded ALTER TABLE
    conn = get_db_connection(legacy_db_path)
    c = conn.cursor()
    c.execute("PRAGMA table_info(scans)")
    migrated_cols = {r["name"] for r in c.fetchall()}
    assert "commit_sha" in migrated_cols
    assert "verification_json" in migrated_cols

    # 4. Assert legacy data is preserved without corruption
    c.execute("SELECT id, user_id, repo_name, score, commit_sha, verification_json FROM scans WHERE id = 1")
    row = c.fetchone()
    assert row["id"] == 1
    assert row["repo_name"] == "Sphere"
    assert row["score"] == 88
    assert row["commit_sha"] is None
    assert row["verification_json"] is None

    # 5. Assert we can write to the migrated columns
    c.execute("""
        UPDATE scans SET commit_sha = 'abc123456789', verification_json = '{"status":"COMPLETED"}'
        WHERE id = 1
    """)
    conn.commit()

    c.execute("SELECT commit_sha, verification_json FROM scans WHERE id = 1")
    updated_row = c.fetchone()
    assert updated_row["commit_sha"] == "abc123456789"
    assert 'COMPLETED' in updated_row["verification_json"]
    conn.close()

    # 6. Test idempotency: re-running init_db on already migrated DB must succeed cleanly
    init_db(legacy_db_path)

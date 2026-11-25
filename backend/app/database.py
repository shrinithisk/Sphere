import sqlite3
import os

from typing import Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secureflow.db")

def get_db_connection(db_path: Optional[str] = None):
    target = db_path or os.environ.get("SPHERE_DB_PATH") or DB_PATH
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Optional[str] = None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            repo_url TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER,
            pipeline_score INTEGER,
            report_json TEXT,
            commit_sha TEXT,
            verification_json TEXT,
            source_type TEXT DEFAULT 'github',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # Requirement 3 & 6: Safe guarded migrations for existing legacy database schemas
    cursor.execute("PRAGMA table_info(scans)")
    existing_cols = {row["name"] for row in cursor.fetchall()}
    
    if "commit_sha" not in existing_cols:
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN commit_sha TEXT")
        except Exception:
            pass
    if "verification_json" not in existing_cols:
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN verification_json TEXT")
        except Exception:
            pass
    if "source_type" not in existing_cols:
        try:
            cursor.execute("ALTER TABLE scans ADD COLUMN source_type TEXT DEFAULT 'github'")
        except Exception:
            pass
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", DB_PATH)

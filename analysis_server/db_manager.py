"""
db_manager.py — SQLite storage for feedback and scan history.
All persistence for signatures.db lives here.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = "signatures.db"

# ─────────────── Schema ───────────────

def init_db():
    """Create / migrate tables."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Migrate old feedback table if it exists with the wrong schema ──
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'")
    if c.fetchone():
        c.execute("PRAGMA table_info(feedback)")
        cols = {row[1] for row in c.fetchall()}
        if "permissions" not in cols or "timestamp" not in cols:
            print("[db_manager] Migrating old feedback table to new schema …")
            c.execute("ALTER TABLE feedback RENAME TO feedback_old")
            c.execute("""
                CREATE TABLE feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT NOT NULL,
                    permissions TEXT,
                    is_malware INTEGER NOT NULL,
                    user_notes TEXT DEFAULT '',
                    timestamp TEXT NOT NULL
                )
            """)
            # Copy old rows (fill missing columns with defaults)
            c.execute("""
                INSERT INTO feedback (package_name, is_malware, permissions, user_notes, timestamp)
                SELECT package_name, is_malware, '[]', '',
                       datetime('now') FROM feedback_old
            """)
            c.execute("DROP TABLE feedback_old")
            print("[db_manager] Migration complete.")

    c.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            permissions TEXT,
            is_malware INTEGER NOT NULL,
            user_notes TEXT DEFAULT '',
            timestamp TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score REAL NOT NULL,
            leak_type TEXT,
            pii_detected TEXT,
            sensitive_detected TEXT,
            detected_threats TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print(f"[db_manager] Database initialized at {DB_PATH}")


# ─────────────── Feedback ───────────────

def save_feedback(package_name: str, permissions: list, is_malware: bool,
                  user_notes: str = ""):
    """Persist a user feedback report."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO feedback
           (package_name, permissions, is_malware, user_notes, timestamp)
           VALUES (?, ?, ?, ?, ?)""",
        (
            package_name,
            json.dumps(permissions),
            1 if is_malware else 0,
            user_notes,
            datetime.utcnow().isoformat()
        )
    )
    conn.commit()
    conn.close()


def get_all_feedback():
    """Return every feedback row as a list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM feedback ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_feedback_stats():
    """Aggregate malware/safe counts per permission for adaptive learning."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT permissions, is_malware FROM feedback"
    ).fetchall()
    conn.close()

    perm_stats = {}  # permission -> {"malware": int, "safe": int}
    for perms_json, is_mal in rows:
        try:
            perms = json.loads(perms_json) if perms_json else []
        except (json.JSONDecodeError, TypeError):
            continue
        for p in perms:
            key = p.split(".")[-1].upper()
            if key not in perm_stats:
                perm_stats[key] = {"malware": 0, "safe": 0}
            if is_mal:
                perm_stats[key]["malware"] += 1
            else:
                perm_stats[key]["safe"] += 1

    return perm_stats


# ─────────────── Scan History ───────────────

def save_scan_result(package_name: str, risk_level: str, score: float,
                     leak_type: str, pii_detected: list,
                     sensitive_detected: list, detected_threats: list):
    """Persist an analysis result."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO scan_history
           (package_name, risk_level, score, leak_type,
            pii_detected, sensitive_detected, detected_threats, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            package_name,
            risk_level,
            score,
            leak_type,
            json.dumps(pii_detected),
            json.dumps(sensitive_detected),
            json.dumps(detected_threats),
            datetime.utcnow().isoformat()
        )
    )
    conn.commit()
    conn.close()


def get_scan_history(limit: int = 50):
    """Return recent scan history rows."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

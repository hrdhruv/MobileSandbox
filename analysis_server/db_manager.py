"""
db_manager.py — SQLite storage for feedback and scan history.
All persistence for signatures.db lives here.
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta

DB_PATH = "signatures.db"

# ─────────────── Schema ───────────────

def init_db():
    """Create / migrate tables."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Migrate old feedback table if schema is out of date ──
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
            c.execute("""
                INSERT INTO feedback (package_name, is_malware, permissions, user_notes, timestamp)
                SELECT package_name, is_malware, '[]', '', datetime('now') FROM feedback_old
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
            timestamp TEXT NOT NULL,
            user_id TEXT DEFAULT 'anonymous'
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
            confidence REAL DEFAULT 1.0,
            timestamp TEXT NOT NULL,
            user_id TEXT DEFAULT 'anonymous'
        )
    """)

    # ── Migrate scan_history: add confidence column if missing ──
    c.execute("PRAGMA table_info(scan_history)")
    scan_cols = {row[1] for row in c.fetchall()}
    if "confidence" not in scan_cols:
        c.execute("ALTER TABLE scan_history ADD COLUMN confidence REAL DEFAULT 1.0")
        print("[db_manager] Migrated scan_history: added confidence column.")
        
    # ── Migrate missing user_id columns ──
    c.execute("PRAGMA table_info(feedback)")
    fb_cols = {row[1] for row in c.fetchall()}
    if "user_id" not in fb_cols:
        c.execute("ALTER TABLE feedback ADD COLUMN user_id TEXT DEFAULT 'anonymous'")
        print("[db_manager] Migrated feedback: added user_id column.")
        
    if "user_id" not in scan_cols:
        c.execute("ALTER TABLE scan_history ADD COLUMN user_id TEXT DEFAULT 'anonymous'")
        print("[db_manager] Migrated scan_history: added user_id column.")

    # ── SQLite VIEW: per-permission feedback aggregates (fast querying) ──
    c.execute("DROP VIEW IF EXISTS feedback_summary")
    # Note: SQLite does not support JSON functions universally, so the view
    # is a lightweight proxy; actual aggregation is done in Python.
    c.execute("""
        CREATE VIEW IF NOT EXISTS feedback_summary AS
        SELECT
            package_name,
            SUM(is_malware)          AS malware_count,
            SUM(1 - is_malware)      AS safe_count,
            COUNT(*)                 AS total_reports,
            MAX(timestamp)           AS last_report
        FROM feedback
        GROUP BY package_name
    """)

    conn.commit()
    conn.close()
    print(f"[db_manager] Database initialized at {DB_PATH}")


# ─────────────── Feedback ───────────────

def save_feedback(package_name: str, permissions: list, is_malware: bool,
                  user_notes: str = "", user_id: str = "anonymous"):
    """Persist a user feedback report."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO feedback
           (package_name, permissions, is_malware, user_notes, timestamp, user_id)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            package_name,
            json.dumps(permissions),
            1 if is_malware else 0,
            user_notes,
            datetime.utcnow().isoformat(),
            user_id
        )
    )
    conn.commit()
    conn.close()


def check_feedback_cooldown(user_id: str, package_name: str) -> bool:
    """
    Returns True if the user is in cooldown for this package.
    Cooldown triggers if they have submitted 2 or more reports
    in the last 1 hour for the same package.
    """
    if user_id == "anonymous":
        pass # Anonymous users might be pooled, but we can rate limit them too
    cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    row = c.execute(
        """SELECT COUNT(*) FROM feedback
           WHERE user_id = ? AND package_name = ? AND timestamp >= ?""",
        (user_id, package_name, cutoff)
    ).fetchone()
    conn.close()
    return int(row[0]) >= 2


def get_rating_progression():
    """
    Returns the rating history for each app as a structured dict limit to recent.
    Format: {"com.example.app": [{"user_id": ..., "is_malware": ..., "timestamp": ...}]}
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT package_name, user_id, is_malware, timestamp FROM feedback ORDER BY timestamp ASC").fetchall()
    conn.close()
    progression = {}
    for r in rows:
        pkg = r["package_name"]
        if pkg not in progression:
            progression[pkg] = []
        progression[pkg].append({
            "user_id": r["user_id"],
            "is_malware": bool(r["is_malware"]),
            "timestamp": r["timestamp"]
        })
    return progression


def get_all_feedback():
    """Return every feedback row as a list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM feedback ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_feedback_for_package(package_name: str):
    """Retrieve all feedback rows for a specific package."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM feedback WHERE package_name = ? ORDER BY id DESC",
        (package_name,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_feedback_stats():
    """
    Aggregate malware/safe counts per permission for adaptive learning.
    Returns: {permission_key: {"malware": int, "safe": int}}
    """
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT permissions, is_malware FROM feedback").fetchall()
    conn.close()

    perm_stats = {}
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


def get_package_feedback_adjustment(package_name: str) -> float:
    """
    Net user labels for this package only (malware vs safe reports).
    Returns a score delta on the 0–100 scale, capped, so feedback does not
    change risk for other packages that share the same permissions.
    """
    if not package_name:
        return 0.0
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        """SELECT
             COALESCE(SUM(CASE WHEN is_malware = 1 THEN 1 ELSE 0 END), 0),
             COALESCE(SUM(CASE WHEN is_malware = 0 THEN 1 ELSE 0 END), 0)
           FROM feedback WHERE package_name = ?""",
        (package_name,),
    ).fetchone()
    conn.close()
    if not row:
        return 0.0
    malware_n, safe_n = int(row[0]), int(row[1])
    net = malware_n - safe_n
    adj = net * 7.0
    return max(-30.0, min(30.0, adj))


# ─────────────── Scan History ───────────────

def is_duplicate_scan(package_name: str, window_minutes: int = 5) -> bool:
    """
    Return True if this package was already scanned within the last
    window_minutes — prevents duplicate DB entries from rapid re-scans.
    """
    cutoff = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        """SELECT id FROM scan_history
           WHERE package_name = ? AND timestamp >= ?
           ORDER BY id DESC LIMIT 1""",
        (package_name, cutoff)
    ).fetchone()
    conn.close()
    return row is not None


def save_scan_result(package_name: str, risk_level: str, score: float,
                     leak_type: str, pii_detected: list,
                     sensitive_detected: list, detected_threats: list,
                     confidence: float = 1.0, user_id: str = "anonymous"):
    """
    Persist an analysis result.
    Skips insertion if the same package was scanned within 5 minutes
    (deduplication guard).
    confidence: [0–1] signal-agreement score from ml_engine (FIX-v2-6).
    """
    if is_duplicate_scan(package_name):
        return  # skip duplicate

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """INSERT INTO scan_history
           (package_name, risk_level, score, leak_type,
            pii_detected, sensitive_detected, detected_threats,
            confidence, timestamp, user_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            package_name,
            risk_level,
            score,
            leak_type,
            json.dumps(pii_detected),
            json.dumps(sensitive_detected),
            json.dumps(detected_threats),
            confidence,
            datetime.utcnow().isoformat(),
            user_id
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


# ─────────────── Aggregate Stats ───────────────

def get_aggregate_stats():
    """
    Returns a summary dict used by the /stats endpoint:
      - total_scans
      - feedback_malware / feedback_safe / feedback_total
      - top_risky_permissions: top-10 permissions by malware frequency
      - risk_level_distribution: count per risk level in scan_history
    """
    conn = sqlite3.connect(DB_PATH)

    total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    fb_mal = conn.execute(
        "SELECT COUNT(*) FROM feedback WHERE is_malware = 1"
    ).fetchone()[0]
    fb_safe = conn.execute(
        "SELECT COUNT(*) FROM feedback WHERE is_malware = 0"
    ).fetchone()[0]

    # Risk-level distribution
    level_rows = conn.execute(
        "SELECT risk_level, COUNT(*) as cnt FROM scan_history GROUP BY risk_level"
    ).fetchall()
    level_dist = {row[0]: row[1] for row in level_rows}

    # Top risky permissions from feedback (malware-labelled rows)
    mal_rows = conn.execute(
        "SELECT permissions FROM feedback WHERE is_malware = 1"
    ).fetchall()
    conn.close()

    perm_counts = {}
    for (perms_json,) in mal_rows:
        try:
            perms = json.loads(perms_json) if perms_json else []
        except (json.JSONDecodeError, TypeError):
            continue
        for p in perms:
            key = p.split(".")[-1].upper()
            perm_counts[key] = perm_counts.get(key, 0) + 1

    top_perms = sorted(perm_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_scans": total_scans,
        "feedback_malware": fb_mal,
        "feedback_safe": fb_safe,
        "feedback_total": fb_mal + fb_safe,
        "risk_level_distribution": level_dist,
        "top_risky_permissions": [
            {"permission": p, "malware_reports": c} for p, c in top_perms
        ]
    }
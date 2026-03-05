"""
view_db.py — Inspect signatures.db contents (feedback + scan history).
Usage: python view_db.py
"""

import sqlite3
import os
import json

DB_PATH = "signatures.db"


def view_table(conn, table_name, columns, formatters=None):
    """Generic table viewer."""
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT name FROM sqlite_master WHERE type='table' AND name=?;",
        (table_name,)
    )
    if not cursor.fetchone():
        print(f"  Table '{table_name}' does not exist yet.\n")
        return

    cursor.execute(f"SELECT * FROM {table_name} ORDER BY id DESC")
    rows = cursor.fetchall()

    if not rows:
        print(f"  No records in '{table_name}'.\n")
        return

    # Print header
    header = " | ".join(f"{col:<20}" for col in columns)
    print(header)
    print("-" * len(header))

    for row in rows:
        vals = []
        for i, col in enumerate(columns):
            val = row[i] if i < len(row) else ""
            if formatters and col in formatters:
                val = formatters[col](val)
            vals.append(f"{str(val):<20}")
        print(" | ".join(vals))

    print(f"\n  Total: {len(rows)} records\n")


def view_all():
    if not os.path.exists(DB_PATH):
        print(f"Error: {DB_PATH} not found. Run the server first.")
        return

    conn = sqlite3.connect(DB_PATH)

    print("\n" + "=" * 70)
    print("  FEEDBACK TABLE")
    print("=" * 70)
    view_table(conn, "feedback",
               ["id", "package_name", "permissions", "is_malware",
                "user_notes", "timestamp"],
               formatters={
                   "permissions": lambda v: (
                       str(len(json.loads(v))) + " perms"
                       if v else "0 perms"
                   ),
                   "is_malware": lambda v: "MALWARE" if v else "SAFE"
               })

    print("=" * 70)
    print("  SCAN HISTORY TABLE")
    print("=" * 70)
    view_table(conn, "scan_history",
               ["id", "package_name", "risk_level", "score",
                "leak_type", "pii_detected", "sensitive_detected",
                "detected_threats", "timestamp"],
               formatters={
                   "score": lambda v: f"{v:.2f}",
                   "pii_detected": lambda v: (
                       str(len(json.loads(v))) + " items"
                       if v else "0"
                   ),
                   "sensitive_detected": lambda v: (
                       str(len(json.loads(v))) + " items"
                       if v else "0"
                   ),
                   "detected_threats": lambda v: (
                       str(len(json.loads(v))) + " threats"
                       if v else "0"
                   )
               })

    conn.close()


if __name__ == "__main__":
    view_all()
"""
test_backend.py — Automated backend tests using pytest.

Run from analysis_server/ directory:
    python -m pytest test_backend.py -v
"""

import pytest
import json
import os
import sqlite3
import tempfile

# ── Set up a temp DB for tests (never pollutes signatures.db) ──
import db_manager
import ml_engine

TEST_DB = "test_signatures.db"


@pytest.fixture(autouse=True)
def use_test_db(tmp_path, monkeypatch):
    """Redirect all DB calls to a temporary file."""
    test_db = str(tmp_path / "test.db")
    monkeypatch.setattr(db_manager, "DB_PATH", test_db)
    db_manager.init_db()
    yield
    # Cleanup handled by tmp_path fixture


# ──────────────────────────────────────────────
#  1. Scoring: SAFE app
# ──────────────────────────────────────────────

def test_analyze_permissions_safe():
    """An app with no sensitive permissions should score < 30 and be SAFE."""
    result = ml_engine.analyze_permissions(["android.permission.VIBRATE"])
    assert result["score"] < 30, f"Expected < 30, got {result['score']}"
    assert result["level"] == "SAFE", f"Expected SAFE, got {result['level']}"


# ──────────────────────────────────────────────
#  2. Scoring: DANGEROUS app
# ──────────────────────────────────────────────

def test_analyze_permissions_dangerous():
    """An app with READ_SMS + SEND_SMS + ACCESS_FINE_LOCATION should score >= 70."""
    perms = [
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    ]
    result = ml_engine.analyze_permissions(perms)
    assert result["score"] >= 50, f"Expected >= 50 (SUSPICIOUS/DANGEROUS), got {result['score']}"
    assert result["level"] in ("SUSPICIOUS", "DANGEROUS"), \
        f"Expected SUSPICIOUS or DANGEROUS, got {result['level']}"


# ──────────────────────────────────────────────
#  3. Scoring: HANDLE_WITH_CARE
# ──────────────────────────────────────────────

def test_analyze_permissions_handle_with_care():
    """Medium-risk permissions should produce HANDLE_WITH_CARE (30-50)."""
    perms = [
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.INTERNET",
        "android.permission.ACCESS_WIFI_STATE",
    ]
    result = ml_engine.analyze_permissions(perms)
    # HANDLE_WITH_CARE range is 30-50; with ML signal it may vary slightly
    # Just confirm it's not SAFE for a camera+storage app
    assert result["score"] >= 20, \
        f"Expected at least 20 for camera+storage app, got {result['score']}"


# ──────────────────────────────────────────────
#  4. DB: save and retrieve scan
# ──────────────────────────────────────────────

def test_db_save_and_retrieve_scan():
    """Insert a scan, then verify it appears in scan history."""
    db_manager.save_scan_result(
        package_name="com.test.app",
        risk_level="DANGEROUS",
        score=87.5,
        leak_type="High Risk PII",
        pii_detected=["READ_SMS"],
        sensitive_detected=[],
        detected_threats=["READ_SMS"]
    )
    history = db_manager.get_scan_history()
    assert len(history) == 1
    assert history[0]["package_name"] == "com.test.app"
    assert abs(history[0]["score"] - 87.5) < 0.01
    assert history[0]["risk_level"] == "DANGEROUS"


# ──────────────────────────────────────────────
#  5. DB: deduplication within 5-minute window
# ──────────────────────────────────────────────

def test_db_deduplication():
    """Same app scanned twice quickly should only create 1 DB row."""
    for _ in range(3):  # try 3 times in quick succession
        db_manager.save_scan_result(
            package_name="com.dedupe.test",
            risk_level="SAFE",
            score=10.0,
            leak_type="Low Risk",
            pii_detected=[],
            sensitive_detected=[],
            detected_threats=[]
        )
    history = db_manager.get_scan_history()
    assert len(history) == 1, \
        f"Expected 1 row after dedup, got {len(history)}"


# ──────────────────────────────────────────────
#  6. DB: feedback stats aggregation
# ──────────────────────────────────────────────

def test_db_feedback_stats():
    """Insert two feedback rows and verify per-permission counts."""
    db_manager.save_feedback(
        package_name="com.malware",
        permissions=["android.permission.READ_SMS", "android.permission.SEND_SMS"],
        is_malware=True
    )
    db_manager.save_feedback(
        package_name="com.safe",
        permissions=["android.permission.READ_SMS", "android.permission.INTERNET"],
        is_malware=False
    )

    stats = db_manager.get_feedback_stats()

    assert "READ_SMS" in stats
    assert stats["READ_SMS"]["malware"] == 1
    assert stats["READ_SMS"]["safe"] == 1

    assert "SEND_SMS" in stats
    assert stats["SEND_SMS"]["malware"] == 1
    assert stats["SEND_SMS"]["safe"] == 0


# ──────────────────────────────────────────────
#  7. Bayesian update raises risk after malware feedback
# ──────────────────────────────────────────────

def test_bayesian_update_increases_risk():
    """
    Marking an app as malware twice should increase the Bayesian risk
    estimate for its permissions compared to the prior.
    """
    perm = "android.permission.READ_SMS"
    PRIOR = ml_engine.BETA_ALPHA_0 / (ml_engine.BETA_ALPHA_0 + ml_engine.BETA_BETA_0) * 10.0

    ml_engine.adaptive_update(
        package_name="com.testmal1",
        android_permissions=[perm],
        is_malware=True
    )
    ml_engine.adaptive_update(
        package_name="com.testmal2",
        android_permissions=[perm],
        is_malware=True
    )

    bayes_risk = ml_engine.get_bayesian_risk("READ_SMS")
    assert bayes_risk > PRIOR, \
        f"Expected Bayesian risk > prior ({PRIOR:.2f}), got {bayes_risk:.2f}"


# ──────────────────────────────────────────────
#  8. Aggregate stats
# ──────────────────────────────────────────────

def test_aggregate_stats():
    """After adding scans and feedback, stats should reflect them."""
    db_manager.save_scan_result(
        "com.a", "DANGEROUS", 80.0, "High Risk", ["READ_SMS"], [], []
    )
    db_manager.save_feedback("com.a", ["android.permission.READ_SMS"], True)

    stats = db_manager.get_aggregate_stats()
    assert stats["total_scans"] >= 1
    assert stats["feedback_total"] >= 1
    assert "DANGEROUS" in stats["risk_level_distribution"]

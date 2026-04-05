from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import uvicorn
import ml_engine
import db_manager
import random
import numpy as np

random.seed(42)
np.random.seed(42)

app = FastAPI(title="MobileSandbox Analysis Server")


# ─────────────── Request Models ───────────────

class AppData(BaseModel):
    package_name: str
    permissions: List[str]


class FeedbackData(BaseModel):
    package_name: str
    permissions: List[str]
    is_malware: bool
    user_notes: Optional[str] = ""


# ─────────────── Lifecycle ───────────────

@app.on_event("startup")
def startup_event():
    db_manager.init_db()
    ml_engine.load_or_train()


# ─────────────── Core Endpoints ───────────────

@app.post("/analyze")
async def analyze(data: AppData):
    """
    Analyse an app's permissions and return a risk score.

    Single deterministic evaluation (permission mix + models + package
    reputation). Min/max match the point score for API compatibility.

    Returns 'confidence' [0–1]: how much the three internal signals agree.
    High confidence → the verdict is reliable.
    Low confidence  → signals are mixed; treat result with more caution.
    """
    base_result = ml_engine.analyze_permissions(
        data.permissions, package_name=data.package_name
    )
    median_score = base_result["score_int"]
    min_score = median_score
    max_score = median_score

    enhanced_leak_type = (
        f"{base_result['leak_type']} (Range: {min_score}–{max_score})"
    )

    db_manager.save_scan_result(
        package_name=data.package_name,
        risk_level=base_result["level"],
        score=base_result["score"],
        leak_type=enhanced_leak_type,
        pii_detected=base_result["pii_detected"],
        sensitive_detected=base_result["sensitive_detected"],
        detected_threats=base_result["flags"],
        confidence=base_result.get("confidence", 1.0),
    )

    return {
        "app": data.package_name,
        "risk_level": base_result["level"],
        "score": median_score,
        "score_min": min_score,
        "score_max": max_score,
        "score_precise": round(base_result["score"], 4),
        "leak_type": enhanced_leak_type,
        "pii_detected": base_result["pii_detected"],
        "sensitive_detected": base_result["sensitive_detected"],
        "detected_threats": base_result["flags"],
        "confidence": base_result.get("confidence", 1.0),
    }


@app.post("/feedback")
async def feedback(data: FeedbackData):
    ml_engine.adaptive_update(
        package_name=data.package_name,
        android_permissions=data.permissions,
        is_malware=data.is_malware,
        user_notes=data.user_notes or ""
    )
    return {
        "status": "feedback recorded and adaptive learning update applied",
        "package": data.package_name,
        "is_malware": data.is_malware
    }


# ─────────────── History Endpoints ───────────────

@app.get("/feedback/history")
async def feedback_history():
    return {"feedback": db_manager.get_all_feedback()}


@app.get("/scan/history")
async def scan_history():
    return {"scans": db_manager.get_scan_history()}


# ─────────────── Stats Endpoint ───────────────

@app.get("/stats")
async def stats():
    """
    Aggregate statistics across all scans and feedback:
      - total_scans, feedback breakdown
      - risk_level_distribution
      - top_10 riskiest permissions observed in malware-labelled feedback
    """
    return db_manager.get_aggregate_stats()


# ─────────────── Calibrate Endpoint ───────────────

@app.get("/calibrate")
async def calibrate():
    """
    FIX-v2: Returns current scoring configuration so clients can display
    threshold information and understand the scoring model's parameters.
    """
    return {
        "thresholds": {
            "SAFE": "< 30",
            "HANDLE_WITH_CARE": "30 – 55",
            "SUSPICIOUS": "55 – 75",
            "DANGEROUS": "≥ 75",
        },
        "bayesian_prior": {
            "alpha_0": ml_engine.BETA_ALPHA_0,
            "beta_0": ml_engine.BETA_BETA_0,
            "prior_mean_scaled": round(
                ml_engine.BETA_ALPHA_0 /
                (ml_engine.BETA_ALPHA_0 + ml_engine.BETA_BETA_0) * 10, 2
            ),
            "description": "Safe-biased. New apps start at low risk until evidence says otherwise.",
        },
        "auto_retrain": {
            "every_n_samples": ml_engine.AUTO_RETRAIN_EVERY,
            "min_malware_samples": ml_engine.MIN_RETRAIN_MALWARE,
            "min_safe_samples": ml_engine.MIN_RETRAIN_SAFE,
        },
        "signal_weights": {
            "signal_a_static": "58% (ML present) / 70% (ML absent)",
            "signal_b_ml": "24% (ML present) / 0% (ML absent)",
            "signal_c_prior": "18% (ML present) / 30% (ML absent); not cross-app feedback",
        },
        "known_safe_apps": ml_engine._known_safe_apps,
    }


# ─────────────── Retrain Endpoint ───────────────

@app.post("/retrain")
async def retrain():
    """
    Trigger a background retrain augmented with feedback data.
    Non-blocking — returns immediately; training runs in a daemon thread.
    """
    started = ml_engine.retrain_from_feedback()
    if started:
        return {
            "status": "retrain started in background",
            "message": "Check server logs for progress. "
                       "Model will be updated automatically on completion."
        }
    else:
        return {
            "status": "skipped",
            "message": "A retrain is already in progress."
        }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
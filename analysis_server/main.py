from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import uvicorn
import ml_engine
import db_manager

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
    result = ml_engine.analyze_permissions(data.permissions)

    db_manager.save_scan_result(
        package_name=data.package_name,
        risk_level=result["level"],
        score=result["score"],
        leak_type=result["leak_type"],
        pii_detected=result["pii_detected"],
        sensitive_detected=result["sensitive_detected"],
        detected_threats=result["flags"]
    )

    return {
        "app": data.package_name,
        "risk_level": result["level"],
        "score": result["score_int"],
        "score_precise": round(result["score"], 4),
        "leak_type": result["leak_type"],
        "pii_detected": result["pii_detected"],
        "sensitive_detected": result["sensitive_detected"],
        "detected_threats": result["flags"]
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
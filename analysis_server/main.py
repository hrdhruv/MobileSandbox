from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import uvicorn
import ml_engine
import db_manager

app = FastAPI()


class AppData(BaseModel):
    package_name: str
    permissions: list[str]


class FeedbackData(BaseModel):
    package_name: str
    permissions: list[str]
    is_malware: bool
    user_notes: Optional[str] = ""


@app.on_event("startup")
def startup_event():
    db_manager.init_db()
    ml_engine.load_or_train()


@app.post("/analyze")
async def analyze(data: AppData):
    result = ml_engine.analyze_permissions(data.permissions)

    # Persist scan result to database
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
        "score": result["score_int"],       # int for Android display
        "score_precise": result["score"],    # float for logging / debug
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


@app.get("/feedback/history")
async def feedback_history():
    return {"feedback": db_manager.get_all_feedback()}


@app.get("/scan/history")
async def scan_history():
    return {"scans": db_manager.get_scan_history()}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
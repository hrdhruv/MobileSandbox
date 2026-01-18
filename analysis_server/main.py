from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import ml_engine

app = FastAPI()

CSV_PATH = "dataset/data.csv"


class AppData(BaseModel):
    package_name: str
    permissions: list[str]


class FeedbackData(BaseModel):
    permissions: list[str]
    is_malware: bool


@app.on_event("startup")
def startup_event():
    ml_engine.train_from_csv(CSV_PATH)


@app.post("/analyze")
async def analyze(data: AppData):
    result = ml_engine.analyze_permissions(data.permissions)
    return {
        "app": data.package_name,
        "risk_level": result["level"],
        "score": result["score"],
        "detected_threats": result["flags"]
    }


@app.post("/feedback")
async def feedback(data: FeedbackData):
    ml_engine.adaptive_update(data.permissions, data.is_malware)
    return {"status": "model updated"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

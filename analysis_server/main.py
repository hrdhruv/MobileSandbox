from fastapi import FastAPI
from pydantic import BaseModel
import ml_engine
import uvicorn

app = FastAPI()

class AppData(BaseModel):
    package_name: str
    permissions: list[str]

@app.post("/analyze")
async def analyze(data: AppData):
    print(f"Request received for: {data.package_name}")
    result = ml_engine.analyze_permissions(data.permissions)
    return {
        "app": data.package_name,
        "risk_level": result["level"],
        "score": result["score"],
        "detected_threats": result["flags"]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
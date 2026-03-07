"""
ML Detector API Server — FastAPI
Exposes HTTP classification endpoint for the DWAF validator network.

Run:
    uvicorn api_server:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import logging

from detector import HTTPDetector


# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("ml-detector")


# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────

app = FastAPI(
    title="DWAF ML Detector",
    description="HTTP anomaly detection service for the Distributed WAF pipeline",
    version="0.1.0",
)

detector: Optional[HTTPDetector] = None


@app.on_event("startup")
def load_models():
    global detector
    detector = HTTPDetector()
    logger.info("ML detector initialized")


# ─────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────

class HTTPRequestIn(BaseModel):
    method: str = Field(..., example="POST")
    url: str = Field(..., example="/login?id=1")

    user_agent: Optional[str] = Field("", example="Mozilla/5.0")
    content_type: Optional[str] = Field("", example="application/x-www-form-urlencoded")
    cookie: Optional[str] = Field("", example="JSESSIONID=abc123")

    length: Optional[int] = Field(0, ge=0, example=42)
    content: Optional[str] = Field("", example="username=admin&password=pass")

    host: Optional[str] = Field("localhost")
    pragma: Optional[str] = Field("")
    cache_control: Optional[str] = Field("")
    accept: Optional[str] = Field("")
    connection: Optional[str] = Field("keep-alive")


class DetectionResponse(BaseModel):
    classification: str
    threat_score: float
    rf_probability: float
    iso_flag: int
    features: List[float]
    latency_ms: float


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    model_loaded: bool


class BatchRequestIn(BaseModel):
    requests: List[HTTPRequestIn]


class BatchDetectionResponse(BaseModel):
    results: List[DetectionResponse]
    total: int
    malicious_count: int
    benign_count: int
    total_latency_ms: float


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "DWAF ML Detector", "status": "running"}


@app.get("/health", response_model=HealthResponse)
def health():
    """Health check used by orchestrator."""
    return HealthResponse(
        status="healthy",
        service="ml-detector",
        version="0.1.0",
        model_loaded=detector is not None,
    )


@app.post("/detect", response_model=DetectionResponse)
def detect(req: HTTPRequestIn):
    """
    Classify a single HTTP request.
    """

    if detector is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    start = time.time()

    try:
        result = detector.predict(req.model_dump())
    except Exception as e:
        logger.error(f"Detection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    latency = round((time.time() - start) * 1000, 2)
    result["latency_ms"] = latency

    logger.info(
        f"{req.method} {req.url[:60]} → "
        f"{result['classification']} "
        f"(score={result['threat_score']:.2f}, {latency}ms)"
    )

    return result


@app.post("/detect/batch", response_model=BatchDetectionResponse)
def detect_batch(batch: BatchRequestIn):

    if detector is None:
        raise HTTPException(status_code=500, detail="Model not loaded")

    start = time.time()
    results = []

    for req in batch.requests:

        try:
            result = detector.predict(req.model_dump())
            result["latency_ms"] = 0.0
            results.append(result)

        except Exception as e:
            logger.error(f"Batch item failed: {e}")

            results.append({
                "classification": "error",
                "threat_score": 0.0,
                "rf_probability": 0.0,
                "iso_flag": 0,
                "features": [0.0] * 41,
                "latency_ms": 0.0,
            })

    total_ms = round((time.time() - start) * 1000, 2)

    malicious = sum(1 for r in results if r["classification"] == "malicious")
    benign = sum(1 for r in results if r["classification"] == "benign")

    logger.info(
        f"Batch {len(results)} requests → "
        f"{malicious} malicious, {benign} benign ({total_ms}ms)"
    )

    return BatchDetectionResponse(
        results=results,
        total=len(results),
        malicious_count=malicious,
        benign_count=benign,
        total_latency_ms=total_ms,
    )


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )

"""
app.py — Feedback Service API
Receives threat events from orchestrator, updates WAF rules, triggers retraining.
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from model_retrainer import save_events, should_retrain, trigger_retrain
from waf_updater import update_rules, get_rules

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("feedback-service")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DWAF Feedback Service",
    description="Stage V: Adaptive WAF rule generation and ML retraining",
    version="0.1.0",
)

# ── Models ────────────────────────────────────────────────────────────────────

class ThreatEvent(BaseModel):
    request_id: str
    classification: str
    threat_score: float
    features: Optional[List[float]] = None
    consensus: bool = False
    url: Optional[str] = ""
    timestamp: Optional[datetime] = None


class EventsPayload(BaseModel):
    events: List[ThreatEvent]
    timestamp: Optional[datetime] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
def health():
    """Health check endpoint."""
    rules = get_rules()

    return {
        "status": "healthy",
        "service": "feedback-service",
        "version": "0.1.0",
        "total_rules": len(rules),
    }


@app.post("/events", tags=["feedback"])
def receive_events(payload: EventsPayload):
    """
    Receive threat events from orchestrator.
    Updates WAF rules and triggers retraining if threshold reached.
    """

    events = []

    for e in payload.events:
        event = e.model_dump()

        # Ensure timestamp exists
        if not event.get("timestamp"):
            event["timestamp"] = datetime.now(timezone.utc).isoformat()

        events.append(event)

    # ── Save events ─────────────────────────────────────────

    total = save_events(events)

    # ── Update adaptive WAF rules ───────────────────────────

    rule_result = update_rules(events)

    # ── Check retraining threshold ──────────────────────────

    retrain_result = None

    if should_retrain(min_events=100):
        retrain_result = trigger_retrain()
        logger.info("Automatic model retraining triggered")

    logger.info(
        f"Processed {len(events)} events | total stored: {total} | new rules: {rule_result['added']}"
    )

    return {
        "received": len(events),
        "total": total,
        "rules": rule_result,
        "retrain": retrain_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/retrain", tags=["ml"])
def manual_retrain():
    """Manually trigger model retraining."""
    logger.info("Manual retraining requested")

    result = trigger_retrain()

    return result


@app.get("/rules", tags=["waf"])
def get_waf_rules():
    """Return current adaptive WAF rules."""
    return {"rules": get_rules()}


@app.get("/rules/count", tags=["waf"])
def rules_count():
    """Return number of adaptive WAF rules."""
    return {"count": len(get_rules())}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=5000,
        log_level="info",
        reload=False
    )
"""
app.py — TAXII 2.1 server for DWAF threat distribution
"""

import json
import os
import uuid
from datetime import datetime
from typing import List

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from stix_convertor import threat_to_stix

# ── Setup ───────────────────────────────────────────────────────────────

app = FastAPI(title="DWAF TAXII Server")

COLLECTION_PATH = "collections/verified-threats.json"


# ── Helpers ─────────────────────────────────────────────────────────────

def load_collection():
    if not os.path.exists(COLLECTION_PATH):
        return []
    with open(COLLECTION_PATH, "r") as f:
        return json.load(f)


def save_collection(data):
    os.makedirs("collections", exist_ok=True)
    with open(COLLECTION_PATH, "w") as f:
        json.dump(data, f, indent=2)


# ── Models ──────────────────────────────────────────────────────────────

class ThreatEvent(BaseModel):
    request_id: str
    classification: str
    threat_score: float
    consensus: bool


class PublishRequest(BaseModel):
    events: List[ThreatEvent]


# ── Endpoints ───────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "taxii-server",
        "threats": len(load_collection()),
    }


@app.get("/collections")
def get_collections():
    return {
        "collections": [
            {
                "id": "verified-threats",
                "title": "DWAF Verified Threat Intelligence",
                "can_read": True,
                "can_write": True,
            }
        ]
    }


@app.get("/collections/verified-threats/objects")
def get_objects():
    return load_collection()


@app.post("/publish")
def publish_events(req: PublishRequest):
    stored = load_collection()
    for event in req.events:
        stix_obj = threat_to_stix(event.model_dump())
        stored.append(json.loads(stix_obj.serialize()))
    save_collection(stored)
    return {"status": "published", "count": len(req.events)}


# ── Entry point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=6000, log_level="info")

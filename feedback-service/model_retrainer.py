"""
model_retrainer.py — triggers ML model retraining when new threat data accumulates
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("feedback.retrainer")

RULES_DIR = Path(__file__).parent / "rules"
EVENTS_LOG = RULES_DIR / "threat_events.json"

# Ensure rules directory exists
RULES_DIR.mkdir(parents=True, exist_ok=True)


def save_events(events: List[Dict]) -> int:
    """
    Append new threat events to the local log file.
    Returns total number of stored events.
    """
    existing = []

    if EVENTS_LOG.exists():
        try:
            existing = json.loads(EVENTS_LOG.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Failed to read existing events log: {e}")
            existing = []

    existing.extend(events)

    EVENTS_LOG.write_text(
        json.dumps(existing, indent=2, default=str),
        encoding="utf-8"
    )

    logger.info(f"Saved {len(events)} events — total stored: {len(existing)}")

    return len(existing)


def should_retrain(min_events: int = 100) -> bool:
    """
    Returns True if enough new events have accumulated
    to justify model retraining.
    """
    if not EVENTS_LOG.exists():
        return False

    try:
        events = json.loads(EVENTS_LOG.read_text(encoding="utf-8"))
        return len(events) >= min_events
    except Exception as e:
        logger.warning(f"Failed reading events log: {e}")
        return False


def trigger_retrain(csv_path: str | None = None) -> dict:
    """
    Trigger ML model retraining by preparing a training command.
    In production this would submit a job to a training cluster.
    """

    logger.info("Triggering model retraining...")

    result = {
        "triggered": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "queued",
    }

    try:
        cmd = [
            "python",
            "training/train.py",
            "--csv",
            csv_path or "training/csic2010/csic_2010.csv",
        ]

        logger.info(f"Retraining command: {' '.join(cmd)}")

        # In a real deployment this would submit an async job
        result["command"] = " ".join(cmd)
        result["status"] = "queued"

        logger.info("Retraining job queued successfully")

    except Exception as e:
        logger.error(f"Retraining failed: {e}")

        result["status"] = "failed"
        result["error"] = str(e)

    return result
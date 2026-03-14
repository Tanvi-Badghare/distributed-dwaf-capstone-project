"""
stix_converter.py — converts DWAF threat events into STIX 2.1 Indicator objects
"""

import uuid
from datetime import datetime, timezone

from stix2 import Indicator


def threat_to_stix(event: dict) -> Indicator:
    """
    Convert a DWAF threat event dict into a STIX 2.1 Indicator.
    """
    now = datetime.now(timezone.utc).isoformat()

    indicator = Indicator(
        id=f"indicator--{uuid.uuid4()}",
        name="DWAF Verified Threat",
        description=(
            f"Malicious request detected: {event.get('request_id', 'unknown')}. "
            f"Score: {event.get('threat_score', 0):.3f}. "
            f"Consensus: {event.get('consensus', False)}."
        ),
        pattern_type="stix",
        pattern=f"[x-dwaf-threat:score >= {event.get('threat_score', 0)}]",
        valid_from=now,
        labels=["malicious-activity", event.get("classification", "unknown")],
        custom_properties={
            "x_dwaf_request_id":    event.get("request_id", ""),
            "x_dwaf_score":         event.get("threat_score", 0),
            "x_dwaf_consensus":     event.get("consensus", False),
            "x_dwaf_classification": event.get("classification", ""),
        },
    )

    return indicator
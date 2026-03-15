"""
waf_updater.py — generates and updates adaptive WAF rules based on detected threats
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("feedback.waf_updater")

RULES_DIR = Path(__file__).parent / "rules"
RULES_FILE = RULES_DIR / "adaptive_rules.json"

# Ensure rules directory exists
RULES_DIR.mkdir(parents=True, exist_ok=True)


def extract_patterns(events: List[Dict]) -> List[Dict]:
    """
    Extract URL patterns from threat events and generate WAF blocking rules.
    Only events with high threat score are considered.
    """

    rules: List[Dict] = []

    for event in events:
        url = event.get("url", "")
        score = event.get("threat_score", 0)

        if not url or score < 0.8:
            continue

        # Extract path without query string
        path = url.split("?")[0] if "?" in url else url

        rule = {
            "id": f"rule-{len(rules)+1:04d}",
            "action": "block",
            "pattern": path,
            "threat_score": score,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source": "dwaf-adaptive",
        }

        rules.append(rule)

    return rules


def update_rules(events: List[Dict]) -> Dict:
    """
    Generate new WAF rules from threat events and update the rule store.
    Deduplicates rules based on URL pattern.
    """

    existing: List[Dict] = []

    if RULES_FILE.exists():
        try:
            existing = json.loads(RULES_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Failed reading existing rules: {e}")
            existing = []

    new_rules = extract_patterns(events)

    # Deduplicate rules by pattern
    existing_patterns = {r["pattern"] for r in existing}

    added = [r for r in new_rules if r["pattern"] not in existing_patterns]

    existing.extend(added)

    RULES_FILE.write_text(
        json.dumps(existing, indent=2),
        encoding="utf-8"
    )

    logger.info(f"WAF rules updated — added {len(added)}, total {len(existing)}")

    return {
        "added": len(added),
        "total": len(existing),
        "updated": datetime.now(timezone.utc).isoformat(),
    }


def get_rules() -> List[Dict]:
    """
    Return the current adaptive WAF rules.
    """

    if not RULES_FILE.exists():
        return []

    try:
        return json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Failed reading rules: {e}")
        return []
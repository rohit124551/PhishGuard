"""
Google Safe Browsing Check
Queries the Google Safe Browsing API v4 to detect known malicious URLs.
Requires the SAFE_BROWSING_KEY environment variable to be set.
"""

import os
import requests
from typing import Dict, Any

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]

REQUEST_TIMEOUT = 5  # seconds


def check(url: str) -> Dict[str, Any]:
    """
    Query Google Safe Browsing API v4 for known threats.

    Scoring:
      - Threat found → score 30 (danger)
      - No threat    → score 0  (safe)
      - API key missing / request error → score 0 (warning)
    """
    api_key = os.getenv("SAFE_BROWSING_KEY", "").strip()

    if not api_key:
        return {
            "name": "Google Safe Browsing",
            "score": 0,
            "status": "warning",
            "reason": "SAFE_BROWSING_KEY environment variable is not set — check skipped.",
        }

    payload = {
        "client": {
            "clientId": "phishguard-detector",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])
        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN")
            friendly = threat_type.replace("_", " ").title()
            return {
                "name": "Google Safe Browsing",
                "score": 30,
                "status": "danger",
                "reason": f"URL is listed as a threat by Google Safe Browsing: {friendly}.",
            }

        return {
            "name": "Google Safe Browsing",
            "score": 0,
            "status": "safe",
            "reason": "URL is not flagged by Google Safe Browsing.",
        }

    except requests.exceptions.Timeout:
        return {
            "name": "Google Safe Browsing",
            "score": 0,
            "status": "warning",
            "reason": "Google Safe Browsing API request timed out — check skipped.",
        }
    except requests.exceptions.HTTPError as exc:
        return {
            "name": "Google Safe Browsing",
            "score": 0,
            "status": "warning",
            "reason": f"Safe Browsing API returned HTTP {exc.response.status_code} — check skipped.",
        }
    except Exception as exc:
        return {
            "name": "Google Safe Browsing",
            "score": 0,
            "status": "warning",
            "reason": f"Safe Browsing check failed: {str(exc)[:120]}",
        }

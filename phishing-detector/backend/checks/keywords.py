"""
Keyword Check
Scans the full URL string for common phishing-related keywords.
Each matched keyword adds 5 points to the score (max 30).
"""

from urllib.parse import unquote
from typing import Dict, Any, List

PHISHING_KEYWORDS: List[str] = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "password",
    "credential",
    "signin",
    "webscr",
]

POINTS_PER_MATCH = 5
MAX_SCORE = 30


def check(url: str) -> Dict[str, Any]:
    """
    Scan the URL (decoded) for phishing keywords.

    Scoring: 5 points per keyword match, capped at 30.
    """
    try:
        # Decode percent-encoding so embedded keywords are visible
        decoded_url = unquote(url).lower()

        matched: List[str] = [kw for kw in PHISHING_KEYWORDS if kw in decoded_url]
        score = min(len(matched) * POINTS_PER_MATCH, MAX_SCORE)

        if not matched:
            return {
                "name": "Suspicious Keywords",
                "score": 0,
                "status": "safe",
                "reason": "No phishing-related keywords detected in the URL.",
            }

        if score >= 20:
            status = "danger"
        else:
            status = "warning"

        keyword_list = ", ".join(f'"{kw}"' for kw in matched)
        return {
            "name": "Suspicious Keywords",
            "score": score,
            "status": status,
            "reason": f"Found {len(matched)} phishing keyword(s) in URL: {keyword_list}.",
        }

    except Exception as exc:
        return {
            "name": "Suspicious Keywords",
            "score": 0,
            "status": "safe",
            "reason": f"Keyword scan encountered an error: {str(exc)[:120]}",
        }

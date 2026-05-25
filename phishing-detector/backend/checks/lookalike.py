"""
Lookalike Domain Check
Compares the extracted domain name against a list of well-known brands
using difflib.SequenceMatcher to detect typosquatting / homograph attacks.
"""

import difflib
import tldextract
from typing import Dict, Any, List, Tuple

BRAND_DOMAINS: List[str] = [
    "paypal",
    "google",
    "amazon",
    "apple",
    "microsoft",
    "facebook",
    "instagram",
    "netflix",
    "bank",
    "chase",
    "wellsfargo",
]

# Similarity threshold: above this triggers a warning (but is NOT an exact match)
SIMILARITY_THRESHOLD = 0.7


def _best_match(domain: str) -> Tuple[str, float]:
    """Return the brand with the highest similarity ratio and its score."""
    best_brand = ""
    best_ratio = 0.0

    for brand in BRAND_DOMAINS:
        ratio = difflib.SequenceMatcher(None, domain, brand).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_brand = brand

    return best_brand, best_ratio


def check(url: str) -> Dict[str, Any]:
    """
    Detect lookalike/typosquat domains impersonating major brands.

    Scoring:
      - Similarity > 0.7 AND not an exact match → score 25 (danger)
      - Exact match (legitimate brand domain)   → score 0  (safe)
      - Below threshold                         → score 0  (safe)
    """
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()

        if not domain:
            return {
                "name": "Lookalike Domain",
                "score": 0,
                "status": "safe",
                "reason": "Could not extract a domain name to compare.",
            }

        best_brand, ratio = _best_match(domain)

        if ratio >= SIMILARITY_THRESHOLD:
            if domain == best_brand:
                return {
                    "name": "Lookalike Domain",
                    "score": 0,
                    "status": "safe",
                    "reason": f"Domain exactly matches the brand '{best_brand}' — appears legitimate.",
                }
            else:
                similarity_pct = round(ratio * 100, 1)
                return {
                    "name": "Lookalike Domain",
                    "score": 25,
                    "status": "danger",
                    "reason": (
                        f"Domain '{domain}' is {similarity_pct}% similar to the brand '{best_brand}' "
                        f"— likely a typosquat or impersonation attempt."
                    ),
                }

        return {
            "name": "Lookalike Domain",
            "score": 0,
            "status": "safe",
            "reason": f"Domain '{domain}' does not closely resemble any known brand (best match: '{best_brand}' at {round(ratio*100,1)}%).",
        }

    except Exception as exc:
        return {
            "name": "Lookalike Domain",
            "score": 0,
            "status": "safe",
            "reason": f"Lookalike check encountered an error: {str(exc)[:120]}",
        }

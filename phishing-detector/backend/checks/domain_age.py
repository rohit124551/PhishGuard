"""
Domain Age Check
Checks how old the domain is using WHOIS data.
Newer domains are more commonly associated with phishing attacks.
"""

import whois
import tldextract
from datetime import datetime, timezone
from typing import Dict, Any


def check(url: str) -> Dict[str, Any]:
    """
    Check the domain age via WHOIS lookup.

    Scoring:
      - Domain < 30 days old  → score 25
      - Domain < 6 months old → score 15
      - Domain >= 6 months    → score 0
    """
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        if not extracted.domain or not extracted.suffix:
            return {
                "name": "Domain Age",
                "score": 10,
                "status": "warning",
                "reason": "Could not extract a valid domain from the URL.",
            }

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return {
                "name": "Domain Age",
                "score": 20,
                "status": "warning",
                "reason": "WHOIS creation date not available — domain may be newly registered or privacy-protected.",
            }

        # Normalise to UTC-aware datetime
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        if age_days < 30:
            return {
                "name": "Domain Age",
                "score": 25,
                "status": "danger",
                "reason": f"Domain is only {age_days} day(s) old — extremely new domains are a strong phishing indicator.",
            }
        elif age_days < 180:
            months = age_days // 30
            return {
                "name": "Domain Age",
                "score": 15,
                "status": "warning",
                "reason": f"Domain is approximately {months} month(s) old — recently registered domains warrant caution.",
            }
        else:
            years = age_days // 365
            months = (age_days % 365) // 30
            age_str = f"{years}y {months}m" if years else f"{months} month(s)"
            return {
                "name": "Domain Age",
                "score": 0,
                "status": "safe",
                "reason": f"Domain is {age_str} old — established domain with no age-related risk.",
            }

    except Exception as exc:
        return {
            "name": "Domain Age",
            "score": 10,
            "status": "warning",
            "reason": f"WHOIS lookup failed or timed out: {str(exc)[:120]}",
        }

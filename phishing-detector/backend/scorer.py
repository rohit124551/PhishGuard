"""
Scorer
Aggregates results from all individual checks and produces a final verdict.
"""

from typing import List, Dict, Any

# Verdict thresholds
SAFE_THRESHOLD = 30
SUSPICIOUS_THRESHOLD = 60


def score(check_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Collect all check results, sum scores, and return a final verdict.

    Verdict:
      total_score  <  30  → "safe"
      30 ≤ total_score ≤ 60  → "suspicious"
      total_score  > 60  → "dangerous"
    """
    total_score: int = sum(result.get("score", 0) for result in check_results)

    # Clamp to the theoretical maximum (5 checks × 30 pts = 150)
    total_score = max(0, min(total_score, 150))

    if total_score < SAFE_THRESHOLD:
        verdict = "safe"
    elif total_score <= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "dangerous"

    # Determine the highest individual risk level for a summary status
    status_priority = {"safe": 0, "warning": 1, "danger": 2}
    highest_status = max(
        (r.get("status", "safe") for r in check_results),
        key=lambda s: status_priority.get(s, 0),
        default="safe",
    )

    return {
        "total_score": total_score,
        "max_score": 150,
        "verdict": verdict,
        "highest_status": highest_status,
        "checks": check_results,
    }

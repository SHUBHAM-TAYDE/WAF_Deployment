def calculate_threat_score(crs_score: float, xgb_prob: float, iso_score: float, redis_rep: float) -> float:
    """
    Computes a combined normalized threat score between 0.0 and 1.0.
    
    Parameters:
      crs_score: Raw OWASP CRS anomaly score.
      xgb_prob: Probability output of the XGBoost classifier [0.0 - 1.0].
      iso_score: Score output of the Isolation Forest (negative implies anomaly).
      redis_rep: Threat reputation counter of the client IP from Redis.
    """
    # Defensive type conversions
    crs_score = float(crs_score or 0.0)
    xgb_prob = float(xgb_prob or 0.0)
    iso_score = float(iso_score or 0.0)
    redis_rep = float(redis_rep or 0.0)

    # 1. Normalize variables to [0.0 - 1.0] scale
    crs_norm = min(crs_score / 20.0, 1.0)
    
    # Isolation Forest: normal is close to 0 or positive, outliers are negative down to -0.5
    iso_norm = min(max(-iso_score / 0.5, 0.0), 1.0)
    
    # Reputation boost caps at 0.15 (reached at ~5 previous blocks)
    rep_boost = min(redis_rep * 0.03, 0.15)
    
    # 2. Weighted score calculation
    base_score = (crs_norm * 0.50 + xgb_prob * 0.30 + iso_norm * 0.20)
    
    return min(base_score + rep_boost, 1.0)

def get_routing_outcome(score: float, crs_score: float) -> str:
    """
    Maps threat score to routing actions.
    Enforces immediate blocking on obvious attacks with critically high CRS scores.
    """
    crs_score = float(crs_score or 0.0)
    score = float(score or 0.0)
    
    # TODO(security): High-certainty attack threshold bypass.
    # If the rule engine is absolutely sure of an attack (CRS score >= 20),
    # do not allow ML scores to override the block.
    if crs_score >= 20.0:
        return "block"
        
    # Decision Matrix Routing Outcomes
    if score >= 0.85:
        return "block"
    elif score >= 0.70:
        return "rate_limit"
    elif score >= 0.40:
        return "log"
    else:
        return "allow"

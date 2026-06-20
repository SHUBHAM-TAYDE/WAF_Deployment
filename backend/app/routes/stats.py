from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from app.models.response_models import StatsResponse, TimelineResponse, TimelineEntry
from app.services.auth import require_any_role, TokenData
from app.services.stats_calculator import (
    calculate_stats,
    get_top_ips,
    get_attack_types_distribution,
    get_timeline,
    get_top_rules,
    get_severity_distribution,
)

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
async def get_general_stats(current_user: TokenData = Depends(require_any_role)):
    """
    Get overall WAF statistics.
    """
    stats = calculate_stats()
    return StatsResponse(**stats)


@router.get("/top-ips", response_model=List[Dict[str, Any]])
async def get_top_attacking_ips(current_user: TokenData = Depends(require_any_role)):
    """
    Get top attacking IPs.
    """
    return get_top_ips()


@router.get("/attack-types", response_model=List[Dict[str, Any]])
async def get_attack_types(current_user: TokenData = Depends(require_any_role)):
    """
    Get attack category distribution.
    """
    return get_attack_types_distribution()


@router.get("/timeline", response_model=TimelineResponse)
async def get_attack_timeline(current_user: TokenData = Depends(require_any_role)):
    """
    Get timeline of attacks.
    """
    data = get_timeline()
    entries = [TimelineEntry(**item) for item in data]
    return TimelineResponse(data=entries)


@router.get("/top-rules", response_model=List[Dict[str, Any]])
async def get_top_rules_stats(current_user: TokenData = Depends(require_any_role)):
    """
    Get most triggered rules.
    """
    return get_top_rules()


@router.get("/severity-distribution", response_model=List[Dict[str, Any]])
async def get_severity_dist(current_user: TokenData = Depends(require_any_role)):
    """
    Get severity level distribution.
    """
    return get_severity_distribution()

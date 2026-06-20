import logging
from fastapi import APIRouter, Depends
from typing import Dict, Any

from app.services.ddos_analytics import get_ddos_analytics
from app.services.auth import require_admin, TokenData

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/ddos/analytics", response_model=Dict[str, Any])
async def ddos_analytics(current_user: TokenData = Depends(require_admin)):
    """
    Returns the latest DDoS/Bot mitigation traffic graph and top blocked IPs.
    """
    try:
        return get_ddos_analytics()
    except Exception as e:
        logger.error(f"Error fetching DDoS analytics: {e}")
        return {"timeline": [], "top_ips": [], "total_blocks": 0}

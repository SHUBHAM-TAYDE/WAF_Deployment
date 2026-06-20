from fastapi import APIRouter, Query, HTTPException, Depends
from typing import List, Optional
from app.models.rule_model import (
    RuleEntry,
    RuleToggleRequest,
    ParanoiaRequest,
    AuditLogEntry,
    RuleStatsResponse,
)
from app.services import rule_manager
from app.services.auth import require_admin, require_any_role, TokenData

router = APIRouter()


@router.get("/rules")
async def get_rules(
    page: int = Query(1, ge=1),
    size: int = Query(15, ge=1, le=100),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """
    Fetch paginated, filtered WAF rules database.
    """
    try:
        rules, total = rule_manager.get_all_rules(
            page=page,
            size=size,
            category=category,
            severity=severity,
            enabled=enabled,
            search=search,
        )
        return {"data": rules, "total": total, "page": page, "size": size}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch rules: {str(e)}")


@router.get("/rules/stats", response_model=RuleStatsResponse)
async def get_rules_stats(current_user: TokenData = Depends(require_any_role)):
    """
    Get rules triggers, status summary, and tuning recommendation statistics.
    """
    try:
        return rule_manager.get_rules_stats()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to calculate stats: {str(e)}"
        )


@router.get("/rules/history", response_model=List[AuditLogEntry])
async def get_rules_history(current_user: TokenData = Depends(require_any_role)):
    """
    Get WAF rules configuration modification audit logs.
    """
    try:
        return rule_manager.get_audit_history()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to load audit history: {str(e)}"
        )


@router.get("/rules/{id}", response_model=RuleEntry)
async def get_rule(id: str, current_user: TokenData = Depends(require_any_role)):
    """
    Get specific rule details including full regular expression syntax blocks.
    """
    rule = rule_manager.get_rule_by_id(id)
    if not rule:
        raise HTTPException(
            status_code=404,
            detail=f"Rule ID {id} not found in current OWASP CRS dataset.",
        )
    return rule


@router.post("/rules/enable")
async def enable_rule(
    request: RuleToggleRequest, current_user: TokenData = Depends(require_admin)
):
    """
    Enable a specific WAF rule.
    """
    ok, msg = rule_manager.toggle_rule(
        rule_id=request.id,
        enabled=True,
        reason=request.reason or "Enabled from CyberSentinel SOC portal.",
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"message": msg}


@router.post("/rules/disable")
async def disable_rule(
    request: RuleToggleRequest, current_user: TokenData = Depends(require_admin)
):
    """
    Disable a specific WAF rule (requires validation reason).
    """
    if not request.reason or len(request.reason.strip()) < 3:
        raise HTTPException(
            status_code=400,
            detail="A valid justification reason is required to disable protection rules.",
        )

    ok, msg = rule_manager.toggle_rule(
        rule_id=request.id, enabled=False, reason=request.reason
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"message": msg}


@router.post("/paranoia-level")
async def update_paranoia_level(
    request: ParanoiaRequest, current_user: TokenData = Depends(require_admin)
):
    """
    Update the global OWASP CRS detection paranoia level (PL1 to PL4).
    """
    ok, msg = rule_manager.set_paranoia_level(level=request.level)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"message": msg}


@router.post("/rules/reset")
async def restore_defaults(current_user: TokenData = Depends(require_admin)):
    """
    Revert all custom rule overrides and restore system default states.
    """
    ok, msg = rule_manager.reset_rules()
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"message": msg}

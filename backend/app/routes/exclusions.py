from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from datetime import datetime
import base64
import json
from app.routes.settings import EncodedPayloadModel

from app.models.exclusion_model import (
    ExclusionCreateRequest,
    ExclusionPreviewRequest,
    ExclusionStatusUpdateRequest,
    ExclusionNoteUpdateRequest,
    ExclusionResponse,
)
from app.services import db_service, rule_manager
from app.services.auth import require_admin, require_any_role, TokenData

router = APIRouter()


@router.post("/exclusions/preview")
async def preview_exclusion(
    encoded_payload: EncodedPayloadModel,
    current_user: TokenData = Depends(require_any_role),
):
    """Generates a preview of the ModSecurity exclusion rule without saving it."""
    try:
        encoded_str = encoded_payload.payload
        if encoded_str.startswith("WAF_BYPASS_"):
            encoded_str = encoded_str[len("WAF_BYPASS_") :]
        json_str = base64.b64decode(encoded_str).decode("utf-8")
        request = ExclusionPreviewRequest(**json.loads(json_str))

        # Determine a simulated ID
        simulated_id = 9999
        rule_text = rule_manager.generate_modsec_rule(
            exclusion_type=request.exclusion_type,
            rule_id=request.rule_id,
            uri=request.uri,
            parameter_name=request.parameter_name,
            http_method=request.http_method,
            client_ip=request.client_ip,
            next_id=simulated_id,
        )
        return {"modsec_rule": rule_text}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate preview: {e}")


@router.post(
    "/exclusions", response_model=ExclusionResponse, status_code=status.HTTP_201_CREATED
)
async def create_new_exclusion(
    encoded_payload: EncodedPayloadModel,
    current_user: TokenData = Depends(require_admin),
):
    """Creates a new targeted exclusion, generates the ModSec rule, and reloads NGINX WAF."""
    try:
        encoded_str = encoded_payload.payload
        if encoded_str.startswith("WAF_BYPASS_"):
            encoded_str = encoded_str[len("WAF_BYPASS_") :]
        json_str = base64.b64decode(encoded_str).decode("utf-8")
        request = ExclusionCreateRequest(**json.loads(json_str))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload")

    # Safety Check: Broad exclusion prevention
    if request.exclusion_type in (
        "uri",
        "uri_parameter",
        "endpoint_method",
        "ip_suppression",
    ):
        if not request.uri or request.uri.strip() == "/" or request.uri.strip() == "":
            raise HTTPException(
                status_code=400,
                detail="Broad exclusions on root path ('/') are rejected to prevent weakening overall WAF protection.",
            )
        if not request.uri.startswith("/"):
            raise HTTPException(
                status_code=400,
                detail="Target endpoint URI must start with a forward slash '/'.",
            )

    # Generate the rule first to validate inputs
    try:
        # Get next auto-increment ID to use for rule ID generation
        existing = db_service.get_all_exclusions()
        next_id = len(existing) + 1

        modsec_rule_text = rule_manager.generate_modsec_rule(
            exclusion_type=request.exclusion_type,
            rule_id=request.rule_id,
            uri=request.uri,
            parameter_name=request.parameter_name,
            http_method=request.http_method,
            client_ip=request.client_ip,
            next_id=next_id,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Store in database
    exclusion = db_service.create_exclusion(
        false_positive_id=request.false_positive_id,
        rule_id=request.rule_id,
        exclusion_type=request.exclusion_type,
        uri=request.uri,
        parameter_name=request.parameter_name,
        http_method=request.http_method,
        client_ip=request.client_ip,
        created_by=current_user.username,
        notes=request.notes,
        modsec_rule=modsec_rule_text,
        timestamp=timestamp,
    )

    if not exclusion:
        raise HTTPException(
            status_code=500,
            detail="Failed to write exception policy to SQLite registry.",
        )

    # Sync configuration file & reload NGINX WAF
    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        # Revert DB entry on failure to maintain consistency with actual WAF state
        db_service.delete_exclusion(exclusion["id"], "system", timestamp)
        raise HTTPException(
            status_code=400,
            detail=f"WAF compilation failed: {msg}. Exclusion was rolled back.",
        )

    return exclusion


@router.get("/exclusions", response_model=List[ExclusionResponse])
async def list_exclusions(
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """Retrieves all exceptions and custom tuning rules."""
    return db_service.get_all_exclusions(status=status, search=search)


@router.get("/exclusions/analytics")
async def get_analytics(current_user: TokenData = Depends(require_any_role)):
    """Returns analytics data for exceptions and false positive rules triggers."""
    return db_service.get_exclusions_analytics()


@router.get("/exclusions/history")
async def get_exclusions_history(current_user: TokenData = Depends(require_any_role)):
    """Retrieves edit/tuning history and historical overrides logs."""
    return db_service.get_exclusion_audit_history()


@router.post("/exclusions/{id}/status", response_model=ExclusionResponse)
async def update_status(
    id: int,
    request: ExclusionStatusUpdateRequest,
    current_user: TokenData = Depends(require_admin),
):
    """Enables or disables a specific exclusion and reloads WAF state."""
    if request.status not in ("Active", "Disabled"):
        raise HTTPException(
            status_code=400, detail="Exclusion status must be 'Active' or 'Disabled'."
        )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated = db_service.update_exclusion_status(
        id, request.status, current_user.username, timestamp
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Exclusion record not found.")

    # Sync & reload NGINX WAF
    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        # Revert status on failure
        old_status = "Disabled" if request.status == "Active" else "Active"
        db_service.update_exclusion_status(id, old_status, "system", timestamp)
        raise HTTPException(
            status_code=400, detail=f"WAF reload failed: {msg}. Change rolled back."
        )

    return updated


@router.post("/exclusions/{id}/note", response_model=ExclusionResponse)
async def update_note(
    id: int,
    request: ExclusionNoteUpdateRequest,
    current_user: TokenData = Depends(require_admin),
):
    """Updates analyst justification note for a registered WAF exception."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    updated = db_service.update_exclusion_note(
        id, request.notes, current_user.username, timestamp
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Exclusion record not found.")
    return updated


@router.post("/exclusions/{id}/delete")
async def delete_exclusion(id: int, current_user: TokenData = Depends(require_admin)):
    """Removes a rule exception and reloads WAF configs to activate the target rules."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Keep old copy in case reload fails and we need to restore it
    old_exclusion = db_service.get_exclusion_by_id(id)
    if not old_exclusion:
        raise HTTPException(status_code=404, detail="Exclusion record not found.")

    success = db_service.delete_exclusion(id, current_user.username, timestamp)
    if not success:
        raise HTTPException(
            status_code=500, detail="Failed to delete exclusion from registry."
        )

    # Sync & reload NGINX WAF
    ok, msg = rule_manager.sync_rules_and_exclusions()
    if not ok:
        # Restore on failure to keep WAF in sync with DB
        db_service.create_exclusion(
            false_positive_id=old_exclusion["false_positive_id"],
            rule_id=old_exclusion["rule_id"],
            exclusion_type=old_exclusion["exclusion_type"],
            uri=old_exclusion["uri"],
            parameter_name=old_exclusion["parameter_name"],
            http_method=old_exclusion["http_method"],
            client_ip=old_exclusion["client_ip"],
            created_by=old_exclusion["created_by"],
            notes=old_exclusion["notes"],
            modsec_rule=old_exclusion["modsec_rule"],
            timestamp=old_exclusion["created_at"],
        )
        raise HTTPException(
            status_code=400,
            detail=f"WAF reload failed: {msg}. Deletion aborted & rolled back.",
        )

    return {
        "message": "Exclusion rule successfully deleted and WAF configurations synchronized."
    }

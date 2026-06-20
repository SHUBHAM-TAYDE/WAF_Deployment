import os
import stat
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, Depends
from typing import Optional
from app.models.response_models import PaginatedLogs
from app.services.auth import require_any_role, TokenData
from app.services.log_reader import get_all_logs, list_newest_log_files
from app.config.settings import settings
from app.websocket.connection_manager import manager

router = APIRouter()


@router.get("/logs", response_model=PaginatedLogs)
async def get_logs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = None,
    rule_id: Optional[str] = None,
    ip: Optional[str] = None,
    attack_type: Optional[str] = None,
    status_code: Optional[str] = None,
    search: Optional[str] = None,
    current_user: TokenData = Depends(require_any_role),
):
    """
    Fetch paginated, filtered logs.
    """
    logs = get_all_logs()

    # Apply filters
    if severity:
        logs = [log for log in logs if log.severity.lower() == severity.lower()]
    if rule_id:
        logs = [log for log in logs if log.rule_id == rule_id]
    if ip:
        logs = [log for log in logs if log.client_ip == ip]
    if attack_type:
        logs = [log for log in logs if log.attack_type.lower() == attack_type.lower()]
    if status_code:
        logs = [log for log in logs if log.http_code == status_code]
    if search:
        s_lower = search.lower()
        logs = [
            log
            for log in logs
            if (log.message and s_lower in log.message.lower())
            or (log.uri and s_lower in log.uri.lower())
            or (log.client_ip and s_lower in log.client_ip.lower())
            or (log.rule_id and s_lower in log.rule_id.lower())
            or (log.attack_type and s_lower in log.attack_type.lower())
        ]

    total = len(logs)

    # Pagination
    start = (page - 1) * size
    end = start + size
    paginated_data = logs[start:end]

    return PaginatedLogs(data=paginated_data, total=total, page=page, size=size)


@router.websocket("/logs/stream")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time log streaming.
    """
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the client, just keep the connection open
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.get("/debug/logs")
async def debug_logs(current_user: TokenData = Depends(require_any_role)):
    """
    Debug endpoint: lists all discovered log files, their permissions, and readability.
    Use this to diagnose why logs may not be appearing.
    """
    files = list_newest_log_files(limit=50)

    results = []
    for f in files[:50]:
        try:
            file_stat = os.stat(f)
            mode = oct(stat.S_IMODE(file_stat.st_mode))
            readable = os.access(f, os.R_OK)
            owner_uid = file_stat.st_uid
            results.append(
                {
                    "path": f,
                    "readable": readable,
                    "mode": mode,
                    "owner_uid": owner_uid,
                    "size_bytes": file_stat.st_size,
                    "mtime": file_stat.st_mtime,
                }
            )
        except Exception as e:
            results.append({"path": f, "error": str(e)})

    return {
        "log_dir": settings.LOG_DIR,
        "dir_exists": os.path.isdir(settings.LOG_DIR),
        "dir_readable": os.access(settings.LOG_DIR, os.R_OK),
        "backend_user_uid": os.getuid(),
        "backend_user_gid": os.getgid(),
        "total_files_found": len(files),
        "files": results,
    }

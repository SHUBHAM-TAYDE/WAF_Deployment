from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any
import csv
import io

from app.models.response_models import StatsResponse, TimelineResponse, TimelineEntry
from app.services.auth import require_any_role, TokenData
from app.services.log_reader import get_all_logs
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


@router.get("/stats/export/csv")
async def export_logs_csv(current_user: TokenData = Depends(require_any_role)):
    """
    Exports the WAF security events/logs as a CSV file.
    """
    logs = get_all_logs()

    def generate():
        output = io.StringIO()
        writer = csv.writer(output)

        # Write CSV header
        writer.writerow([
            "Transaction ID",
            "Timestamp",
            "Client IP",
            "Country",
            "Method",
            "URI",
            "Severity",
            "Attack Type",
            "Rule ID",
            "Message"
        ])

        for log in logs:
            writer.writerow([
                log.id,
                log.timestamp,
                log.client_ip,
                log.country or "Unknown",
                log.method,
                log.uri,
                log.severity,
                log.attack_type,
                log.rule_id or "N/A",
                log.message or ""
            ])
            data = output.getvalue()
            output.seek(0)
            output.truncate(0)
            yield data

    response = StreamingResponse(generate(), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=waf_security_report.csv"
    return response

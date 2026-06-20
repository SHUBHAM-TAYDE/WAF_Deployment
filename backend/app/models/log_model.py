from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class ViolationDetail(BaseModel):
    rule_id: str
    message: str
    data: Optional[str] = ""
    pattern: Optional[str] = ""
    file: Optional[str] = ""
    line_number: Optional[str] = ""


class LogEntry(BaseModel):
    id: str  # Unique identifier for the log (e.g. transaction id)
    timestamp: str
    client_ip: str
    uri: str
    method: str
    http_code: str
    rule_id: str
    message: str
    severity: str
    attack_type: str
    hostname: str
    country: Optional[str] = ""
    source_asn_org: Optional[str] = ""
    request_headers: Optional[Dict[str, str]] = {}
    response_headers: Optional[Dict[str, str]] = {}
    violations: Optional[List[ViolationDetail]] = []
    raw_log: Optional[Dict[str, Any]] = None

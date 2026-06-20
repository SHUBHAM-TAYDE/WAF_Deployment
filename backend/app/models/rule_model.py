from pydantic import BaseModel
from typing import List, Dict, Any, Optional


class RuleEntry(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    category: str
    enabled: bool
    paranoia_level: int
    hit_count: int
    last_triggered: Optional[str] = ""
    file_path: str
    syntax: str
    tags: List[str]


class RuleToggleRequest(BaseModel):
    id: str
    enabled: bool = True
    reason: Optional[str] = ""


class ParanoiaRequest(BaseModel):
    level: int


class AuditLogEntry(BaseModel):
    timestamp: str
    username: str
    action: str  # "enable", "disable", "paranoia_change", "reset"
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    details: str


class RuleStatsResponse(BaseModel):
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    paranoia_level: int
    top_triggered_rules: List[Dict[str, Any]]
    category_distribution: List[Dict[str, Any]]
    tuning_candidates: List[Dict[str, Any]]

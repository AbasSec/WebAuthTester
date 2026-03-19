"""
WebAuth Models - Data structures for the auditing suite.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from datetime import datetime

@dataclass
class AuthEndpoint:
    """Represents a discovered authentication gateway."""
    url: str
    auth_type: str  # form_urlencoded, universal_json
    method: str
    username_field: str
    password_field: str
    extra_fields: Dict[str, str] = field(default_factory=dict)
    source_page: Optional[str] = None

@dataclass
class AuthBaseline:
    """Reference signature for a failed login attempt."""
    failed_status: int
    failed_length: int
    failed_body_sample: str

@dataclass
class SecurityFinding:
    """Represents a security weakness or vulnerability."""
    type: str
    title: str
    severity: str
    description: str
    remediation: str
    evidence: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

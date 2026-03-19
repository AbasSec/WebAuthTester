"""
WebAuth Models - Data structures for the auditing suite.

This module defines the core data structures used throughout the WebAuthTester
framework, ensuring strong typing and clear data boundaries between modules.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional
from datetime import datetime

@dataclass
class AuthEndpoint:
    """
    Represents a discovered authentication gateway.
    
    Attributes:
        url (str): The target URL of the endpoint.
        auth_type (str): The method of authentication (e.g., 'form_urlencoded', 'universal_json').
        method (str): The HTTP method expected (e.g., 'POST').
        username_field (str): The identified field name for the username/email.
        password_field (str): The identified field name for the password.
        extra_fields (Dict[str, str]): Additional required fields (e.g., CSRF tokens, API flags).
        source_page (Optional[str]): The URL where this endpoint was discovered.
    """
    url: str
    auth_type: str
    method: str
    username_field: str
    password_field: str
    extra_fields: Dict[str, str] = field(default_factory=dict)
    source_page: Optional[str] = None

@dataclass
class AuthBaseline:
    """
    Reference signature for a failed login attempt.
    
    Used by the Differential Response Modeling (DRM) engine to determine 
    if a subsequent authentication attempt was successful based on structural divergence.
    
    Attributes:
        failed_status (int): The HTTP status code returned for a known failure.
        failed_length (int): The byte length of the failure response body.
        failed_body_sample (str): A string sample (up to 2000 chars) of the failure response.
    """
    failed_status: int
    failed_length: int
    failed_body_sample: str

@dataclass
class SecurityFinding:
    """
    Represents a generalized security weakness or vulnerability.
    
    Attributes:
        type (str): The category of the finding (e.g., 'Misconfiguration', 'Cleartext').
        title (str): A human-readable title.
        severity (str): The CVSS-aligned severity (e.g., 'High', 'Medium').
        description (str): Detailed explanation of the flaw.
        remediation (str): Recommended steps to fix the issue.
        evidence (Dict): Data supporting the finding.
        timestamp (datetime): When the finding was identified.
    """
    type: str
    title: str
    severity: str
    description: str
    remediation: str
    evidence: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

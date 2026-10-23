"""
Graph Entity & Relationship Models
Component: Active Directory Knowledge Graph


These models define the contract between:
  - Meseret's tool integration layer (feature/tool-integration), which
    produces raw LDAP/NetExec output,
  - Feben's finding_rules.py (feature/ad-security), which produces
    SecurityFinding objects, and
  - this graph module, which stores both as a connected graph in Neo4j.

Node labels: Domain, User, Group, Computer, Service, Finding
Relationship types: MemberOf, HasSPN, AdminTo, RunsService, CanAccess,
                     TrustedBy, HasFinding
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ----------------------------------------------------------------------
# Nodes
# ----------------------------------------------------------------------

class Domain(BaseModel):
    name: str                              # e.g. "sevenkingdoms.local" - unique key
    dc_hostname: Optional[str] = None      # e.g. "kingslanding.sevenkingdoms.local"
    netbios_name: Optional[str] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class User(BaseModel):
    distinguished_name: str                # unique key, e.g. "CN=sql_svc,CN=Users,DC=..."
    sam_account_name: str
    domain: str                            # FK to Domain.name
    object_sid: Optional[str] = None
    user_account_control: Optional[int] = None
    service_principal_names: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    admin_count: Optional[int] = None      # AdminCount=1 is a common privilege signal
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Group(BaseModel):
    distinguished_name: str                # unique key
    sam_account_name: str
    domain: str
    object_sid: Optional[str] = None
    is_high_value: Optional[bool] = None   # e.g. Domain Admins, Enterprise Admins
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Computer(BaseModel):
    distinguished_name: str                # unique key
    sam_account_name: str
    domain: str
    dns_hostname: Optional[str] = None
    operating_system: Optional[str] = None
    object_sid: Optional[str] = None
    is_domain_controller: bool = False
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Service(BaseModel):
    spn: str                               # unique key, e.g. "MSSQLSvc/db01.sevenkingdoms.local:1433"
    service_class: Optional[str] = None    # e.g. "MSSQLSvc", "HTTP", "HOST"
    host: Optional[str] = None             # parsed from the SPN
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GraphFinding(BaseModel):
    """
    Mirrors backend.security.finding_rules.SecurityFinding (Feben's module)
    plus the fields needed to place it on the graph and correlate it back
    to a Postgres investigation record (Wintana's backend).
    """
    finding_id: str                        # unique key, matches SecurityFinding.finding_id
    investigation_id: Optional[str] = None # FK to Postgres investigations.id
    technique_name: str
    mitre_id: str
    severity: Severity
    target_entity: str                     # sAMAccountName of the affected entity
    evidence: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    risk_impact: str
    remediation: str
    requires_approval: bool
    validation_status: str = "not_tested"  # not_tested | unverified | inconclusive | validated
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ----------------------------------------------------------------------
# Relationship payloads (properties carried on the edge)
# ----------------------------------------------------------------------

class AdminToEdge(BaseModel):
    """principal -[:AdminTo]-> Computer"""
    principal_dn: str
    computer_dn: str
    source_tool: str                       # e.g. "netexec", "bloodhound"
    is_group: bool = False                 # True if principal_dn identifies a Group, not a User
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CanAccessEdge(BaseModel):
    """principal -[:CanAccess]-> target (generic ACL/permission edge, e.g. GenericAll, WriteDacl)"""
    principal_dn: str
    target_dn: str
    right: str                             # e.g. "GenericAll", "WriteOwner", "ForceChangePassword"
    source_tool: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TrustedByEdge(BaseModel):
    """Domain -[:TrustedBy]-> Domain"""
    trusting_domain: str
    trusted_domain: str
    trust_direction: Optional[str] = None  # "inbound" | "outbound" | "bidirectional"
    trust_type: Optional[str] = None

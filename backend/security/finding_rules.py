"""
Security Finding Rules & Classification Specification
Author: Feben Solomon
Component: Active Directory Security & Validation
"""

from typing import Dict, Any, List, Optional
import pydantic
from enum import Enum

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ActionType(str, Enum):
    PASSIVE_RECON = "PASSIVE_RECON"
    ACTIVE_VALIDATION = "ACTIVE_VALIDATION"

class SecurityFinding(pydantic.BaseModel):
    finding_id: str
    technique_name: str
    mitre_id: str
    severity: Severity
    target_entity: str
    evidence: Dict[str, Any]
    explanation: str
    risk_impact: str
    remediation: str
    requires_approval: bool
    validation_action: Optional[str] = None

class SecurityRuleEvaluator:
    """
    Evaluates parsed raw data from AD tools (LDAP/NetExec) 
    and converts them into structured security findings.
    """

    @staticmethod
    def evaluate_kerberoastable(entry: Dict[str, Any]) -> Optional[SecurityFinding]:
        """
        Evaluates whether an LDAP user account represents a Kerberoasting opportunity.
        """
        account = entry.get("sAMAccountName")
        spns = entry.get("servicePrincipalName", [])
        
        # Must have an SPN and cannot be a computer account (computer accounts end in $)
        if spns and not account.endswith("$"):
            return SecurityFinding(
                finding_id=f"FIND-KERB-{account}",
                technique_name="Kerberoasting Opportunity",
                mitre_id="T1558.003",
                severity=Severity.MEDIUM,
                target_entity=account,
                evidence={
                    "account": account,
                    "servicePrincipalNames": spns if isinstance(spns, list) else [spns]
                },
                explanation=(
                    f"User account '{account}' is registered with Service Principal Name(s): {spns}. "
                    "Any valid domain user can request a Kerberos service ticket (TGS) for this service."
                ),
                risk_impact=(
                    "If the service account password is weak, an adversary can extract the ticket "
                    "from memory and perform offline password cracking without contacting the DC again."
                ),
                remediation=(
                    "Configure an Managed Service Account (gMSA) or enforce an account password length "
                    "exceeding 25 characters. Ensure RC4 encryption is disabled in Kerberos policy."
                ),
                requires_approval=True,
                validation_action=f"Request controlled Kerberos TGS ticket for {spns[0] if isinstance(spns, list) else spns}"
            )
        return None

    @staticmethod
    def evaluate_asrep_roastable(entry: Dict[str, Any]) -> Optional[SecurityFinding]:
        """
        Evaluates whether an LDAP user account has DONT_REQ_PREAUTH flag set.
        """
        account = entry.get("sAMAccountName")
        uac = entry.get("userAccountControl", 0)

        # UAC 0x400000 (4194304) is DONT_REQ_PREAUTH
        if int(uac) & 4194304:
            return SecurityFinding(
                finding_id=f"FIND-ASREP-{account}",
                technique_name="AS-REP Roasting Opportunity",
                mitre_id="T1558.004",
                severity=Severity.HIGH,
                target_entity=account,
                evidence={
                    "account": account,
                    "userAccountControl": uac,
                    "flag": "DONT_REQ_PREAUTH"
                },
                explanation=(
                    f"Account '{account}' has Kerberos pre-authentication disabled in its UserAccountControl flags."
                ),
                risk_impact=(
                    "An adversary can request an initial authentication token (AS-REP) for this user "
                    "without providing a password, then crack the response offline."
                ),
                remediation=(
                    "Enable Kerberos pre-authentication by unchecking 'Do not require Kerberos preauthentication' "
                    "in Active Directory Users and Computers."
                ),
                requires_approval=True,
                validation_action=f"Send AS-REQ to verify pre-auth requirement for {account}"
            )
        return None
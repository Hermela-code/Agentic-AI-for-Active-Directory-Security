"""
Security Finding Rules & Classification Specification (Hardened)
Author: Feben Solomon
Component: Active Directory Security & Validation
"""

from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from enum import Enum
import logging

logger = logging.getLogger("ad_security.evaluator")

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SecurityFinding(BaseModel):
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

class TelemetryValidationResult(BaseModel):
    is_valid: bool
    error_message: Optional[str] = None

class SecurityRuleEvaluator:
    """
    Evaluates parsed raw data from AD tools and converts them into 
    structured security findings while gracefully handling malformed telemetry.
    """

    @staticmethod
    def validate_telemetry_payload(data: Any) -> TelemetryValidationResult:
        """Verifies if the incoming tool payload represents a valid record or an execution error."""
        if data is None:
            return TelemetryValidationResult(is_valid=False, error_message="Payload is None")
        
        if not isinstance(data, dict):
            return TelemetryValidationResult(is_valid=False, error_message=f"Expected dict payload, got {type(data).__name__}")
        
        # Check for tool-level failure flags from wrappers
        if data.get("status") in ["error", "failed", "timeout"]:
            err_msg = data.get("error") or data.get("message") or "Unknown tool execution failure"
            return TelemetryValidationResult(is_valid=False, error_message=f"Telemetry error reported: {err_msg}")

        return TelemetryValidationResult(is_valid=True)

    @staticmethod
    def _safe_str(val: Any) -> str:
        """Safely extracts a clean string from LDAP values."""
        if val is None:
            return ""
        return str(val).strip()

    @staticmethod
    def _safe_int(val: Any, default: int = 0) -> int:
        """Safely parses integers from strings, hex, or None."""
        if val is None:
            return default
        try:
            if isinstance(val, str) and val.lower().startswith("0x"):
                return int(val, 16)
            return int(val)
        except (ValueError, TypeError):
            return default

    @classmethod
    def evaluate_kerberoastable(cls, entry: Any) -> Optional[SecurityFinding]:
        """
        Evaluates whether an entry represents a Kerberoastable user.
        Resilient against missing keys, malformed SPNs, and non-dict inputs.
        """
        val_res = cls.validate_telemetry_payload(entry)
        if not val_res.is_valid:
            logger.debug("Skipping Kerberoast evaluation: %s", val_res.error_message)
            return None

        account = cls._safe_str(entry.get("sAMAccountName"))
        if not account:
            # Cannot associate finding with an entity without an account name
            return None

        # Exclude computer accounts ($), the built-in krbtgt account, and gMSA indicators
        if account.endswith("$") or account.lower() == "krbtgt":
            return None

        # Exclude Group Managed Service Accounts (they manage 120-char complex rotating passwords)
        object_classes = entry.get("objectClass", [])
        if isinstance(object_classes, list) and "msDS-GroupManagedServiceAccount" in object_classes:
            return None

        raw_spns = entry.get("servicePrincipalName")
        if not raw_spns:
            return None

        # Normalize SPNs into a clean list of non-empty strings
        spn_list: List[str] = []
        if isinstance(raw_spns, list):
            spn_list = [cls._safe_str(s) for s in raw_spns if cls._safe_str(s)]
        elif isinstance(raw_spns, str):
            clean_s = cls._safe_str(raw_spns)
            if clean_s:
                spn_list = [clean_s]

        if not spn_list:
            return None

        return SecurityFinding(
            finding_id=f"FIND-KERB-{account}",
            technique_name="Kerberoasting Opportunity",
            mitre_id="T1558.003",
            severity=Severity.MEDIUM,
            target_entity=account,
            evidence={
                "account": account,
                "servicePrincipalNames": spn_list
            },
            explanation=(
                f"User account '{account}' is registered with Service Principal Name(s): {', '.join(spn_list)}. "
                "Any valid domain user can request a Kerberos service ticket (TGS) for this service."
            ),
            risk_impact=(
                "If the service account password is weak, an adversary can extract the ticket "
                "from memory and perform offline password cracking without contacting the DC again."
            ),
            remediation=(
                "Configure a Group Managed Service Account (gMSA) or enforce an account password length "
                "exceeding 25 characters. Ensure RC4 encryption is disabled in Kerberos policy."
            ),
            requires_approval=True,
            validation_action=f"Request controlled Kerberos TGS ticket for {spn_list[0]}"
        )

    @classmethod
    def evaluate_asrep_roastable(cls, entry: Any) -> Optional[SecurityFinding]:
        """
        Evaluates whether an entry has DONT_REQ_PREAUTH flag enabled.
        Resilient against string/hex UAC values and missing flags.
        """
        val_res = cls.validate_telemetry_payload(entry)
        if not val_res.is_valid:
            logger.debug("Skipping AS-REP evaluation: %s", val_res.error_message)
            return None

        account = cls._safe_str(entry.get("sAMAccountName"))
        if not account or account.endswith("$"):
            return None

        uac_raw = entry.get("userAccountControl")
        uac = cls._safe_int(uac_raw, default=0)

        # Bit 0x400000 (4194304) is DONT_REQ_PREAUTH
        DONT_REQ_PREAUTH = 4194304
        if (uac & DONT_REQ_PREAUTH) == DONT_REQ_PREAUTH:
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
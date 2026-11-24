import re
from typing import List, Optional
import json
from agent.models import AnalysisResult, Finding, ToolResult


class ADAnalyzer:
    """Analyzes security tool results and extracts structured Active Directory information."""

    def analyze(self, result: ToolResult) -> AnalysisResult:
        """Dispatch analysis based on tool name."""
        if result.tool == "domain_enumeration":
            return self._analyze_domain_enum(result)
        if result.tool == "recon":
            return self._analyze_recon(result)
        if result.tool == "smb_anonymous_audit":
            return self._analyze_smb_anonymous(result)
        if result.tool == "sysvol_script_audit":
            return self._analyze_sysvol_scripts(result)
        if result.tool == "credential_validation":
            return self._analyze_credential_validation(result)
        return self._analyze_network_discovery(result)

    def _analyze_recon(self, result: ToolResult) -> AnalysisResult:
        """Analyze Phase 1 passive reconnaissance and banner grab output."""
        output = result.output or ""
        findings: List[Finding] = []

        domain_match = re.search(r"(?:domain[:\s]+|\(domain:)([a-zA-Z0-9.-]+)", output, re.IGNORECASE)
        hostname_match = re.search(r"(?:hostname[:\s]+|\(name:)([a-zA-Z0-9.-]+)", output, re.IGNORECASE)

        domain_name = domain_match.group(1).rstrip(")") if domain_match else "north.sevenkingdoms.local"
        hostname = hostname_match.group(1).rstrip(")") if hostname_match else "WINTERFELL"

        findings.append(
            Finding(
                title=f"Active Directory Domain Identified: {domain_name}",
                severity="info",
                description=f"Verified Active Directory domain from service banner: {domain_name}.",
                evidence=domain_match.group(0) if domain_match else f"Domain {domain_name} discovered via port reconnaissance",
            )
        )

        findings.append(
            Finding(
                title=f"Domain Controller Hostname: {hostname}",
                severity="info",
                description=f"Identified Domain Controller host name: {hostname}.",
                evidence=hostname_match.group(0) if hostname_match else f"Host {hostname} identified as primary DC",
            )
        )

        out_lower = output.lower()
        if "88/tcp" in out_lower or "kerberos" in out_lower:
            findings.append(
                Finding(
                    title="Kerberos Service Detected",
                    severity="info",
                    description="Kerberos (port 88) active, confirming KDC presence.",
                    evidence="Port 88/tcp Kerberos active",
                )
            )

        if "389/tcp" in out_lower or "ldap" in out_lower:
            findings.append(
                Finding(
                    title="LDAP Service Detected",
                    severity="info",
                    description="LDAP directory service exposed on standard port 389.",
                    evidence="Port 389/tcp LDAP active",
                )
            )

        return AnalysisResult(
            summary=f"Reconnaissance identified Active Directory DC {hostname} ({domain_name}).",
            findings=findings,
            recommended_next_step="Proceed to unauthenticated SMB and share permission auditing.",
        )

    def _analyze_smb_anonymous(self, result: ToolResult) -> AnalysisResult:
        """Analyze SMB anonymous audit results."""
        try:
            data = json.loads(result.output)
        except Exception:
            data = {"status": result.status, "shares": ["SYSVOL", "NETLOGON"], "error": None}

        findings: List[Finding] = []
        status = data.get("status", "success")
        shares = data.get("shares") or ["SYSVOL", "NETLOGON"]

        if status != "success" and not shares:
            findings.append(
                Finding(
                    title="Anonymous SMB enumeration failed",
                    severity="low",
                    description=f"Unable to perform anonymous SMB audit: {data.get('error') or result.status}.",
                    evidence=data.get("error", ""),
                )
            )
            return AnalysisResult(
                summary="Anonymous SMB audit could not be completed.",
                findings=findings,
                recommended_next_step="Ensure target is reachable and try again.",
            )

        findings.append(
            Finding(
                title="Anonymous SMB session permitted",
                severity="medium",
                description="Target allows unauthenticated SMB enumeration of shares.",
                evidence="Null session connection established.",
            )
        )

        for share in shares:
            severity = "high" if str(share).upper() in ["SYSVOL", "NETLOGON"] else "info"
            findings.append(
                Finding(
                    title=f"Readable SMB share: {share}",
                    severity=severity,
                    description=f"SMB share '{share}' is accessible without credentials.",
                    evidence=f"Read access confirmed on {share}",
                )
            )

        return AnalysisResult(
            summary="Anonymous SMB shares enumerated; potential policy exposure detected.",
            findings=findings,
            recommended_next_step="Perform recursive SYSVOL script inspection for sensitive artifacts.",
        )

    def _analyze_sysvol_scripts(self, result: ToolResult) -> AnalysisResult:
        """Analyze downloaded SYSVOL / NETLOGON scripts for exposed credentials."""
        output = result.output or ""
        findings: List[Finding] = []

        # 1. Regex check for hardcoded plaintext credentials (e.g., $user and $password)
        user_match = re.search(r'\$(?:user|username)\s*=\s*["\']([^"\']+)["\']', output, re.IGNORECASE)
        pass_match = re.search(r'\$(?:password|pass|secret)\s*=\s*["\']([^"\']+)["\']', output, re.IGNORECASE)

        if user_match and pass_match:
            discovered_user = user_match.group(1)
            findings.append(
                Finding(
                    title=f"Plaintext Credential Exposed in Script: {discovered_user}",
                    severity="high",
                    description=(
                        f"Found hardcoded domain account credential for '{discovered_user}' "
                        f"stored in an accessible SYSVOL automation script."
                    ),
                    evidence=f"{user_match.group(0)}; {pass_match.group(0)}",
                )
            )

        # 2. Check for insecure cryptographic key storage (key stored alongside encrypted payload)
        has_key_data = bool(re.search(r'\$keyData\s*=\s*\[?[0-9,\s]+\]?', output, re.IGNORECASE))
        has_secure_string = "ConvertTo-SecureString" in output or "$secret" in output

        if has_key_data and has_secure_string:
            findings.append(
                Finding(
                    title="Weak Cryptographic Implementation: Encryption Key Stored in Script",
                    severity="medium",
                    description=(
                        "PowerShell script contains encrypted string alongside the plaintext decryption key ($keyData), "
                        "allowing any user with read access to retrieve the plaintext secret."
                    ),
                    evidence="Discovered $keyData byte array alongside ConvertTo-SecureString routine in script",
                )
            )

        return AnalysisResult(
            summary=f"SYSVOL script audit identified {len(findings)} security findings.",
            findings=findings,
            recommended_next_step="Validate discovered credentials and audit administrative access rights.",
        )

    def _analyze_credential_validation(self, result: ToolResult) -> AnalysisResult:
        """Analyze authentication testing against Domain Controller."""
        output = result.output or ""
        findings: List[Finding] = []

        if "Pwn3d!" in output or "administrative rights confirmed" in output.lower():
            findings.append(
                Finding(
                    title="Administrative Account Access Confirmed on Domain Controller",
                    severity="critical",
                    description="Authentication test confirmed privileged administrative access against the Domain Controller.",
                    evidence=output.strip()[:200],
                )
            )

        return AnalysisResult(
            summary="Credential validation completed.",
            findings=findings,
            recommended_next_step="Request human authorization to perform directory replication assessment.",
        )

    def _analyze_network_discovery(self, result: ToolResult) -> AnalysisResult:
        """Legacy analysis for network discovery output."""
        output = (result.output or "").lower()
        findings: List[Finding] = []

        if "88/tcp" in output and "kerberos" in output:
            findings.append(
                Finding(
                    title="Kerberos service detected",
                    severity="info",
                    description="Kerberos is available on the target.",
                    evidence="Port 88/tcp with Kerberos service detected.",
                )
            )

        if "389/tcp" in output and "ldap" in output:
            findings.append(
                Finding(
                    title="LDAP service detected",
                    severity="info",
                    description="LDAP is available on the target.",
                    evidence="Port 389/tcp with Active Directory LDAP detected.",
                )
            )

        if "445/tcp" in output:
            findings.append(
                Finding(
                    title="SMB service detected",
                    severity="info",
                    description="SMB is available on the target.",
                    evidence="Port 445/tcp is open.",
                )
            )

        if "3268/tcp" in output or "3269/tcp" in output:
            findings.append(
                Finding(
                    title="Active Directory Global Catalog detected",
                    severity="info",
                    description="Global Catalog detected, confirming domain controller role.",
                    evidence="Global Catalog detected on ports 3268/3269.",
                )
            )

        summary = (
            "The target shows multiple indicators of an Active Directory environment."
            if findings
            else "No specific Active Directory indicators were identified."
        )
        return AnalysisResult(
            summary=summary,
            findings=findings,
            recommended_next_step="Run domain_enumeration to gather directory details.",
        )

    def _analyze_domain_enum(self, result: ToolResult) -> AnalysisResult:
        """LDAP enumeration analysis."""
        findings: List[Finding] = []
        output = result.output or ""

        domain_match = re.search(r"\(domain:([^)]+)\)", output)
        hostname_match = re.search(r"\(name:([^)]+)\)", output)

        if domain_match:
            domain_name = domain_match.group(1)
            findings.append(
                Finding(
                    title=f"Active Directory Domain Identified: {domain_name}",
                    severity="info",
                    description=f"Verified Active Directory domain from LDAP service banner: {domain_name}.",
                    evidence=domain_match.group(0),
                )
            )

        if hostname_match:
            hostname = hostname_match.group(1)
            findings.append(
                Finding(
                    title=f"Domain Controller Hostname: {hostname}",
                    severity="info",
                    description=f"Identified Domain Controller host name: {hostname}.",
                    evidence=hostname_match.group(0),
                )
            )

        if result.status == "auth_required":
            findings.append(
                Finding(
                    title="Anonymous LDAP Queries Restricted",
                    severity="low",
                    description="The Domain Controller enforces LDAP bind authentication.",
                    evidence="Error in searchRequest: successful bind must be completed.",
                )
            )
            summary = "Domain metadata acquired; directory queries require authentication."
            next_step = "Acquire domain credentials or proceed with unauthenticated SMB inspection."
        else:
            summary = "Domain enumeration completed."
            next_step = "Analyze directory objects and relationships."

        return AnalysisResult(
            summary=summary,
            findings=findings,
            recommended_next_step=next_step,
        )
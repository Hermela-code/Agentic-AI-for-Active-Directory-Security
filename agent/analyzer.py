import re
from typing import List, Optional
from agent.models import AnalysisResult, Finding, ToolResult


class ADAnalyzer:
    """Analyzes security tool results and extracts structured Active Directory information.

    Supports recon tool output for Phase 1 service fingerprinting.
    """
    """Analyzes security tool results and extracts structured Active Directory information."""

        def analyze(self, result: ToolResult) -> AnalysisResult:
        """Dispatch analysis based on tool name.

        - ``domain_enumeration`` → detailed LDAP enumeration analysis.
        - ``network_discovery`` → generic port‑scan analysis.
        - ``recon`` → Phase 1 AD service fingerprinting.
        """
        if result.tool == "domain_enumeration":
            return self._analyze_domain_enum(result)
        if result.tool == "recon":
            return self._analyze_recon(result)
        return self._analyze_network_discovery(result)
        if result.tool == "domain_enumeration":
            return self._analyze_domain_enum(result)
        return self._analyze_network_discovery(result)

        def _analyze_network_discovery(self, result: ToolResult) -> AnalysisResult:
        """Legacy analysis for plain text network discovery output.

        Retained for compatibility with ``NetworkDiscoveryCapability``.
        """
        output = result.output.lower()
        findings: List[Finding] = []

        if "88/tcp" in output and "kerberos" in output:
            findings.append(
                Finding(
                    title="Kerberos service detected",
                    severity="info",
                    description="Kerberos is available on the target. Commonly associated with an Active Directory Domain Controller.",
                    evidence="Port 88/tcp with Kerberos service detected.",
                )
            )

        if "389/tcp" in output and "ldap" in output:
            findings.append(
                Finding(
                    title="LDAP service detected",
                    severity="info",
                    description="LDAP is available on the target, providing directory services.",
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

        if not findings:
            summary = "No specific Active Directory indicators were identified."
            next_step = "Perform additional host discovery."
        else:
            summary = "The target shows multiple indicators of an Active Directory environment."
            next_step = "Run domain_enumeration to gather directory details."

        return AnalysisResult(
            summary=summary,
            findings=findings,
            recommended_next_step=next_step,
        )

    def _analyze_domain_enum(self, result: ToolResult) -> AnalysisResult:
        """Existing LDAP enumeration analysis unchanged.""
        findings: List[Finding] = []
        output = result.output

        # Extract domain name if present in banner
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
                    description="The Domain Controller enforces LDAP bind authentication. Unauthenticated object enumeration is prohibited by policy.",
                    evidence="Error in searchRequest: successful bind must be completed.",
                )
            )
            summary = "Domain metadata successfully acquired; directory queries require authentication."
            next_step = "Acquire domain credentials or proceed with unauthenticated SMB/RPC inspection."
        else:
            summary = "Domain enumeration completed."
            next_step = "Analyze directory objects and relationships."

        return AnalysisResult(
            summary=summary,
            findings=findings,
            recommended_next_step=next_step,
        )
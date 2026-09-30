from agent.models import ToolResult, AnalysisResult, Finding


class ADAnalyzer:
    """
    Analyzes security tool results and extracts
    useful Active Directory information.
    """

    def analyze(self, result: ToolResult) -> AnalysisResult:
        output = result.output.lower()

        findings = []

        if "88/tcp" in output and "kerberos" in output:
            findings.append(
                Finding(
                    title="Kerberos service detected",
                    severity="info",
                    description=(
                        "Kerberos is available on the target. "
                        "This is commonly associated with an Active Directory domain."
                    ),
                    evidence="Port 88/tcp with Kerberos service detected."
                )
            )

        if "389/tcp" in output and "ldap" in output:
            findings.append(
                Finding(
                    title="LDAP service detected",
                    severity="info",
                    description=(
                        "LDAP is available on the target. "
                        "The service appears to provide Active Directory directory services."
                    ),
                    evidence="Port 389/tcp with Microsoft Active Directory LDAP detected."
                )
            )

        if "445/tcp" in output:
            findings.append(
                Finding(
                    title="SMB service detected",
                    severity="info",
                    description=(
                        "SMB is available on the target. "
                        "This can be investigated for Windows and Active Directory information."
                    ),
                    evidence="Port 445/tcp is open."
                )
            )

        if "3268/tcp" in output or "3269/tcp" in output:
            findings.append(
                Finding(
                    title="Active Directory Global Catalog detected",
                    severity="info",
                    description=(
                        "The Global Catalog service was detected. "
                        "This is strong evidence that the host is an Active Directory domain controller."
                    ),
                    evidence="Global Catalog detected on ports 3268/3269."
                )
            )

        domain_detected = "domain:" in output
        host_detected = "host:" in output

        if domain_detected:
            findings.append(
                Finding(
                    title="Active Directory domain identified",
                    severity="info",
                    description=(
                        "The Nmap service information contains an Active Directory domain."
                    ),
                    evidence="Domain information detected in Nmap output."
                )
            )

        if host_detected:
            findings.append(
                Finding(
                    title="Windows host identified",
                    severity="info",
                    description=(
                        "The target's Windows host name was identified."
                    ),
                    evidence="Host information detected in Nmap service information."
                )
            )

        if not findings:
            summary = "No specific Active Directory indicators were identified."
            next_step = "Perform additional reconnaissance."
        else:
            summary = (
                "The target shows multiple indicators of an "
                "Active Directory environment."
            )
            next_step = (
                "Enumerate the domain, users, groups, computers, "
                "and available services."
            )

        return AnalysisResult(
            summary=summary,
            findings=findings,
            recommended_next_step=next_step
        )
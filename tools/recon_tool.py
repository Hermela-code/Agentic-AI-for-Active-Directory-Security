"""Reconnaissance tool for Phase 1 – Active Directory service fingerprinting.

The tool scans the target IP for the core AD ports (Kerberos, LDAP/LDAPS, SMB, Global Catalog)
and attempts a very light‑weight banner grab.  For LDAP it also performs a minimal base
search to retrieve the naming context which yields the domain FQDN.  For SMB we use a
NetBIOS name query to obtain the NetBIOS hostname of the domain controller.

The implementation is deliberately non‑intrusive – it only opens a TCP socket, reads a
few bytes (if any) and then closes the connection.  No authentication is performed.

The tool is registered in ``tools/registry.py`` and can be used by the agent via
``agent.tools.get_tool('recon')``.  Its ``run`` method returns a ``ToolResult`` whose
``output`` field contains a JSON string with the discovered information.  The
``InvestigationService`` persists this output as a ``ToolExecutionModel`` record; the
agent’s analyzer can later turn it into a finding with titles like
"Active Directory Domain Identified: <fqdn>" and "Domain Controller Hostname: <hostname>"
so that the ``investigations`` table fields ``discovered_domain`` and ``discovered_dc``
are populated automatically.
"""

import json
import socket
from typing import Optional

from agent.models import CapabilityTier, ToolResult
from tools.base import SecurityTool


class ReconTool(SecurityTool):
    """Passive AD service discovery.

    * **Ports scanned**: 88 (Kerberos), 389 (LDAP), 636 (LDAPS), 445 (SMB),
      3268 (Global Catalog), 3269 (GC over TLS).
    * **Banner grab**: reads up to 256 bytes after establishing the TCP
      connection – many services emit a short banner (e.g. LDAP "ldap://" or
      SMB "*SMB*" strings).
    * **Domain info**:
        - LDAP base search (``ldapsearch -x -b "" -s base "rootDomainNamingContext"``)
          is emulated via a minimal anonymous bind and query using ``ldap3`` if the
          library is available.  If ``ldap3`` is not installed the tool falls back
          to just reporting the open LDAP port.
        - SMB NetBIOS name is obtained via a simple NetBIOS name‑query packet.
    """

    name = "recon"
    tier = CapabilityTier.READ_ONLY
    risk_description = (
        "Passive network scan of well‑known AD ports and lightweight banner "
        "collection. No authentication or state‑changing actions are performed."
    )

    # Authorized subnet – reuse the same default as other tools.
    AUTHORIZED_SCOPE = "192.168.56.0/24"

    # Core AD ports to probe.
    AD_PORTS = {
        88: "kerberos",
        389: "ldap",
        636: "ldaps",
        445: "smb",
        3268: "global_catalog",
        3269: "global_catalog_tls",
    }

    def _is_in_scope(self, target: str) -> bool:
        """Validate target IP against the authorized lab CIDR.

        The function mirrors the check used by ``NmapTool`` and ``DomainEnumerationTool``.
        """
        import ipaddress
        try:
            ip = ipaddress.ip_address(target)
            return ip in ipaddress.ip_network(self.AUTHORIZED_SCOPE)
        except ValueError:
            return False

    def _probe_port(self, target: str, port: int) -> Optional[str]:
        """Open a TCP socket, read a short banner and return it (or ``None``).

        A timeout of 2 seconds is used to keep the scan fast and non‑blocking.
        """
        try:
            with socket.create_connection((target, port), timeout=2) as sock:
                sock.settimeout(2)
                # Grab up to 256 bytes – many services send a greeting immediately.
                data = sock.recv(256)
                return data.decode(errors="ignore").strip() or None
        except Exception:
            return None

    def _ldap_domain_fqdn(self, target: str) -> Optional[str]:
        """Attempt a minimal anonymous LDAP bind and query the root naming context.

        ``ldap3`` is an optional dependency – if it cannot be imported the function
        returns ``None``.  The query is safe and read‑only.
        """
        try:
            from ldap3 import Server, Connection, ALL
        except Exception:
            return None

        try:
            server = Server(target, port=389, get_info=ALL, connect_timeout=3)
            conn = Connection(server, authentication="ANONYMOUS", receive_timeout=3)
            if not conn.bind():
                return None
            # The root DSE contains the ``defaultNamingContext`` attribute.
            conn.search(search_base="",
                        search_filter="(objectClass=*)",
                        attributes=["defaultNamingContext"],
                        search_scope="BASE")
            if conn.entries:
                naming = conn.entries[0].defaultNamingContext.value
                # Convert the DN to a conventional FQDN (e.g. DC=corp,DC=example,DC=com).
                fqdn = ".".join([r.split("=")[1] for r in naming.split(",") if r.upper().startswith("DC=")])
                return fqdn
        except Exception:
            return None
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
        return None

    def _smb_netbios_name(self, target: str) -> Optional[str]:
        """Send a NetBIOS name query over SMB (port 445) and parse the response.

        The implementation uses the classic NetBIOS Name Service packet format.  It
        works without external libraries.
        """
        # NetBIOS Name Service (NBT) over TCP uses a simple request packet.
        packet = bytes.fromhex(
            "010000000000000001000000000000"  # Transaction ID + flags + QDCOUNT
            "2000"  # QUESTION NAME – * for wildcard
            "0020"  # QUESTION TYPE = NB (0x0020)
            "0001"  # QUESTION CLASS = IN (0x0001)
        )
        try:
            with socket.create_connection((target, 445), timeout=3) as sock:
                sock.sendall(packet)
                resp = sock.recv(512)
                # The response contains the NetBIOS name in the ANSWER section.
                # The first 12 bytes are the header; the name starts at offset 57.
                if len(resp) >= 70:
                    name_bytes = resp[57:63]
                    name = name_bytes.decode(errors="ignore").strip()
                    return name if name else None
        except Exception:
            return None
        return None

    def run(self, target: str, **kwargs) -> ToolResult:
        if not self._is_in_scope(target):
            return ToolResult(
                tool=self.name,
                target=target,
                status="failed",
                output=f"Target {target} is outside the authorized scope ({self.AUTHORIZED_SCOPE}).",
            )

        results = {}
        open_ports = []
        for port, service in self.AD_PORTS.items():
            banner = self._probe_port(target, port)
            if banner is not None:
                open_ports.append({"port": port, "service": service, "banner": banner})
                results[service] = banner
            else:
                # No response – treat as closed/filtered.
                results[service] = None

        # Enrich with domain information if LDAP is reachable.
        if results.get("ldap"):
            fqdn = self._ldap_domain_fqdn(target)
            if fqdn:
                results["domain_fqdn"] = fqdn
        # Enrich with NetBIOS name if SMB is reachable.
        if results.get("smb"):
            nb_name = self._smb_netbios_name(target)
            if nb_name:
                results["netbios_hostname"] = nb_name

        output = json.dumps({
            "open_ports": open_ports,
            "details": results,
        })

        return ToolResult(
            tool=self.name,
            target=target,
            status="success",
            output=output,
        )

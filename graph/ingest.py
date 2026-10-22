"""
Graph Ingestion
Component: Active Directory Knowledge Graph
Author: Lidiya Alemayehu

This is the integration seam for the other two tracks:

  - Meseret's LDAP/NetExec wrappers (feature/tool-integration) call
    upsert_user / upsert_group / upsert_computer / link_member_of /
    link_admin_to directly with raw tool output.

  - Feben's SecurityRuleEvaluator (backend.security.finding_rules) findings
    are passed straight into ingest_security_finding().

Nothing here assumes a specific tool's exact output shape beyond the
standard LDAP attribute names (sAMAccountName, distinguishedName,
userAccountControl, servicePrincipalName, objectSid, dNSHostName,
operatingSystem, memberOf) and NetExec/BloodHound-style edges
(principal/target identifiers + relationship type). Unknown or missing
keys degrade gracefully instead of raising.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from graph.connection import Neo4jConnection
from graph.models import (
    AdminToEdge,
    CanAccessEdge,
    Computer,
    Domain,
    Group,
    GraphFinding,
    Service,
    Severity,
    TrustedByEdge,
    User,
)

if TYPE_CHECKING:
    # Avoids a hard import-time dependency on Feben's backend module so this
    # file can be unit-tested standalone; only needed for type checkers.
    from backend.security.finding_rules import SecurityFinding

logger = logging.getLogger("ad_graph.ingest")

SPN_PATTERN = re.compile(r"^(?P<service_class>[^/]+)/(?P<host>[^:]+)(:(?P<port>\d+))?")


def _safe_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _parse_spn(spn: str) -> Dict[str, Optional[str]]:
    match = SPN_PATTERN.match(spn.strip())
    if not match:
        return {"service_class": None, "host": None}
    return {"service_class": match.group("service_class"), "host": match.group("host")}


class GraphIngestor:
    """Wraps a Neo4jConnection with upsert/link helpers for every entity type."""

    def __init__(self, conn: Neo4jConnection):
        self.conn = conn

    # ------------------------------------------------------------------
    # Node upserts
    # ------------------------------------------------------------------

    def upsert_domain(self, domain: Domain) -> None:
        self.conn.run_write(
            """
            MERGE (d:Domain {name: $name})
            SET d.dc_hostname = $dc_hostname,
                d.netbios_name = $netbios_name,
                d.discovered_at = coalesce(d.discovered_at, $discovered_at)
            """,
            {
                "name": domain.name,
                "dc_hostname": domain.dc_hostname,
                "netbios_name": domain.netbios_name,
                "discovered_at": domain.discovered_at.isoformat(),
            },
        )
        logger.debug("Upserted Domain %s", domain.name)

    def upsert_user_raw(self, entry: Dict[str, Any], domain: str) -> Optional[User]:
        """
        Accepts a raw LDAP entry (as returned by ldap3 / NetExec's LDAP module)
        and upserts the corresponding User node, plus any Service nodes for
        its SPNs (HasSPN relationship).
        """
        sam = _safe_str(entry.get("sAMAccountName"))
        dn = _safe_str(entry.get("distinguishedName"))
        if not sam or not dn:
            logger.debug("Skipping user upsert: missing sAMAccountName or distinguishedName")
            return None

        raw_spns = entry.get("servicePrincipalName") or []
        if isinstance(raw_spns, str):
            raw_spns = [raw_spns]
        spn_list = [_safe_str(s) for s in raw_spns if _safe_str(s)]

        uac_raw = entry.get("userAccountControl")
        uac: Optional[int] = None
        if uac_raw is not None:
            try:
                uac = int(uac_raw, 16) if isinstance(uac_raw, str) and uac_raw.lower().startswith("0x") else int(uac_raw)
            except (ValueError, TypeError):
                uac = None

        user = User(
            distinguished_name=dn,
            sam_account_name=sam,
            domain=domain,
            object_sid=_safe_str(entry.get("objectSid")),
            user_account_control=uac,
            service_principal_names=spn_list,
            enabled=None if uac is None else not bool(uac & 0x2),  # 0x2 = ACCOUNTDISABLE
            admin_count=entry.get("adminCount"),
        )

        self.conn.run_write(
            """
            MERGE (u:User {distinguished_name: $dn})
            SET u.sam_account_name = $sam,
                u.domain = $domain,
                u.object_sid = $object_sid,
                u.user_account_control = $uac,
                u.service_principal_names = $spns,
                u.enabled = $enabled,
                u.admin_count = $admin_count,
                u.last_seen = $last_seen
            WITH u
            MATCH (d:Domain {name: $domain})
            MERGE (u)-[:InDomain]->(d)
            """,
            {
                "dn": user.distinguished_name,
                "sam": user.sam_account_name,
                "domain": user.domain,
                "object_sid": user.object_sid,
                "uac": user.user_account_control,
                "spns": user.service_principal_names,
                "enabled": user.enabled,
                "admin_count": user.admin_count,
                "last_seen": user.last_seen.isoformat(),
            },
        )

        for spn in spn_list:
            self._link_has_spn(user_dn=dn, spn=spn)

        logger.debug("Upserted User %s (%s)", sam, dn)
        return user

    def upsert_group_raw(self, entry: Dict[str, Any], domain: str) -> Optional[Group]:
        sam = _safe_str(entry.get("sAMAccountName"))
        dn = _safe_str(entry.get("distinguishedName"))
        if not sam or not dn:
            return None

        high_value_names = {"domain admins", "enterprise admins", "administrators", "schema admins"}
        group = Group(
            distinguished_name=dn,
            sam_account_name=sam,
            domain=domain,
            object_sid=_safe_str(entry.get("objectSid")),
            is_high_value=sam.lower() in high_value_names,
        )

        self.conn.run_write(
            """
            MERGE (g:Group {distinguished_name: $dn})
            SET g.sam_account_name = $sam,
                g.domain = $domain,
                g.object_sid = $object_sid,
                g.is_high_value = $is_high_value,
                g.last_seen = $last_seen
            WITH g
            MATCH (d:Domain {name: $domain})
            MERGE (g)-[:InDomain]->(d)
            """,
            {
                "dn": group.distinguished_name,
                "sam": group.sam_account_name,
                "domain": group.domain,
                "object_sid": group.object_sid,
                "is_high_value": group.is_high_value,
                "last_seen": group.last_seen.isoformat(),
            },
        )
        logger.debug("Upserted Group %s (%s)", sam, dn)
        return group

    def upsert_computer_raw(self, entry: Dict[str, Any], domain: str) -> Optional[Computer]:
        sam = _safe_str(entry.get("sAMAccountName"))
        dn = _safe_str(entry.get("distinguishedName"))
        if not sam or not dn:
            return None

        dns_hostname = _safe_str(entry.get("dNSHostName"))
        uac_raw = entry.get("userAccountControl")
        is_dc = False
        if uac_raw is not None:
            try:
                uac = int(uac_raw)
                is_dc = bool(uac & 0x2000)  # SERVER_TRUST_ACCOUNT bit commonly set for DCs
            except (ValueError, TypeError):
                pass

        computer = Computer(
            distinguished_name=dn,
            sam_account_name=sam,
            domain=domain,
            dns_hostname=dns_hostname,
            operating_system=_safe_str(entry.get("operatingSystem")),
            object_sid=_safe_str(entry.get("objectSid")),
            is_domain_controller=is_dc,
        )

        self.conn.run_write(
            """
            MERGE (c:Computer {distinguished_name: $dn})
            SET c.sam_account_name = $sam,
                c.domain = $domain,
                c.dns_hostname = $dns_hostname,
                c.operating_system = $os,
                c.object_sid = $object_sid,
                c.is_domain_controller = $is_dc,
                c.last_seen = $last_seen
            WITH c
            MATCH (d:Domain {name: $domain})
            MERGE (c)-[:InDomain]->(d)
            """,
            {
                "dn": computer.distinguished_name,
                "sam": computer.sam_account_name,
                "domain": computer.domain,
                "dns_hostname": computer.dns_hostname,
                "os": computer.operating_system,
                "object_sid": computer.object_sid,
                "is_dc": computer.is_domain_controller,
                "last_seen": computer.last_seen.isoformat(),
            },
        )
        logger.debug("Upserted Computer %s (%s)", sam, dn)
        return computer

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def _link_has_spn(self, user_dn: str, spn: str) -> None:
        parsed = _parse_spn(spn)
        self.conn.run_write(
            """
            MERGE (s:Service {spn: $spn})
            ON CREATE SET s.service_class = $service_class, s.host = $host
            WITH s
            MATCH (u:User {distinguished_name: $user_dn})
            MERGE (u)-[:HasSPN]->(s)
            """,
            {
                "spn": spn,
                "service_class": parsed["service_class"],
                "host": parsed["host"],
                "user_dn": user_dn,
            },
        )

    def link_member_of(self, member_dn: str, group_dn: str) -> None:
        """
        Links a User or Group as a member of a Group. We don't require the
        caller to say which label the member is - MATCH against both.
        """
        result = self.conn.run_write(
            """
            MATCH (m {distinguished_name: $member_dn})
            WHERE m:User OR m:Group
            MATCH (g:Group {distinguished_name: $group_dn})
            MERGE (m)-[:MemberOf]->(g)
            RETURN count(*) AS linked
            """,
            {"member_dn": member_dn, "group_dn": group_dn},
        )
        linked = result.get("records", [{}])[0].get("linked", 0) if result else 0
        if not linked:
            logger.warning(
                "MemberOf link skipped: member %s or group %s not found in graph yet",
                member_dn, group_dn,
            )

    def link_admin_to(self, edge: AdminToEdge) -> None:
        self.conn.run_write(
            """
            MATCH (p {distinguished_name: $principal_dn})
            WHERE p:User OR p:Group
            MATCH (c:Computer {distinguished_name: $computer_dn})
            MERGE (p)-[r:AdminTo]->(c)
            SET r.source_tool = $source_tool,
                r.collected_at = $collected_at
            """,
            {
                "principal_dn": edge.principal_dn,
                "computer_dn": edge.computer_dn,
                "source_tool": edge.source_tool,
                "collected_at": edge.collected_at.isoformat(),
            },
        )

    def link_can_access(self, edge: CanAccessEdge) -> None:
        self.conn.run_write(
            """
            MATCH (p {distinguished_name: $principal_dn})
            MATCH (t {distinguished_name: $target_dn})
            MERGE (p)-[r:CanAccess {right: $right}]->(t)
            SET r.source_tool = $source_tool,
                r.collected_at = $collected_at
            """,
            {
                "principal_dn": edge.principal_dn,
                "target_dn": edge.target_dn,
                "right": edge.right,
                "source_tool": edge.source_tool,
                "collected_at": edge.collected_at.isoformat(),
            },
        )

    def link_trusted_by(self, edge: TrustedByEdge) -> None:
        self.conn.run_write(
            """
            MERGE (a:Domain {name: $trusting_domain})
            MERGE (b:Domain {name: $trusted_domain})
            MERGE (a)-[r:TrustedBy]->(b)
            SET r.trust_direction = $trust_direction,
                r.trust_type = $trust_type
            """,
            {
                "trusting_domain": edge.trusting_domain,
                "trusted_domain": edge.trusted_domain,
                "trust_direction": edge.trust_direction,
                "trust_type": edge.trust_type,
            },
        )

    # ------------------------------------------------------------------
    # Findings (from Feben's finding_rules.SecurityRuleEvaluator)
    # ------------------------------------------------------------------

    def ingest_security_finding(
        self, finding: "SecurityFinding", investigation_id: Optional[str] = None
    ) -> GraphFinding:
        """
        Takes a SecurityFinding produced by
        backend.security.finding_rules.SecurityRuleEvaluator and writes it
        as a Finding node, linked to whichever User or Computer node
        matches finding.target_entity (by sam_account_name).

        If the target entity isn't in the graph yet (e.g. tool integration
        hasn't ingested that account), the Finding node is still created so
        nothing is silently dropped - it's just left unlinked until the
        entity is ingested, at which point re-running this call will MERGE
        the relationship in.
        """
        graph_finding = GraphFinding(
            finding_id=finding.finding_id,
            investigation_id=investigation_id,
            technique_name=finding.technique_name,
            mitre_id=finding.mitre_id,
            severity=Severity(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
            target_entity=finding.target_entity,
            evidence=finding.evidence,
            explanation=finding.explanation,
            risk_impact=finding.risk_impact,
            remediation=finding.remediation,
            requires_approval=finding.requires_approval,
        )

        self.conn.run_write(
            """
            MERGE (f:Finding {finding_id: $finding_id})
            SET f.investigation_id = $investigation_id,
                f.technique_name = $technique_name,
                f.mitre_id = $mitre_id,
                f.severity = $severity,
                f.target_entity = $target_entity,
                f.evidence_json = $evidence_json,
                f.explanation = $explanation,
                f.risk_impact = $risk_impact,
                f.remediation = $remediation,
                f.requires_approval = $requires_approval,
                f.validation_status = $validation_status,
                f.created_at = $created_at
            WITH f
            OPTIONAL MATCH (entity {sam_account_name: $target_entity})
            WHERE entity:User OR entity:Computer
            FOREACH (_ IN CASE WHEN entity IS NULL THEN [] ELSE [1] END |
                MERGE (entity)-[:HasFinding]->(f)
            )
            """,
            {
                "finding_id": graph_finding.finding_id,
                "investigation_id": graph_finding.investigation_id,
                "technique_name": graph_finding.technique_name,
                "mitre_id": graph_finding.mitre_id,
                "severity": graph_finding.severity.value,
                "target_entity": graph_finding.target_entity,
                "evidence_json": json.dumps(graph_finding.evidence, default=str),
                "explanation": graph_finding.explanation,
                "risk_impact": graph_finding.risk_impact,
                "remediation": graph_finding.remediation,
                "requires_approval": graph_finding.requires_approval,
                "validation_status": graph_finding.validation_status,
                "created_at": graph_finding.created_at.isoformat(),
            },
        )
        logger.info("Ingested Finding %s (%s) for %s", graph_finding.finding_id, graph_finding.mitre_id, graph_finding.target_entity)
        return graph_finding

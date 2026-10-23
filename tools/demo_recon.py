"""
Demo / Integration Smoke Test: full recon -> finding -> graph pipeline
Component: Tool Integration


Run against a live GOAD-Light target once Neo4j is up and .env is loaded:

    python -m tools.demo_recon 192.168.56.11

This mirrors the project doc's intended flow end to end:
  1. Nmap port scan (Observation - autonomous)
  2. If Kerberos/LDAP detected -> LDAP enumeration (Observation - autonomous)
  3. Feben's SecurityRuleEvaluator classifies each user entry
  4. Every finding + entity gets written into Lidiya's Neo4j graph

It deliberately does NOT call tools.netexec_wrapper.check_admin_access(),
since that's a Controlled Validation action requiring human approval -
wiring that in belongs in the agent/backend approval flow, not a
standalone demo script.
"""

import logging
import sys

from backend.security.finding_rules import SecurityRuleEvaluator

from graph.connection import Neo4jConnection
from graph.ingest import GraphIngestor
from graph.models import Domain
from graph.schema import apply_schema

from tools.ldap_enum import LDAPEnumerator
from tools.nmap_scanner import run_port_scan

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ad_tools.demo_recon")


def main(target: str) -> None:
    logger.info("=== Step 1: Nmap port scan of %s ===", target)
    scan = run_port_scan(target)
    if scan.status != "success":
        logger.error("Nmap scan failed (%s): %s", scan.status, scan.error)
        return

    logger.info(
        "Open ports: %s | kerberos=%s ldap=%s smb=%s likely_dc=%s",
        [p.port for p in scan.open_ports],
        scan.has_kerberos, scan.has_ldap, scan.has_smb, scan.likely_domain_controller,
    )

    if not scan.has_ldap:
        logger.info("No LDAP service detected - stopping here (nothing further to enumerate).")
        return

    logger.info("=== Step 2: LDAP enumeration of %s ===", target)
    with LDAPEnumerator(target) as enumerator:
        if enumerator._conn is None:  # noqa: SLF001 - demo script, internal check is fine here
            logger.error("LDAP bind failed: %s", enumerator.last_error)
            return

        users_result = enumerator.enumerate_users()
        groups_result = enumerator.enumerate_groups()
        computers_result = enumerator.enumerate_computers()

    if users_result.status != "success":
        logger.error("LDAP user enumeration failed: %s", users_result.error)
        return

    logger.info(
        "Collected %d users, %d groups, %d computers",
        users_result.entry_count, groups_result.entry_count, computers_result.entry_count,
    )

    logger.info("=== Step 3: Classify findings (Feben's SecurityRuleEvaluator) ===")
    findings = []
    for entry in users_result.entries:
        kerb_finding = SecurityRuleEvaluator.evaluate_kerberoastable(entry)
        if kerb_finding:
            findings.append(kerb_finding)
            logger.info("Finding: %s (%s)", kerb_finding.technique_name, kerb_finding.target_entity)

        asrep_finding = SecurityRuleEvaluator.evaluate_asrep_roastable(entry)
        if asrep_finding:
            findings.append(asrep_finding)
            logger.info("Finding: %s (%s)", asrep_finding.technique_name, asrep_finding.target_entity)

    logger.info("=== Step 4: Write everything into the graph (Lidiya's module) ===")
    with Neo4jConnection() as conn:
        apply_schema(conn)
        ingestor = GraphIngestor(conn)

        domain_name = enumerator._base_dn or target  # noqa: SLF001
        domain_name = domain_name.replace("DC=", "").replace(",", ".") if "DC=" in str(domain_name) else domain_name
        ingestor.upsert_domain(Domain(name=domain_name, dc_hostname=target))

        for entry in users_result.entries:
            ingestor.upsert_user_raw(entry, domain=domain_name)
        for entry in groups_result.entries:
            ingestor.upsert_group_raw(entry, domain=domain_name)
        for entry in computers_result.entries:
            ingestor.upsert_computer_raw(entry, domain=domain_name)

        for finding in findings:
            ingestor.ingest_security_finding(finding)

    logger.info("Done. %d finding(s) written to the graph.", len(findings))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m tools.demo_recon <target_ip>")
        sys.exit(1)
    main(sys.argv[1])

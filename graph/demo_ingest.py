"""
Demo / smoke test: Feben's finding_rules.py -> graph.ingest -> Neo4j
Component: Active Directory Knowledge Graph


Run this once GOAD-Light + Neo4j (docker-compose) are up to confirm the
whole pipeline works end to end:

    python -m graph.demo_ingest

It does NOT call any real network tool - it uses one representative raw
LDAP-shaped dict per entity (the same shape python-ldap3 / NetExec's LDAP
module returns) so Meseret's real wrappers can be swapped in later by
replacing `SAMPLE_USERS` / `SAMPLE_COMPUTERS` with actual query results,
without changing any ingestion code.
"""

import logging

from backend.security.finding_rules import SecurityRuleEvaluator

from graph.connection import Neo4jConnection
from graph.ingest import GraphIngestor
from graph.models import Domain
from graph.schema import apply_schema

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ad_graph.demo")

DOMAIN_NAME = "sevenkingdoms.local"
DC_HOSTNAME = "kingslanding.sevenkingdoms.local"

# Representative raw LDAP entries - same attribute names ldap3 / NetExec return.
SAMPLE_USERS = [
    {
        "sAMAccountName": "sql_svc",
        "distinguishedName": "CN=sql_svc,CN=Users,DC=sevenkingdoms,DC=local",
        "servicePrincipalName": ["MSSQLSvc/kingslanding.sevenkingdoms.local:1433"],
        "userAccountControl": 512,
        "objectSid": "S-1-5-21-0000000000-0000000000-0000000000-1105",
    },
    {
        "sAMAccountName": "brandon.stark",
        "distinguishedName": "CN=Brandon Stark,CN=Users,DC=sevenkingdoms,DC=local",
        "userAccountControl": 4194816,  # 512 + DONT_REQ_PREAUTH
        "objectSid": "S-1-5-21-0000000000-0000000000-0000000000-1106",
    },
]

SAMPLE_GROUPS = [
    {
        "sAMAccountName": "Domain Admins",
        "distinguishedName": "CN=Domain Admins,CN=Users,DC=sevenkingdoms,DC=local",
        "objectSid": "S-1-5-21-0000000000-0000000000-0000000000-512",
    },
]

SAMPLE_COMPUTERS = [
    {
        "sAMAccountName": "KINGSLANDING$",
        "distinguishedName": "CN=KINGSLANDING,OU=Domain Controllers,DC=sevenkingdoms,DC=local",
        "dNSHostName": DC_HOSTNAME,
        "userAccountControl": 532480,  # includes SERVER_TRUST_ACCOUNT (0x2000)
    },
]


def main() -> None:
    with Neo4jConnection() as conn:
        apply_schema(conn)
        ingestor = GraphIngestor(conn)

        ingestor.upsert_domain(Domain(name=DOMAIN_NAME, dc_hostname=DC_HOSTNAME))

        for entry in SAMPLE_USERS:
            ingestor.upsert_user_raw(entry, domain=DOMAIN_NAME)

        for entry in SAMPLE_GROUPS:
            ingestor.upsert_group_raw(entry, domain=DOMAIN_NAME)

        for entry in SAMPLE_COMPUTERS:
            ingestor.upsert_computer_raw(entry, domain=DOMAIN_NAME)

        # Run Feben's actual rule evaluator against the same raw entries and
        # push any findings straight into the graph.
        findings_written = 0
        for entry in SAMPLE_USERS:
            finding = SecurityRuleEvaluator.evaluate_kerberoastable(entry)
            if finding:
                ingestor.ingest_security_finding(finding)
                findings_written += 1

            finding = SecurityRuleEvaluator.evaluate_asrep_roastable(entry)
            if finding:
                ingestor.ingest_security_finding(finding)
                findings_written += 1

        logger.info("Demo ingest complete. %d finding(s) written.", findings_written)


if __name__ == "__main__":
    main()

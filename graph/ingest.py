"""
graph/ingest.py

Loads structured AD-enumeration data (the JSON format that Meseret's
tool wrappers / the backend are expected to produce) into Neo4j.

This is the boundary between "reconnaissance tool output" and "the
knowledge graph" — once this works, anyone on the team can hand you
a JSON file shaped like sample_input.json and you can load it.

Usage:
    python ingest.py --file sample_input.json
    python ingest.py --file sample_input.json --uri bolt://localhost:7687 \
        --user neo4j --password yourpassword

Requires:
    pip install neo4j
"""

import argparse
import json
from neo4j import GraphDatabase


class GraphIngestor:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest(self, data: dict):
        with self.driver.session() as session:
            if "domain" in data:
                session.execute_write(self._merge_domain, data["domain"])

            for user in data.get("users", []):
                session.execute_write(self._merge_user, user)

            for group in data.get("groups", []):
                session.execute_write(self._merge_group, group)

            for computer in data.get("computers", []):
                session.execute_write(self._merge_computer, computer)

            for service in data.get("services", []):
                session.execute_write(self._merge_service, service)

            rels = data.get("relationships", {})

            for user_sam, domain_name in rels.get("belongs_to", []):
                session.execute_write(self._link_belongs_to, user_sam, domain_name)

            for user_sam, group_sid in rels.get("member_of", []):
                session.execute_write(self._link_member_of, user_sam, group_sid)

            for user_sam, spn in rels.get("has_spn", []):
                session.execute_write(self._link_has_spn, user_sam, spn)

            for principal_sam, hostname, source in rels.get("admin_to", []):
                session.execute_write(self._link_admin_to, principal_sam, hostname, source)

            for hostname, spn in rels.get("runs_service", []):
                session.execute_write(self._link_runs_service, hostname, spn)

            for principal_sam, hostname, access_type in rels.get("can_access", []):
                session.execute_write(self._link_can_access, principal_sam, hostname, access_type)

    # ---- node merges ----

    @staticmethod
    def _merge_domain(tx, domain):
        tx.run(
            "MERGE (d:Domain {name: $name}) SET d.sid = $sid",
            name=domain["name"], sid=domain.get("sid"),
        )

    @staticmethod
    def _merge_user(tx, user):
        tx.run(
            """
            MERGE (u:User {samAccountName: $sam})
            SET u.displayName = $displayName,
                u.enabled = $enabled,
                u.description = $description
            """,
            sam=user["samAccountName"],
            displayName=user.get("displayName"),
            enabled=user.get("enabled", True),
            description=user.get("description"),
        )

    @staticmethod
    def _merge_group(tx, group):
        tx.run(
            "MERGE (g:Group {sid: $sid}) SET g.name = $name",
            sid=group["sid"], name=group.get("name"),
        )

    @staticmethod
    def _merge_computer(tx, computer):
        tx.run(
            """
            MERGE (c:Computer {hostname: $hostname})
            SET c.os = $os, c.ipAddress = $ip
            """,
            hostname=computer["hostname"],
            os=computer.get("os"),
            ip=computer.get("ipAddress"),
        )

    @staticmethod
    def _merge_service(tx, service):
        tx.run(
            "MERGE (s:Service {spn: $spn}) SET s.name = $name",
            spn=service["spn"], name=service.get("name"),
        )

    # ---- relationship links ----

    @staticmethod
    def _link_belongs_to(tx, user_sam, domain_name):
        tx.run(
            """
            MATCH (u:User {samAccountName: $sam}), (d:Domain {name: $domain})
            MERGE (u)-[:BELONGS_TO]->(d)
            """,
            sam=user_sam, domain=domain_name,
        )

    @staticmethod
    def _link_member_of(tx, user_sam, group_sid):
        tx.run(
            """
            MATCH (u:User {samAccountName: $sam}), (g:Group {sid: $sid})
            MERGE (u)-[:MEMBER_OF]->(g)
            """,
            sam=user_sam, sid=group_sid,
        )

    @staticmethod
    def _link_has_spn(tx, user_sam, spn):
        tx.run(
            """
            MATCH (u:User {samAccountName: $sam}), (s:Service {spn: $spn})
            MERGE (u)-[:HAS_SPN]->(s)
            """,
            sam=user_sam, spn=spn,
        )

    @staticmethod
    def _link_admin_to(tx, principal_sam, hostname, source):
        tx.run(
            """
            MATCH (p {samAccountName: $sam}), (c:Computer {hostname: $hostname})
            MERGE (p)-[r:ADMIN_TO]->(c)
            SET r.source = $source
            """,
            sam=principal_sam, hostname=hostname, source=source,
        )

    @staticmethod
    def _link_runs_service(tx, hostname, spn):
        tx.run(
            """
            MATCH (c:Computer {hostname: $hostname}), (s:Service {spn: $spn})
            MERGE (c)-[:RUNS_SERVICE]->(s)
            """,
            hostname=hostname, spn=spn,
        )

    @staticmethod
    def _link_can_access(tx, principal_sam, hostname, access_type):
        tx.run(
            """
            MATCH (p {samAccountName: $sam}), (c:Computer {hostname: $hostname})
            MERGE (p)-[r:CAN_ACCESS]->(c)
            SET r.type = $type
            """,
            sam=principal_sam, hostname=hostname, type=access_type,
        )


def main():
    parser = argparse.ArgumentParser(description="Ingest AD recon data into Neo4j")
    parser.add_argument("--file", required=True, help="Path to JSON input file")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    with open(args.file, "r") as f:
        data = json.load(f)

    ingestor = GraphIngestor(args.uri, args.user, args.password)
    try:
        ingestor.ingest(data)
        print(f"Ingested data from {args.file} successfully.")
    finally:
        ingestor.close()


if __name__ == "__main__":
    main()

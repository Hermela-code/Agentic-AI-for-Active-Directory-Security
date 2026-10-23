"""
Graph Schema: Constraints & Indexes
Component: Active Directory Knowledge Graph

Defines uniqueness constraints (which also create backing indexes) for every
node label used in the AD graph. Run once at application startup, or via
`python -m graph.schema` locally. Idempotent - safe to run repeatedly.
"""

from graph.connection import Neo4jConnection

# Each entry: (label, unique_property)
# The unique property is the natural key we MERGE on everywhere else in
# ingest.py, so it must be unique and stable across re-ingestion.
CONSTRAINTS = [
    ("Domain", "name"),                      # e.g. "sevenkingdoms.local"
    ("User", "distinguished_name"),
    ("Group", "distinguished_name"),
    ("Computer", "distinguished_name"),
    ("Service", "spn"),                       # servicePrincipalName string, globally unique in AD
    ("Finding", "finding_id"),                # matches SecurityFinding.finding_id from finding_rules.py
]

# Secondary (non-unique) lookup indexes for common query patterns.
INDEXES = [
    ("User", "sam_account_name"),
    ("Group", "sam_account_name"),
    ("Computer", "dns_hostname"),
    ("Finding", "mitre_id"),
    ("Finding", "severity"),
]


def apply_schema(conn: Neo4jConnection) -> None:
    for label, prop in CONSTRAINTS:
        cypher = (
            f"CREATE CONSTRAINT {label.lower()}_{prop}_unique IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
        )
        conn.run_write(cypher)

    for label, prop in INDEXES:
        cypher = (
            f"CREATE INDEX {label.lower()}_{prop}_idx IF NOT EXISTS "
            f"FOR (n:{label}) ON (n.{prop})"
        )
        conn.run_write(cypher)


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)
    with Neo4jConnection() as conn:
        apply_schema(conn)
        print("Schema applied: constraints + indexes created (or already present).")

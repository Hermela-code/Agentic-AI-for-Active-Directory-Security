"""
Graph Queries: Attack Paths & Visualization
Component: Active Directory Knowledge Graph


Read-only Cypher queries the agent (Hermela) and frontend (Yosef) will call.
Every function returns plain JSON-serializable dicts/lists so they can be
dropped straight into a FastAPI response (Wintana's backend) without any
extra mapping layer.
"""

from typing import Any, Dict, List, Optional

from graph.connection import Neo4jConnection

# Relationship types that represent "control" for attack-path purposes -
# i.e. traversing one of these edges means the source effectively gains
# the privileges of the target. Mirrors the standard BloodHound edge set
# relevant to this project's scope.
CONTROL_EDGES = "MemberOf|AdminTo|CanAccess"


def get_attack_paths_to_high_value(
    conn: Neo4jConnection, max_hops: int = 6
) -> List[Dict[str, Any]]:
    """
    Finds all shortest paths from any User to any high-value Group
    (is_high_value = true, e.g. Domain Admins) or to a Domain Controller,
    via MemberOf / AdminTo / CanAccess edges.

    This is the core "attack path" query the project doc describes:
    user -> group -> AdminTo computer, etc.
    """
    cypher = f"""
        MATCH (start:User)
        MATCH (target)
        WHERE (target:Group AND target.is_high_value = true)
           OR (target:Computer AND target.is_domain_controller = true)
        MATCH path = shortestPath((start)-[:{CONTROL_EDGES}*1..{max_hops}]->(target))
        RETURN
            start.sam_account_name AS start_entity,
            target.sam_account_name AS target_entity,
            labels(target) AS target_type,
            length(path) AS hop_count,
            [n IN nodes(path) | coalesce(n.sam_account_name, n.name)] AS path_nodes,
            [r IN relationships(path) | type(r)] AS path_edges
        ORDER BY hop_count ASC
    """
    return conn.run_query(cypher)


def get_path_between(
    conn: Neo4jConnection, start_sam: str, target_sam: str, max_hops: int = 8
) -> Optional[Dict[str, Any]]:
    """Shortest attack path between two specific named entities, if one exists."""
    cypher = f"""
        MATCH (start {{sam_account_name: $start_sam}})
        MATCH (target {{sam_account_name: $target_sam}})
        MATCH path = shortestPath((start)-[:{CONTROL_EDGES}*1..{max_hops}]->(target))
        RETURN
            [n IN nodes(path) | coalesce(n.sam_account_name, n.name)] AS path_nodes,
            [r IN relationships(path) | type(r)] AS path_edges,
            length(path) AS hop_count
        LIMIT 1
    """
    rows = conn.run_query(cypher, {"start_sam": start_sam, "target_sam": target_sam})
    return rows[0] if rows else None


def get_kerberoastable_accounts_with_privilege(conn: Neo4jConnection) -> List[Dict[str, Any]]:
    """
    Cross-references Kerberoasting findings (from Feben's rules, ingested as
    Finding nodes) with graph privilege: flags accounts that are BOTH
    Kerberoastable AND sit on a path to a high-value group. This is exactly
    the kind of "individually not meaningful, combined = important" signal
    described in the project overview.
    """
    cypher = f"""
        MATCH (u:User)-[:HasFinding]->(f:Finding {{mitre_id: 'T1558.003'}})
        OPTIONAL MATCH path = shortestPath(
            (u)-[:{CONTROL_EDGES}*1..6]->(g:Group {{is_high_value: true}})
        )
        RETURN
            u.sam_account_name AS account,
            f.finding_id AS finding_id,
            f.severity AS severity,
            CASE WHEN path IS NULL THEN false ELSE true END AS has_privilege_path,
            CASE WHEN path IS NULL THEN null ELSE length(path) END AS hops_to_privilege
        ORDER BY has_privilege_path DESC, severity DESC
    """
    return conn.run_query(cypher)


def get_entity_neighbors(conn: Neo4jConnection, sam_account_name: str) -> Dict[str, Any]:
    """
    One-hop neighborhood of a single entity, for the frontend's
    'click a node to expand' graph visualization view.
    """
    cypher = """
        MATCH (center {sam_account_name: $sam})
        OPTIONAL MATCH (center)-[r_out]->(neighbor_out)
        OPTIONAL MATCH (neighbor_in)-[r_in]->(center)
        RETURN
            center.sam_account_name AS center,
            labels(center) AS center_type,
            collect(DISTINCT {
                direction: 'out', type: type(r_out),
                node: coalesce(neighbor_out.sam_account_name, neighbor_out.name, neighbor_out.spn),
                node_type: labels(neighbor_out)
            }) AS outgoing,
            collect(DISTINCT {
                direction: 'in', type: type(r_in),
                node: coalesce(neighbor_in.sam_account_name, neighbor_in.name),
                node_type: labels(neighbor_in)
            }) AS incoming
    """
    rows = conn.run_query(cypher, {"sam": sam_account_name})
    return rows[0] if rows else {"center": sam_account_name, "outgoing": [], "incoming": []}


def get_findings_for_entity(conn: Neo4jConnection, sam_account_name: str) -> List[Dict[str, Any]]:
    """All findings attached to a given entity, for a findings detail panel."""
    cypher = """
        MATCH (e {sam_account_name: $sam})-[:HasFinding]->(f:Finding)
        RETURN f.finding_id AS finding_id, f.technique_name AS technique_name,
               f.mitre_id AS mitre_id, f.severity AS severity,
               f.explanation AS explanation, f.risk_impact AS risk_impact,
               f.remediation AS remediation, f.requires_approval AS requires_approval,
               f.validation_status AS validation_status, f.evidence_json AS evidence_json
        ORDER BY f.created_at DESC
    """
    return conn.run_query(cypher, {"sam": sam_account_name})


def get_graph_summary(conn: Neo4jConnection) -> Dict[str, Any]:
    """Node/relationship counts for a dashboard overview widget."""
    cypher = """
        MATCH (n)
        WITH labels(n) AS lbls
        UNWIND lbls AS lbl
        RETURN lbl AS label, count(*) AS count
        ORDER BY count DESC
    """
    node_counts = conn.run_query(cypher)

    rel_cypher = """
        MATCH ()-[r]->()
        RETURN type(r) AS relationship, count(*) AS count
        ORDER BY count DESC
    """
    rel_counts = conn.run_query(rel_cypher)

    return {"nodes": node_counts, "relationships": rel_counts}


def get_domain_controllers(conn: Neo4jConnection) -> List[Dict[str, Any]]:
    cypher = """
        MATCH (c:Computer {is_domain_controller: true})-[:InDomain]->(d:Domain)
        RETURN c.sam_account_name AS computer, c.dns_hostname AS dns_hostname,
               d.name AS domain
    """
    return conn.run_query(cypher)

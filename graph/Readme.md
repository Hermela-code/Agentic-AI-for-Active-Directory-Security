# Agentic AI for Active Directory Security — Individual Submission

**contributor:** Lidiya Alemayehu

**Role:** Knowledge Graph & Attack Paths

**Presentation Video:** https://docs.google.com/document/d/1X30zuVKZMHAeRJeN9aQkUY6oPWrdLIujUkXMZYzAmlQ/edit?usp=sharing
**Repository:** https://github.com/Hermela-code/Agentic-AI-for-Active-Directory-Security
**Component Location:** `graph/`

---

## 1. Project Title

Agentic AI for Active Directory Security

## 2. My Role in the Project

I was responsible for the **Knowledge Graph & Attack Paths** component —
the part of the system that models the Active Directory environment as a
connected graph, so that individually small facts (a user, a group
membership, a service principal name) can be combined into a meaningful
attack path, and so that security findings produced elsewhere in the
system are stored as connected, queryable evidence rather than isolated
records.



## 3. What's in `graph/`

| File | Purpose |
|---|---|
| `connection.py` | Neo4j driver wrapper — reads connection settings from environment variables, never hardcodes credentials |
| `schema.py` | Applies uniqueness constraints and indexes for every node label (idempotent) |
| `models.py` | Pydantic models for every node type, edge payload, and the `GraphFinding` model |
| `ingest.py` | `GraphIngestor` — upserts raw LDAP-shaped data and security findings into the graph |
| `queries.py` | Attack-path and analysis queries (shortest path to a privileged group, Kerberoastable-accounts-with-privilege, entity neighborhood, findings-for-entity, graph summary) |
| `demo_ingest.py` | End-to-end smoke test: ingest sample data, run the team's real security rule evaluator, confirm findings land in the graph |
| `requirements.txt` | Python dependencies for this component |

## 4. How to Run / Verify

These are the exact steps shown in my presentation video.

**Prerequisites:** Neo4j running locally (e.g. via `docker-compose`), Python 3.10+.

```bash
# 1. From the repo root, on main, with the latest code
git checkout main
git pull origin main

# 2. Install dependencies
pip install -r graph/requirements.txt --break-system-packages

# 3. Set your Neo4j password
export NEO4J_PASSWORD=yourpassword

# 4. Apply the schema (constraints + indexes)
python3 -m graph.schema

# 5. Run the end-to-end demo ingestion
python3 -m graph.demo_ingest
```

Expected output ends with:
```
Demo ingest complete. 2 finding(s) written.
```

**To verify in Neo4j Browser** (http://localhost:7474):
```cypher
MATCH (u:User)-[:HasFinding]->(f:Finding)
RETURN u.sam_account_name, f.technique_name, f.severity, f.mitre_id;
```
Expected result: `sql_svc` → Kerberoasting Opportunity (MEDIUM, T1558.003),
`brandon.stark` → AS-REP Roasting Opportunity (HIGH, T1558.004).

## 5. Verification Note

The findings shown above are produced by the team's **real, unmodified**
security rule evaluator (`backend/security/finding_rules.py`,
`SecurityRuleEvaluator`) — not mock or stand-in logic. This confirms the
graph ingestion correctly integrates with the rest of the team's work,
not just in isolation.


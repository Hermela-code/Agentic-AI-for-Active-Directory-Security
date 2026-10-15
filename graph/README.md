# Knowledge Graph & Attack Paths

Owner: **Lidiya Alemayehu**

This folder is the Neo4j-backed knowledge graph for the Agentic AI for
Active Directory Security project. It turns raw recon-tool output into
a connected model of the AD environment, and exposes attack-path and
finding queries that the agent and backend can call.

## What's in here

| File | Purpose |
|---|---|
| `schema.cypher` | Constraints/indexes + the node & relationship reference. Run once per fresh database. |
| `sample_data.cypher` | Small hand-built GOAD-Light-style dataset for manual testing in Neo4j Browser. |
| `sample_input.json` | The same data, but in the JSON shape `ingest.py` expects — for testing the ingestion path. |
| `ingest.py` | Loads a JSON file (produced by the recon tool wrappers) into Neo4j. |
| `queries/attack_paths.cypher` | The reusable queries other components will call — Kerberoastable accounts, path-to-Domain-Admins, findings list, etc. |
| `requirements.txt` | Python deps (`neo4j` driver). |

## Full workflow (what you've done + what's next)

1. **Stand up Neo4j** — done, via `docker-compose` (or locally as you have it running at `localhost:7474`).
2. **Apply the schema** — open Neo4j Browser, paste the contents of `schema.cypher`, run it. This creates constraints so duplicate nodes can't creep in.
3. **Load test data** — paste `sample_data.cypher` into the Browser and run it. This gives you something to query immediately without waiting on real tool output.
4. **Validate with the attack-path queries** — open `queries/attack_paths.cypher` and run query #1 (Kerberoastable accounts) and #3 (path to Domain Admins, with `$startUser` set to `"arya.stark"`) to confirm the model behaves the way the project doc describes (e.g. the Kerberoasting scenario in section 5).
5. **Test the ingestion script** — run:
   ```bash
   pip install -r requirements.txt
   python ingest.py --file sample_input.json --password yourpassword
   ```
   This proves the JSON → graph pipeline works end-to-end, independent of any real tool output.
6. **Hand off the contract** — Meseret's tool wrappers (Nmap/NetExec/LDAP) need to eventually produce JSON shaped like `sample_input.json`. Share this file with her/the team as the agreed format (or adjust it together — it's deliberately simple and flat).
7. **Hand off the query interface** — Hermela's agent (now calling Ollama + Qwen2.5-Coder directly) and Wintana's FastAPI backend will need to run the queries in `queries/attack_paths.cypher`. The cleanest handoff: wrap each query as a small Python function (e.g. in a `graph/queries.py` you add later) that takes parameters and returns results as plain dicts/lists, so the backend just imports and calls it — it doesn't need to know Cypher.
8. **Grow the model as real scenarios get added** — Feben's AD-security research (Kerberoasting, AS-REP roasting, permission abuse, etc.) will suggest new relationship types or finding categories. Extend `schema.cypher` and `attack_paths.cypher` together as those come in, rather than redesigning later.
9. **Visualization requirements** — once Yosef starts the dashboard's graph view, you'll want a query that returns a whole subgraph (nodes + relationships) in a frontend-friendly shape (e.g. `{nodes: [...], edges: [...]}`) rather than raw paths. Worth drafting once the frontend's graph library is chosen.

## Notes on the architecture change

The team moved from OpenClaw to a custom Python agent calling **Ollama**
(local Qwen2.5-Coder) directly. This doesn't change anything here — your
graph is still the source of truth for AD relationships and attack
paths; only *what calls into it* changed (a custom agent loop instead
of an OpenClaw-managed one). Keep your query interface clean and
parameter-driven so either approach can consume it.

## Commit checklist before opening your PR

- [ ] `schema.cypher` runs cleanly on a fresh database
- [ ] `sample_data.cypher` loads without errors
- [ ] At least the Kerberoasting and path-to-DA queries return expected results
- [ ] `ingest.py` successfully loads `sample_input.json`
- [ ] This README is up to date with anything you changed

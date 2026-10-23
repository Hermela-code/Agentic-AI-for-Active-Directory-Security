# tools/ — Security Tool Integrations

**Branch:** `feature/tool-integration`

Wrappers around real Nmap, NetExec (`nxc`), and `ldap3` that return
structured, JSON-serializable results — never raw terminal text the agent
has to re-parse. Every wrapper enforces the authorized scope
(`192.168.56.0/24`) before touching the network, per `SETUP.md` rule #8.

## 1. Files

| File | Purpose |
|---|---|
| `scope_guard.py` | `assert_in_scope()` — refuses to run against anything outside the authorized range |
| `models.py` | `ToolExecutionResult` and subclasses, matching the backend's `/executions` API shape |
| `nmap_scanner.py` | `run_port_scan()` — TCP connect + service scan over AD-relevant ports |
| `ldap_enum.py` | `LDAPEnumerator` — users/groups/computers, output shaped exactly for `finding_rules.py` and `graph.ingest` |
| `netexec_wrapper.py` | `smb_enum()` (passive) and `check_admin_access()` (Controlled Validation — requires approval) |
| `demo_recon.py` | Full pipeline: nmap → LDAP → Feben's rules → Lidiya's graph, in one script |

## 2. Approval Levels (per `scenarios.md`)

| Function | Level | Autonomous? |
|---|---|---|
| `nmap_scanner.run_port_scan()` | Observation | Yes |
| `ldap_enum.LDAPEnumerator.enumerate_*()` | Observation | Yes |
| `netexec_wrapper.smb_enum()` | Observation | Yes |
| `netexec_wrapper.check_admin_access()` | Controlled Validation | **No — requires approval via `POST /approvals/{id}/approve` before calling** |

The wrappers don't enforce the approval gate themselves — that's the
agent/backend's job (see Backend API note, section 3). This package just
makes sure the *validation* functions are clearly labeled so nobody wires
`check_admin_access()` into an autonomous loop by mistake.

## 3. Install

```bash
pip install -r tools/requirements.txt

# External binaries (not pip packages):
sudo apt install nmap
pipx install netexec        # provides the `nxc` command
```

Verify both are on PATH:
```bash
which nmap nxc
```

## 4. Usage

### Nmap
```python
from tools.nmap_scanner import run_port_scan

result = run_port_scan("192.168.56.11")
print(result.status, result.likely_domain_controller, [p.port for p in result.open_ports])
```

### LDAP (feeds Feben's rules directly)
```python
from tools.ldap_enum import LDAPEnumerator
from backend.security.finding_rules import SecurityRuleEvaluator

with LDAPEnumerator("192.168.56.11") as enumerator:
    users = enumerator.enumerate_users()

for entry in users.entries:
    finding = SecurityRuleEvaluator.evaluate_kerberoastable(entry)
    if finding:
        print(finding.technique_name, finding.target_entity)
```

Authenticated bind (once you have valid domain creds, e.g. after an
approved validation step):
```python
enumerator = LDAPEnumerator("192.168.56.11")
enumerator.connect(username="sevenkingdoms\\brandon.stark", password="...")
```

### NetExec
```python
from tools.netexec_wrapper import smb_enum, check_admin_access

info = smb_enum("192.168.56.11")              # Observation - fine to run anytime
print(info.output)

# Only after an approval has been granted:
admin_check = check_admin_access("192.168.56.11", "jon.snow", "...", domain="sevenkingdoms.local")
print(admin_check.is_admin, admin_check.shares)
```

## 5. Full pipeline demo

```bash
python -m tools.demo_recon 192.168.56.11
```

Runs the complete Observation-level chain — nmap, then LDAP if a DC is
detected, then Feben's rule evaluator, then writes everything into Neo4j
via Lidiya's `GraphIngestor`. Requires `graph/` and
`backend/security/finding_rules.py` to already be in place and Neo4j
reachable (same `.env` setup as `graph/README.md` describes).

## 6. Safety Notes

- Every entry point calls `tools.scope_guard.assert_in_scope()` first. A
  target outside `192.168.56.0/24` (or whatever `AUTHORIZED_SCOPE` env var
  is set to) is refused before any packet is sent.
- `check_admin_access()` redacts the password from logged/returned output
  even on success, so credentials never end up in a finding or a log line
  (SETUP.md rule #7).
- All failures (missing binary, timeout, unreachable host, bad bind) come
  back as a `status: "error" | "failed" | "timeout"` result instead of
  raising — this is what lets `finding_rules.py`'s
  `validate_telemetry_payload()` cleanly skip evaluation instead of
  crashing or inventing a finding from a failed collection.

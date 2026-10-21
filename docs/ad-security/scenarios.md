# Active Directory Security Scenarios

## 1. Purpose

This document defines candidate Active Directory (AD) security scenarios for the Agentic AI for Active Directory Security project.

The scenarios will guide security-tool integration, agent analysis, and validation of findings in the authorized GOAD-Light lab.

No scenario in this document is considered confirmed until the required evidence has been collected and reviewed.

## 2. Scope and Constraints

- Target environment: authorized GOAD-Light lab only.
- Objective: identify and explain selected AD security weaknesses using evidence from supported security tools.
- Findings must distinguish observed facts, potential risks, and validated attack paths.
- The agent must not report a vulnerability solely because a related account, attribute, or relationship exists.
- Actions that could expose credentials or materially affect the environment require an explicitly approved and controlled validation process.
- Credentials, secrets, and sensitive authentication material must not be included in ordinary findings or logs.

## 3. Scenario AD-01: Kerberoasting Exposure

### Objective

Identify accounts associated with Service Principal Names (SPNs) and assess whether the available evidence supports a potential Kerberoasting risk.

### Evidence to collect

- Account identifier.
- Whether an SPN is registered.
- Account type and relevant attributes, when available.
- Source tool and collection timestamp.
- Any additional approved evidence needed to assess the risk.

### Analysis requirements

- An SPN-associated account is not automatically vulnerable.
- Explain why the observed configuration may create exposure.
- Do not claim that an account password is weak or recoverable without supporting evidence.
- Do not claim successful credential recovery unless a separately approved validation actually establishes it.

### Expected finding

A structured observation identifying the relevant account, the evidence collected, the potential security significance, and any missing evidence.

### Recommended remediation

Review whether the service account requires its SPN, apply a strong and managed account-password strategy, and consider an appropriate managed service account where supported.

### Validation status

NOT TESTED — GOAD-Light is not yet available to the researcher.

## 4. Scenario AD-02: Kerberos Pre-Authentication Configuration

### Objective

Identify accounts whose Kerberos pre-authentication configuration may expose them to AS-REP roasting.

### Evidence to collect

- Account identifier.
- Relevant Kerberos pre-authentication configuration.
- Source tool and collection timestamp.
- Whether the observation was independently verified.

### Analysis requirements

- Identify the relevant configuration explicitly.
- Distinguish a configuration-based exposure from demonstrated password recovery.
- Do not infer password strength or account compromise from the configuration alone.

### Expected finding

A structured observation explaining which account configuration was identified, why it matters, and what has or has not been validated.

### Recommended remediation

Enable Kerberos pre-authentication where operationally appropriate, investigate any required exceptions, and review affected accounts' credential-management practices.

### Validation status

NOT TESTED — GOAD-Light is not yet available to the researcher.

## 5. Scenario AD-03: Privileged Group Membership and Access Relationships

### Objective

Identify selected privileged group memberships and relevant access relationships that may contribute to excessive privilege or a potential attack path.

### Evidence to collect

- Relevant account and group identifiers.
- Observed group membership or permission relationship.
- Source of the relationship data.
- Scope of the privilege, where known.
- Any missing information needed to determine practical impact.

### Analysis requirements

- Distinguish observed group membership from effective permissions.
- Do not assume that every relationship creates an exploitable attack path.
- Do not claim that a user can control another account or system unless the necessary relationships and permissions are supported by evidence.
- Clearly identify inferred paths separately from validated paths.

### Expected finding

A structured observation describing the account or group, the relationship identified, its potential significance, and the additional evidence required to validate impact.

### Recommended remediation

Review privileged group membership, remove unnecessary privileges, apply least privilege, and periodically audit sensitive access relationships.

### Validation status

NOT TESTED — GOAD-Light is not yet available to the researcher.

## 6. Common Finding Requirements

Each finding should contain the following fields where applicable:

- `scenario_id`
- `title`
- `affected_entities`
- `severity`
- `confidence`
- `observation`
- `evidence`
- `security_impact`
- `recommendation`
- `validation_status`
- `limitations`
- `source_tool`
- `collected_at`

Severity and confidence must be based on documented criteria, not invented by the language model. If the evidence is insufficient, the system should report that limitation rather than manufacture a conclusion.

## 7. Research and Validation Status

The researcher has cloned the project repository but has not yet configured or accessed GOAD-Light.

All three scenarios are proposed research targets. Their presence in this document does not establish that the lab contains the corresponding conditions.

The next step is to confirm tool availability with the integration developer, prepare the authorized lab, and record actual observations against the criteria above.
# Active Directory Security Validation Plan

## 1. Purpose

This plan defines how the initial AD security scenarios will be evaluated for the Agentic AI for Active Directory Security project.

The goal is to determine whether findings produced by the system are supported by evidence, accurately described, and reproducible.

## 2. Current Status

- Repository cloned and feature branch created.
- Initial scenario specifications documented in `scenarios.md`.
- GOAD-Light environment not yet configured or accessed.
- Tool integrations and application components are not yet present in the checked repository directories.
- No scenarios have been validated against a live lab.

## 3. Validation Principles

1. Use only the authorized GOAD-Light environment.
2. Record the source of every observation.
3. Separate raw observations from the agent's interpretation.
4. Do not treat missing data as proof that a weakness is absent.
5. Do not report an attack path as validated unless the required relationships and permissions have been demonstrated.
6. Do not claim credential recovery or account compromise without direct supporting evidence.
7. Record limitations, errors, and incomplete collection.
8. Do not expose credentials, password material, or other secrets in findings or ordinary logs.

## 4. Scenario Validation Matrix

| Scenario | Evidence to inspect | Positive observation | Insufficient evidence |
|---|---|---|---|
| AD-01: Kerberoasting exposure | Account identity, SPN association, relevant account attributes, collection source | An SPN-associated account is identified and the evidence supports further risk assessment | SPN presence alone does not establish weak credentials or successful credential recovery |
| AD-02: AS-REP roasting exposure | Account identity and relevant Kerberos pre-authentication configuration | An account is identified with a configuration consistent with potential AS-REP roasting exposure | The configuration alone does not prove password recovery or account compromise |
| AD-03: Privileged relationships | Account and group identifiers, membership or permission evidence, relationship source | A specific privileged membership or access relationship is supported by collected evidence | Membership or a graph connection alone does not establish an exploitable attack path |

## 5. Test Cases

### TC-01: Evidence supports a finding

**Input:** A structured result contains the evidence required for a selected scenario.

**Expected behavior:**
- The system identifies the relevant scenario.
- The finding references the collected evidence.
- The explanation distinguishes observed facts from inferred impact.
- The recommendation relates to the identified risk.

**Status:** Pending tool integration and lab access.

### TC-02: Evidence is incomplete

**Input:** A structured result contains some relevant information but lacks a required attribute or relationship.

**Expected behavior:**
- The system identifies the missing evidence.
- It lowers confidence or marks the finding inconclusive according to agreed criteria.
- It does not invent missing attributes or claim a confirmed vulnerability.

**Status:** Pending implementation.

### TC-03: No matching observation is returned

**Input:** A tool returns no matching result.

**Expected behavior:**
- The system reports that no matching observation was returned.
- It distinguishes a successful, sufficiently scoped query with no matches from a failed query or incomplete collection.
- It does not automatically conclude that the environment is secure.

**Status:** Pending implementation.

### TC-04: Tool execution fails

**Input:** A tool wrapper returns an error, times out, or cannot reach the target.

**Expected behavior:**
- The error is recorded without exposing secrets.
- The investigation marks the relevant step as failed or incomplete.
- The agent does not interpret the error as evidence that the target has no vulnerability.

**Status:** Pending tool integration.

### TC-05: Finding cannot be independently confirmed

**Input:** The agent proposes a finding, but the available evidence does not independently establish its conclusion.

**Expected behavior:**
- The finding is marked unverified or inconclusive.
- The system identifies what evidence is missing.
- The report does not describe the suspected attack as successful.

**Status:** Pending lab access and integration.

## 6. Proposed Finding Structure

Each finding should use an agreed structure containing:

- `finding_id`: unique finding identifier.
- `scenario_id`: identifier such as AD-01.
- `title`: concise description.
- `affected_entities`: accounts, groups, computers, or other relevant entities.
- `severity`: rating based on an agreed severity rubric.
- `confidence`: confidence in the finding based on the available evidence.
- `observation`: what the tool actually observed.
- `evidence`: relevant structured evidence and its source.
- `security_impact`: potential consequence, with assumptions stated.
- `recommendation`: appropriate remediation guidance.
- `validation_status`: not tested, unverified, inconclusive, or validated.
- `limitations`: missing information or constraints.
- `source_tool`: tool that produced the observation.
- `collected_at`: timestamp of collection.

This is a proposed contract for discussion with the agent, backend, and tool-integration developers. Field names and permitted values must be agreed before implementation.

## 7. Validation Record

For every actual lab test, record:

- Test case identifier.
- Scenario identifier.
- Lab and test conditions.
- Tool and relevant configuration.
- Expected result.
- Actual observation.
- Evidence location, excluding secrets.
- Pass, fail, or inconclusive result.
- Explanation of any difference between expected and actual behavior.
- Researcher and test date.

## 8. Next Steps

1. Confirm which tools Meseret plans to expose and what structured output they return.
2. Confirm how Hermela's agent will receive tool results and apply scenario criteria.
3. Agree on the finding structure with the backend and frontend developers.
4. Prepare or obtain access to the authorized GOAD-Light environment.
5. Run the test cases and replace pending statuses with evidence-based results.

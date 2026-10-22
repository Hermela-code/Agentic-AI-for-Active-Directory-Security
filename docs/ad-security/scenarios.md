# Active Directory Security Scenarios & Validation Spec (GOAD-Light)
**Author:** Feben Solomon (AD Security & Attack Validation)

## 1. Overview & GOAD-Light Environment
This document establishes the security techniques, indicator definitions, and human-in-the-loop (HITL) validation rules for testing against the **Game of Active Directory - Light (GOAD-Light)** environment.

### Target Environment Defaults
- **Domain:** `sevenkingdoms.local`
- **Domain Controller:** `DC01` / `kingslanding.sevenkingdoms.local`
- **Scope Restriction:** Read-only reconnaissance is autonomous; ticket requests and credential validations require human approval.

---

## 2. Selected Security Scenarios

### Scenario 1: Kerberoasting Opportunity (SPN Discovery)
* **MITRE ATT&CK:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
* **Technique Summary:** User accounts associated with a Service Principal Name (SPN) allow any domain-authenticated user to request a Ticket Granting Service (TGS) ticket. The service ticket is encrypted with the NTLM hash of the service account password. An attacker can extract this ticket and attempt offline password cracking.
* **Passive Indicator (Read-only):**
  * Object filter: `(&(servicePrincipalName=*)(!(objectClass=computer)))`
  * Account attribute: `servicePrincipalName` is not empty.
* **Validation Action (Requires Approval):**
  * Request a TGS service ticket for the identified SPN using a standard Kerberos request.
  * Verify whether the encryption type returned is weak (e.g., `arcfour-hmac-md5` / RC4).
* **Remediation / Mitigation:**
  * Enforce passwords with 25+ characters for service accounts, or migrate to Group Managed Service Accounts (gMSA).
  * Configure encryption to enforce AES128/AES256 and disable RC4.

---

### Scenario 2: AS-REP Roasting (Pre-Authentication Disabled)
* **MITRE ATT&CK:** T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)
* **Technique Summary:** When an account has the `DONT_REQ_PREAUTH` flag enabled in `userAccountControl`, any user can request an AS-REP message from the Key Distribution Center (KDC) without knowing the password. The AS-REP contains data encrypted with the user's password hash, which can be extracted for offline cracking.
* **Passive Indicator (Read-only):**
  * Object filter: `(userAccountControl:1.2.840.113556.1.4.803:=4194304)`
  * Flag: `DONT_REQ_PREAUTH` (Bit `0x400000`).
* **Validation Action (Requires Approval):**
  * Send an `AS-REQ` without pre-authentication to verify the KDC returns an `AS-REP` rather than `KRB_ERROR(KDC_ERR_PREAUTH_REQUIRED)`.
* **Remediation / Mitigation:**
  * Untick "Do not require Kerberos preauthentication" on the account properties in Active Directory Users and Computers (ADUC).

---

### Scenario 3: Anonymous / Null Session LDAP & SMB Binding
* **MITRE ATT&CK:** T1087 (Account Discovery)
* **Technique Summary:** Misconfigured Domain Controllers or member servers may permit anonymous binds or null session connections over SMB (port 445) or LDAP (port 389), exposing domain schema, users, and password policies to unauthenticated network actors.
* **Passive Indicator:**
  * Successful connection to LDAP port 389 with null bind credentials (`""`).
* **Validation Action:**
  * Query base naming contexts without credentials.

---

## 3. Human Approval & Safety Thresholds

Every finding produced by the tools must be classified before action:

| Action Level | Autonomous Execution | Approval Required | Examples |
| :--- | :--- | :--- | :--- |
| **Observation** | YES | NO | Port scanning, LDAP object queries, parsing permissions |
| **Controlled Validation** | NO | YES | Requesting Kerberos service tickets, querying AS-REP packets |
| **Exploitation / Crack**| NO (OUT OF SCOPE) | NO (OUT OF SCOPE) | Offline dictionary cracking, shell execution, credential manipulation |
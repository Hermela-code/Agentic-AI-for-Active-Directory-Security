"""
Tests for AD Security Rules and Scenario Ground Truth (Hardened)
Author: Feben Solomon
Component: Active Directory Security & Validation
"""

import unittest
from backend.security.finding_rules import SecurityRuleEvaluator, Severity

class TestADSecurityScenarios(unittest.TestCase):

    # ----------------------------------------------------
    # Baseline Scenario Tests (GOAD-Light Ground Truth)
    # ----------------------------------------------------

    def test_kerberoastable_standard_detection(self):
        """Validates normal GOAD-Light 'sql_svc' detection."""
        entry = {
            "sAMAccountName": "sql_svc",
            "servicePrincipalName": ["MSSQLSvc/kingslanding.sevenkingdoms.local:1433"],
            "memberOf": ["CN=Domain Users,CN=Users,DC=sevenkingdoms,DC=local"]
        }
        finding = SecurityRuleEvaluator.evaluate_kerberoastable(entry)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.mitre_id, "T1558.003")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertTrue(finding.requires_approval)

    def test_asrep_roastable_standard_detection(self):
        """Validates normal GOAD-Light AS-REP vulnerable account."""
        entry = {
            "sAMAccountName": "brandon.stark",
            "userAccountControl": 4194816  # 512 + 4194304
        }
        finding = SecurityRuleEvaluator.evaluate_asrep_roastable(entry)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.mitre_id, "T1558.004")
        self.assertEqual(finding.severity, Severity.HIGH)

    # ----------------------------------------------------
    # Missing Attributes & Malformed Evidence Tests
    # ----------------------------------------------------

    def test_missing_samaccountname(self):
        """Evaluator must safely return None if sAMAccountName is absent or None."""
        entry = {"servicePrincipalName": ["HOST/service1"]}
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(entry))

        entry_none = {"sAMAccountName": None, "servicePrincipalName": ["HOST/service1"]}
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(entry_none))

    def test_empty_or_whitespace_spn(self):
        """Evaluator must ignore empty lists, whitespace SPNs, or None SPNs."""
        cases = [
            {"sAMAccountName": "user1", "servicePrincipalName": []},
            {"sAMAccountName": "user1", "servicePrincipalName": [""]},
            {"sAMAccountName": "user1", "servicePrincipalName": ["   "]},
            {"sAMAccountName": "user1", "servicePrincipalName": None},
        ]
        for c in cases:
            self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(c))

    def test_single_string_spn_instead_of_list(self):
        """Evaluator should handle LDAP wrappers returning a string instead of a list."""
        entry = {
            "sAMAccountName": "web_svc",
            "servicePrincipalName": "HTTP/web.sevenkingdoms.local"
        }
        finding = SecurityRuleEvaluator.evaluate_kerberoastable(entry)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.evidence["servicePrincipalNames"], ["HTTP/web.sevenkingdoms.local"])

    def test_uac_as_string_and_hex(self):
        """Evaluator should parse UAC if returned as string representation or hex."""
        # Decimal as string
        entry_str = {"sAMAccountName": "user_str", "userAccountControl": "4194816"}
        self.assertIsNotNone(SecurityRuleEvaluator.evaluate_asrep_roastable(entry_str))

        # Hex as string (0x400200)
        entry_hex = {"sAMAccountName": "user_hex", "userAccountControl": "0x400200"}
        self.assertIsNotNone(SecurityRuleEvaluator.evaluate_asrep_roastable(entry_hex))

    def test_malformed_uac_type(self):
        """Evaluator must not crash when UAC is an unparseable type or negative."""
        entry = {"sAMAccountName": "corrupted_user", "userAccountControl": "INVALID_VALUE"}
        self.assertIsNone(SecurityRuleEvaluator.evaluate_asrep_roastable(entry))

        entry_none = {"sAMAccountName": "corrupted_user", "userAccountControl": None}
        self.assertIsNone(SecurityRuleEvaluator.evaluate_asrep_roastable(entry_none))

    # ----------------------------------------------------
    # Security Nuance & False-Positive Prevention Tests
    # ----------------------------------------------------

    def test_exclude_krbtgt_account(self):
        """The built-in KRBTGT account has an SPN (kadmin/changepw) but must not be flagged for Kerberoast."""
        entry = {
            "sAMAccountName": "krbtgt",
            "servicePrincipalName": ["kadmin/changepw"]
        }
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(entry))

    def test_exclude_gmsa_accounts(self):
        """Group Managed Service Accounts (gMSA) have SPNs but use 120-char rotating keys (not vulnerable)."""
        entry = {
            "sAMAccountName": "gmsa_account$",
            "objectClass": ["top", "person", "msDS-GroupManagedServiceAccount"],
            "servicePrincipalName": ["MSSQLSvc/db01.sevenkingdoms.local"]
        }
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(entry))

    # ----------------------------------------------------
    # Telemetry Failure & Non-Dict Input Tests
    # ----------------------------------------------------

    def test_failed_telemetry_collection_payload(self):
        """When a tool reports a connection timeout or network error, evaluator returns None cleanly."""
        failed_payload = {
            "status": "error",
            "error": "LDAPSocketOpenError: unable to open socket to 192.168.56.10:389"
        }
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(failed_payload))
        self.assertIsNone(SecurityRuleEvaluator.evaluate_asrep_roastable(failed_payload))

    def test_non_dict_payloads(self):
        """Ensures non-dict inputs (None, list, string) do not raise unhandled exceptions."""
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(None))
        self.assertIsNone(SecurityRuleEvaluator.evaluate_kerberoastable(["unexpected", "list"]))
        self.assertIsNone(SecurityRuleEvaluator.evaluate_asrep_roastable("random_string_from_stdout"))

if __name__ == '__main__':
    unittest.main()
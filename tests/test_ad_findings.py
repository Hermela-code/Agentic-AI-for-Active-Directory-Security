"""
Tests for AD Security Rules and Scenario Ground Truth
Author: Feben Solomon
"""

import unittest
from backend.security.finding_rules import SecurityRuleEvaluator, Severity

class TestADSecurityScenarios(unittest.TestCase):

    def test_kerberoastable_detection(self):
        # Sample raw LDAP entry matching GOAD-Light 'sql_svc'
        raw_ldap_user = {
            "sAMAccountName": "sql_svc",
            "servicePrincipalName": ["MSSQLSvc/kingslanding.sevenkingdoms.local:1433"],
            "memberOf": ["CN=Domain Users,CN=Users,DC=sevenkingdoms,DC=local"]
        }

        finding = SecurityRuleEvaluator.evaluate_kerberoastable(raw_ldap_user)
        
        self.assertIsNotNone(finding)
        self.assertEqual(finding.mitre_id, "T1558.003")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertTrue(finding.requires_approval)
        self.assertIn("sql_svc", finding.explanation)

    def test_machine_account_excluded_from_kerberoast(self):
        # Machine accounts ending in $ should not trigger user kerberoasting
        raw_ldap_machine = {
            "sAMAccountName": "KINGSLANDING$",
            "servicePrincipalName": ["HOST/kingslanding.sevenkingdoms.local"]
        }
        finding = SecurityRuleEvaluator.evaluate_kerberoastable(raw_ldap_machine)
        self.assertIsNone(finding)

    def test_asrep_roastable_detection(self):
        # Sample raw user with DONT_REQ_PREAUTH bit (0x400000 + 0x200 normal account = 4194816)
        raw_ldap_asrep_user = {
            "sAMAccountName": "brandon.stark",
            "userAccountControl": 4194816
        }

        finding = SecurityRuleEvaluator.evaluate_asrep_roastable(raw_ldap_asrep_user)
        
        self.assertIsNotNone(finding)
        self.assertEqual(finding.mitre_id, "T1558.004")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertTrue(finding.requires_approval)

if __name__ == '__main__':
    unittest.main()
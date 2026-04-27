import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import add_days, today

from vault.permissions import user_has_active_grant
from vault.tests.utils import make_credential, make_group, make_user


IGNORE_TEST_RECORD_DEPENDENCIES = ["User", "Employee", "Company", "Fiscal Year", "Vault Credential Entry"]


class TestVaultAccessGrant(IntegrationTestCase):
    def setUp(self):
        make_user("vlt-gr-owner@test.local", "Vault Manager")
        self.member = make_user("vlt-gr-member@test.local", "Vault Member")
        self.group = make_group("Grant Group", "vlt-gr-owner@test.local")
        self.cred = make_credential(self.group.name, portal="Grant Portal")

    def test_grant_create_logs_event(self):
        grant = frappe.get_doc(
            {
                "doctype": "Vault Access Grant",
                "credential": self.cred.name,
                "user": self.member.name,
                "is_active": 1,
            }
        ).insert(ignore_permissions=True)
        logs = frappe.get_all(
            "Vault Access Log",
            filters={"credential": self.cred.name, "action": "Access Granted"},
        )
        self.assertEqual(len(logs), 1)
        self.assertTrue(grant.granted_by)

    def test_user_has_active_grant_helper(self):
        frappe.get_doc(
            {
                "doctype": "Vault Access Grant",
                "credential": self.cred.name,
                "user": self.member.name,
                "is_active": 1,
            }
        ).insert(ignore_permissions=True)
        self.assertTrue(user_has_active_grant(self.cred.name, self.member.name))

    def test_past_expiry_blocked_at_validation(self):
        with self.assertRaises(frappe.ValidationError):
            frappe.get_doc(
                {
                    "doctype": "Vault Access Grant",
                    "credential": self.cred.name,
                    "user": self.member.name,
                    "access_expires_on": add_days(today(), -1),
                }
            ).insert(ignore_permissions=True)

    def test_revoke_logs_event(self):
        grant = frappe.get_doc(
            {
                "doctype": "Vault Access Grant",
                "credential": self.cred.name,
                "user": self.member.name,
                "is_active": 1,
            }
        ).insert(ignore_permissions=True)
        grant.is_active = 0
        grant.save(ignore_permissions=True)
        logs = frappe.get_all(
            "Vault Access Log",
            filters={"credential": self.cred.name, "action": "Access Revoked"},
        )
        self.assertEqual(len(logs), 1)

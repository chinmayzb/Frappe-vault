import frappe
from frappe.tests import IntegrationTestCase

from vault.audit import log_access
from vault.tests.utils import make_credential, make_group, make_user


class TestVaultAccessLog(IntegrationTestCase):
    def setUp(self):
        make_user("vlt-log-owner@test.local", "Vault Manager")
        self.group = make_group("Log Group", "vlt-log-owner@test.local")
        self.cred = make_credential(self.group.name, portal="Log Portal")

    def test_log_access_creates_row(self):
        log_access(self.cred.name, "View")
        row = frappe.get_all(
            "Vault Access Log",
            filters={"credential": self.cred.name, "action": "View"},
            fields=["name", "accessed_by", "timestamp"],
        )
        self.assertEqual(len(row), 1)
        self.assertTrue(row[0].timestamp)

    def test_invalid_action_falls_back_to_view(self):
        log_access(self.cred.name, "Bogus Action")
        row = frappe.get_all(
            "Vault Access Log",
            filters={"credential": self.cred.name, "action": "View"},
        )
        self.assertEqual(len(row), 1)

    def test_logs_are_immutable(self):
        log_access(self.cred.name, "Edit")
        log = frappe.get_all(
            "Vault Access Log", filters={"credential": self.cred.name}, limit=1, pluck="name"
        )[0]
        with self.assertRaises(frappe.ValidationError):
            frappe.delete_doc("Vault Access Log", log, ignore_permissions=True)

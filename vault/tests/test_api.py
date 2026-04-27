import frappe
from frappe.tests import IntegrationTestCase

from vault import api
from vault.tests.utils import make_credential, make_group, make_user


class TestVaultAPI(IntegrationTestCase):
    def setUp(self):
        self.owner = make_user("vlt-api-owner@test.local", "Vault Manager")
        self.outsider = make_user("vlt-api-outsider@test.local", "Vault Member")
        self.member = make_user("vlt-api-member@test.local", "Vault Member")
        self.group = make_group(
            "API Group",
            "vlt-api-owner@test.local",
            members=["vlt-api-member@test.local"],
        )
        self.cred = make_credential(self.group.name, portal="API Portal", password="P@ssword!")

    def _set_user(self, user: str):
        frappe.set_user(user)

    def test_owner_can_reveal(self):
        self._set_user("vlt-api-owner@test.local")
        out = api.reveal_password(self.cred.name)
        self.assertEqual(out["password"], "P@ssword!")
        # log row created
        logs = frappe.get_all(
            "Vault Access Log", filters={"credential": self.cred.name, "action": "Reveal"}
        )
        self.assertGreaterEqual(len(logs), 1)

    def test_group_member_can_reveal(self):
        self._set_user("vlt-api-member@test.local")
        out = api.reveal_password(self.cred.name)
        self.assertEqual(out["password"], "P@ssword!")

    def test_outsider_blocked(self):
        self._set_user("vlt-api-outsider@test.local")
        with self.assertRaises(frappe.PermissionError):
            api.reveal_password(self.cred.name)
        # denial event still logged
        logs = frappe.get_all(
            "Vault Access Log",
            filters={
                "credential": self.cred.name,
                "action": "Reveal",
                "accessed_by": "vlt-api-outsider@test.local",
            },
        )
        self.assertGreaterEqual(len(logs), 1)

    def test_grant_then_outsider_can_reveal(self):
        self._set_user("Administrator")
        api.grant_access(self.cred.name, "vlt-api-outsider@test.local")
        self._set_user("vlt-api-outsider@test.local")
        out = api.reveal_password(self.cred.name)
        self.assertEqual(out["password"], "P@ssword!")

    def test_member_cannot_grant(self):
        self._set_user("vlt-api-member@test.local")
        with self.assertRaises(frappe.PermissionError):
            api.grant_access(self.cred.name, "vlt-api-outsider@test.local")

    def tearDown(self):
        frappe.set_user("Administrator")

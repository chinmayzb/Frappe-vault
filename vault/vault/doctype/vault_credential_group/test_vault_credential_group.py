import frappe
from frappe.tests import IntegrationTestCase

from vault.tests.utils import make_user


class TestVaultCredentialGroup(IntegrationTestCase):
    def test_create_basic_group(self):
        make_user("vlt-owner@test.local", "Vault Manager")
        doc = frappe.get_doc(
            {
                "doctype": "Vault Credential Group",
                "group_name": "Finance Portals",
                "owner_user": "vlt-owner@test.local",
                "is_active": 1,
            }
        ).insert(ignore_permissions=True)
        self.assertEqual(doc.name, "Finance Portals")
        self.assertTrue(doc.is_active)

    def test_duplicate_member_raises(self):
        make_user("vlt-o2@test.local", "Vault Manager")
        make_user("vlt-m1@test.local", "Vault Member")
        doc = frappe.get_doc(
            {
                "doctype": "Vault Credential Group",
                "group_name": "Banking Portals",
                "owner_user": "vlt-o2@test.local",
            }
        )
        doc.append("members", {"user": "vlt-m1@test.local"})
        doc.append("members", {"user": "vlt-m1@test.local"})
        with self.assertRaises(frappe.ValidationError):
            doc.insert(ignore_permissions=True)

    def test_unique_group_name(self):
        make_user("vlt-o3@test.local", "Vault Manager")
        frappe.get_doc(
            {
                "doctype": "Vault Credential Group",
                "group_name": "HR Portals",
                "owner_user": "vlt-o3@test.local",
            }
        ).insert(ignore_permissions=True)
        with self.assertRaises(frappe.exceptions.DuplicateEntryError):
            frappe.get_doc(
                {
                    "doctype": "Vault Credential Group",
                    "group_name": "HR Portals",
                    "owner_user": "vlt-o3@test.local",
                }
            ).insert(ignore_permissions=True)

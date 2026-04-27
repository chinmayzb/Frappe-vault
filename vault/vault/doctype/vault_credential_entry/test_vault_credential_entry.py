import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils.password import get_decrypted_password

from vault.tests.utils import make_credential, make_group, make_user


IGNORE_TEST_RECORD_DEPENDENCIES = ["User", "Employee", "Company", "Fiscal Year", "Vault Credential Group"]


class TestVaultCredentialEntry(IntegrationTestCase):
    def setUp(self):
        self.owner = make_user("vlt-ce-owner@test.local", "Vault Manager")
        self.group = make_group("CE Group", "vlt-ce-owner@test.local")

    def test_password_stored_encrypted(self):
        ce = make_credential(self.group.name, password="super-s3cret!")
        # Stored value in the auth table should NOT equal raw plaintext
        plain = get_decrypted_password(ce.doctype, ce.name, "password", raise_exception=False)
        self.assertEqual(plain, "super-s3cret!")
        # And the password field on the DocType should not contain plaintext after reload
        ce.reload()
        self.assertNotEqual(ce.password, "super-s3cret!")

    def test_initial_save_creates_v1(self):
        ce = make_credential(self.group.name, portal="V1 Portal")
        versions = frappe.get_all(
            "Vault Credential Version",
            filters={"parent_credential": ce.name},
            fields=["version_number"],
        )
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].version_number, 1)

    def test_password_change_creates_new_version_with_hash(self):
        ce = make_credential(self.group.name, portal="VRot Portal", password="old-pw")
        ce.password = "new-pw"
        ce.save(ignore_permissions=True)
        rows = frappe.get_all(
            "Vault Credential Version",
            filters={"parent_credential": ce.name},
            fields=["version_number", "password_hash", "change_summary"],
            order_by="version_number asc",
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1].version_number, 2)
        # Old password hash must be present and never empty for a password change
        self.assertTrue(rows[1].password_hash)
        # Hash must not equal plaintext
        self.assertNotEqual(rows[1].password_hash, "old-pw")
        self.assertIn("password", (rows[1].change_summary or "").lower())

    def test_no_version_created_when_nothing_tracked_changes(self):
        ce = make_credential(self.group.name, portal="Static Portal")
        # Touching a non-tracked field should not create a new version
        ce.last_revealed_at = frappe.utils.now_datetime()
        ce.save(ignore_permissions=True)
        rows = frappe.get_all(
            "Vault Credential Version", filters={"parent_credential": ce.name}
        )
        self.assertEqual(len(rows), 1)

    def test_audit_log_created_on_create_and_update(self):
        ce = make_credential(self.group.name, portal="Audit Portal")
        ce.notes = "rotation tracker"
        ce.save(ignore_permissions=True)
        logs = frappe.get_all(
            "Vault Access Log",
            filters={"credential": ce.name, "action": "Edit"},
        )
        # one for create, one for update
        self.assertGreaterEqual(len(logs), 2)

    def test_expiry_in_past_marks_expired(self):
        ce = make_credential(self.group.name, portal="Past Portal")
        ce.account_expiry_date = "2020-01-01"
        ce.save(ignore_permissions=True)
        ce.reload()
        self.assertEqual(ce.status, "Expired")

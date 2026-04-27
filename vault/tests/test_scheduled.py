import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import add_days, today

from vault.scheduled import run_expiry_checker, sweep_expired_grants
from vault.tests.utils import make_credential, make_group, make_user


class TestScheduledJobs(IntegrationTestCase):
    def test_expiry_checker_marks_past_expiries(self):
        make_user("vlt-sched-1@test.local", "Vault Manager")
        group = make_group("Sched G1", "vlt-sched-1@test.local")
        cred = make_credential(group.name, portal="Sched Portal")
        frappe.db.set_value(
            "Vault Credential Entry",
            cred.name,
            {"expiry_date": add_days(today(), -3), "status": "Active"},
        )
        frappe.db.commit()
        run_expiry_checker()
        self.assertEqual(
            frappe.db.get_value("Vault Credential Entry", cred.name, "status"), "Expired"
        )

    def test_grant_sweeper_deactivates_expired(self):
        make_user("vlt-sched-2@test.local", "Vault Manager")
        member = make_user("vlt-sched-3@test.local", "Vault Member")
        group = make_group("Sched G2", "vlt-sched-2@test.local")
        cred = make_credential(group.name, portal="Sched Portal 2")
        grant = frappe.get_doc(
            {
                "doctype": "Vault Access Grant",
                "credential": cred.name,
                "user": member.name,
                "is_active": 1,
            }
        ).insert(ignore_permissions=True)
        # Bypass validation by writing the past expiry directly
        frappe.db.set_value("Vault Access Grant", grant.name, "expires_on", add_days(today(), -1))
        frappe.db.commit()

        sweep_expired_grants()
        self.assertEqual(
            frappe.db.get_value("Vault Access Grant", grant.name, "is_active"), 0
        )

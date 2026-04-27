import frappe
from frappe.model.document import Document

from vault.audit import log_access


class VaultAccessGrant(Document):
    def validate(self):
        if not self.granted_by:
            self.granted_by = frappe.session.user
        if not self.granted_at:
            self.granted_at = frappe.utils.now_datetime()
        if self.expires_on:
            from frappe.utils import getdate, today
            if getdate(self.expires_on) < getdate(today()):
                frappe.throw("Expiry date cannot be in the past.")

    def after_insert(self):
        log_access(
            self.credential,
            "Access Granted",
            user=self.user,
            extra=f"Granted by {self.granted_by} (grant {self.name})",
        )

    def on_update(self):
        if self.has_value_changed("is_active") and not self.is_active:
            log_access(
                self.credential,
                "Access Revoked",
                user=self.user,
                extra=f"Grant {self.name} deactivated",
            )

    def on_trash(self):
        log_access(
            self.credential,
            "Access Revoked",
            user=self.user,
            extra=f"Grant {self.name} deleted",
        )

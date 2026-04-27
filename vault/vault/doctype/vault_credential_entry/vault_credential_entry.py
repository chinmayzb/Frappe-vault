import frappe
from frappe.model.document import Document

from vault.audit import hash_password, log_access


TRACKED_FIELDS = ("portal_name", "portal_url", "username", "password", "notes", "status", "account_expiry_date")

_INTERVAL_DAYS = {
    "30 Days": 30,
    "60 Days": 60,
    "90 Days": 90,
    "180 Days": 180,
    "1 Year": 365,
}


class VaultCredentialEntry(Document):
    def validate(self):
        from frappe.utils import getdate, today
        if self.account_expiry_date:
            if getdate(self.account_expiry_date) < getdate(today()) and self.status == "Active":
                self.status = "Expired"
        self.last_updated_by = frappe.session.user

    def before_save(self):
        self._diff_summary = []
        self._old_password_hash = None
        self._password_rotated = False
        if self.is_new():
            if self.password_reset_interval and not self.password_reset_due:
                from frappe.utils import add_days, today
                days = _INTERVAL_DAYS.get(self.password_reset_interval)
                if days:
                    self.password_reset_due = add_days(today(), days)
            return
        for field in TRACKED_FIELDS:
            if not self.has_value_changed(field):
                continue
            if field == "password":
                old_pw = frappe.utils.password.get_decrypted_password(
                    self.doctype, self.name, "password", raise_exception=False
                )
                self._old_password_hash = hash_password(old_pw or "")
                self._diff_summary.append("password changed")
                self._password_rotated = True
            else:
                self._diff_summary.append(f"{field} updated")

        if self.password_reset_interval:
            from frappe.utils import add_days, today
            days = _INTERVAL_DAYS.get(self.password_reset_interval)
            if days and (self._password_rotated or not self.password_reset_due):
                self.password_reset_due = add_days(today(), days)

        if self._password_rotated:
            from frappe.utils import now_datetime
            self.last_password_rotated_at = now_datetime()

    def after_insert(self):
        _create_version(self, "v1 — initial save")
        log_access(self.name, "Edit", extra="Initial create")

    def on_update(self):
        summary = "; ".join(getattr(self, "_diff_summary", []) or [])
        if not summary:
            return
        _create_version(
            self,
            summary=summary,
            password_hash=getattr(self, "_old_password_hash", None) or "",
        )
        log_access(self.name, "Edit", extra=summary)

    def on_trash(self):
        log_access(self.name, "Delete")
        # Clean up dependent rows (versions, logs, grants kept by default for audit)
        frappe.db.delete("Vault Credential Version", {"parent_credential": self.name})


def _create_version(doc, summary: str, password_hash: str = ""):
    current = frappe.db.get_value(doc.doctype, doc.name, "version_count") or 0
    next_no = int(current) + 1
    frappe.get_doc(
        {
            "doctype": "Vault Credential Version",
            "parent_credential": doc.name,
            "version_number": next_no,
            "changed_by": frappe.session.user,
            "change_summary": summary[:500],
            "password_hash": password_hash,
        }
    ).insert(ignore_permissions=True)
    frappe.db.set_value(doc.doctype, doc.name, "version_count", next_no, update_modified=False)
    doc.version_count = next_no



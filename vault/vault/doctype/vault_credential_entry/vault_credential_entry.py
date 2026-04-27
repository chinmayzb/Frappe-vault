import frappe
from frappe.model.document import Document

from vault.audit import hash_password, log_access


TRACKED_FIELDS = ("portal_name", "portal_url", "username", "password", "notes", "status", "expiry_date")


class VaultCredentialEntry(Document):
    def validate(self):
        if self.expiry_date:
            from frappe.utils import getdate, today
            if getdate(self.expiry_date) < getdate(today()) and self.status == "Active":
                self.status = "Expired"
        self.last_updated_by = frappe.session.user

    def before_save(self):
        old = self.get_doc_before_save()
        self._old_password_hash = None
        self._diff_summary = []
        if old:
            for field in TRACKED_FIELDS:
                old_val = old.get(field)
                new_val = self.get(field)
                if field == "password":
                    old_pw = self.get_db_value("password") if hasattr(self, "get_db_value") else None
                    try:
                        old_pw = frappe.utils.password.get_decrypted_password(
                            self.doctype, self.name, "password", raise_exception=False
                        )
                    except Exception:
                        old_pw = None
                    new_pw = self.password or ""
                    if (old_pw or "") != (new_pw or ""):
                        self._old_password_hash = hash_password(old_pw or "")
                        self._diff_summary.append("password changed")
                elif (old_val or "") != (new_val or ""):
                    self._diff_summary.append(f"{field}: {old_val!r} → {new_val!r}")

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
    next_no = (doc.version_count or 0) + 1
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



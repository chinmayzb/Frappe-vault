import frappe
from frappe.model.document import Document


class VaultAccessLog(Document):
    def before_insert(self):
        if not self.timestamp:
            self.timestamp = frappe.utils.now_datetime()

    def on_trash(self):
        # Audit trail is immutable
        frappe.throw("Vault Access Log entries cannot be deleted.")

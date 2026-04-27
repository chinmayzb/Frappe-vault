import frappe
from frappe.model.document import Document


class VaultCredentialGroup(Document):
    def validate(self):
        seen = set()
        for row in (self.members or []):
            if row.user in seen:
                frappe.throw(f"Duplicate member: {row.user}")
            seen.add(row.user)

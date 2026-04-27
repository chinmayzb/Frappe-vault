import hashlib

import frappe


VALID_ACTIONS = {
    "View",
    "Reveal",
    "Copy Username",
    "Copy Password",
    "Edit",
    "Delete",
    "Access Granted",
    "Access Revoked",
}


def log_access(credential: str, action: str, user: str = None, extra: str = None):
    """Create an immutable audit log entry. Failures here must never break the caller."""
    if action not in VALID_ACTIONS:
        action = "View"
    if not user:
        user = frappe.session.user

    request = getattr(frappe.local, "request", None)
    ip_address = ""
    if request is not None:
        ip_address = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or ""
        )
    session_id = getattr(frappe.local, "session", {}).get("sid", "") if getattr(frappe.local, "session", None) else ""

    try:
        doc = frappe.get_doc(
            {
                "doctype": "Vault Access Log",
                "credential": credential,
                "accessed_by": user,
                "action": action,
                "ip_address": ip_address[:140],
                "session_id": (session_id or "")[:140],
                "remarks": extra or "",
            }
        )
        doc.flags.ignore_permissions = True
        doc.insert(ignore_permissions=True)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "Vault audit log insert failed")


def hash_password(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

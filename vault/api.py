import frappe
from frappe import _

from vault.audit import log_access
from vault.permissions import credential_entry_has_permission, user_has_active_grant


@frappe.whitelist()
def reveal_password(credential: str) -> dict:
    """Decrypt and return the password for a credential.

    Enforces:
    - Authenticated user
    - Read permission on the credential (group or grant)
    - Rate limit (10/min/user)
    Logs every reveal as an audit event.
    """
    if frappe.session.user == "Guest":
        frappe.throw(_("Authentication required"), frappe.PermissionError)

    if not credential:
        frappe.throw(_("Credential is required"))

    # Rate limit: 10 per minute per user per credential type
    frappe.rate_limiter.rate_limit(
        key=f"vault_reveal:{frappe.session.user}",
        limit=10,
        seconds=60,
    )

    doc = frappe.get_doc("Vault Credential Entry", credential)

    if not credential_entry_has_permission(doc, frappe.session.user, "read"):
        log_access(credential, "Reveal", extra="DENIED - no permission")
        frappe.throw(_("You do not have permission to reveal this credential"), frappe.PermissionError)

    # Get plain password via Frappe password fieldtype (auto-decrypts)
    password = doc.get_password("password", raise_exception=False)

    log_access(credential, "Reveal")
    return {
        "username": doc.username or "",
        "password": password or "",
        "ttl_seconds": 30,
    }


@frappe.whitelist()
def copy_password(credential: str) -> dict:
    """Same as reveal but logged as Copy Password."""
    if frappe.session.user == "Guest":
        frappe.throw(_("Authentication required"), frappe.PermissionError)
    if not credential:
        frappe.throw(_("Credential is required"))

    frappe.rate_limiter.rate_limit(
        key=f"vault_copy_pw:{frappe.session.user}",
        limit=20,
        seconds=60,
    )
    doc = frappe.get_doc("Vault Credential Entry", credential)
    if not credential_entry_has_permission(doc, frappe.session.user, "read"):
        log_access(credential, "Copy Password", extra="DENIED - no permission")
        frappe.throw(_("You do not have permission"), frappe.PermissionError)

    password = doc.get_password("password", raise_exception=False)
    log_access(credential, "Copy Password")
    return {"password": password or ""}


@frappe.whitelist()
def copy_username(credential: str) -> dict:
    """Quick-copy username. Logged as a low-sensitivity event."""
    if frappe.session.user == "Guest":
        frappe.throw(_("Authentication required"), frappe.PermissionError)
    if not credential:
        frappe.throw(_("Credential is required"))

    doc = frappe.get_doc("Vault Credential Entry", credential)
    if not credential_entry_has_permission(doc, frappe.session.user, "read"):
        frappe.throw(_("You do not have permission"), frappe.PermissionError)

    log_access(credential, "Copy Username")
    return {"username": doc.username or ""}


@frappe.whitelist()
def grant_access(credential: str, user: str, expires_on: str = None) -> str:
    """Issue an access grant. Vault Manager / Vault Admin only."""
    roles = set(frappe.get_roles(frappe.session.user))
    if not roles & {"System Manager", "Vault Admin", "Vault Manager"}:
        frappe.throw(_("Only Vault Managers can grant access"), frappe.PermissionError)

    if frappe.db.exists(
        "Vault Access Grant",
        {"credential": credential, "user": user, "is_active": 1},
    ):
        frappe.throw(_("User already has an active grant on this credential"))

    grant = frappe.get_doc(
        {
            "doctype": "Vault Access Grant",
            "credential": credential,
            "user": user,
            "expires_on": expires_on or None,
            "is_active": 1,
            "granted_by": frappe.session.user,
        }
    )
    grant.insert()
    return grant.name


@frappe.whitelist()
def revoke_access(grant: str) -> None:
    roles = set(frappe.get_roles(frappe.session.user))
    if not roles & {"System Manager", "Vault Admin", "Vault Manager"}:
        frappe.throw(_("Only Vault Managers can revoke access"), frappe.PermissionError)

    doc = frappe.get_doc("Vault Access Grant", grant)
    doc.is_active = 0
    doc.save()
    log_access(doc.credential, "Access Revoked", extra=f"Grant {grant} revoked")

"""Shared helpers for Vault test cases."""
import frappe


def ensure_role(role_name: str):
    if not frappe.db.exists("Role", role_name):
        frappe.get_doc({"doctype": "Role", "role_name": role_name, "desk_access": 1}).insert(
            ignore_permissions=True
        )


def make_user(email: str, role: str = "Vault Member"):
    ensure_role(role)
    if frappe.db.exists("User", email):
        user = frappe.get_doc("User", email)
    else:
        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": email.split("@")[0],
                "send_welcome_email": 0,
                "user_type": "System User",
            }
        ).insert(ignore_permissions=True)
    if not any(r.role == role for r in user.roles):
        user.append("roles", {"role": role})
        user.save(ignore_permissions=True)
    return user


def make_group(name: str, owner_user: str, members=None):
    if frappe.db.exists("Vault Credential Group", name):
        return frappe.get_doc("Vault Credential Group", name)
    doc = frappe.get_doc(
        {
            "doctype": "Vault Credential Group",
            "group_name": name,
            "owner_user": owner_user,
            "is_active": 1,
        }
    )
    for m in members or []:
        doc.append("members", {"user": m, "access_level": "Read"})
    doc.insert(ignore_permissions=True)
    return doc


def make_credential(group: str, portal: str = "Test Portal", username: str = "u@test", password: str = "secret-1"):
    return frappe.get_doc(
        {
            "doctype": "Vault Credential Entry",
            "portal_name": portal,
            "portal_url": "https://example.com",
            "credential_group": group,
            "username": username,
            "password": password,
            "status": "Active",
        }
    ).insert(ignore_permissions=True)

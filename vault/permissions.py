import frappe


def _is_admin(user: str) -> bool:
    if user == "Administrator":
        return True
    roles = set(frappe.get_roles(user))
    return bool(roles & {"System Manager", "Vault Admin", "Vault Manager"})


def credential_group_query(user: str) -> str:
    """Limit Credential Group list to groups the user owns or is a member of."""
    if not user:
        user = frappe.session.user
    if _is_admin(user):
        return ""
    user_quoted = frappe.db.escape(user)
    return f"""(
        `tabVault Credential Group`.owner_user = {user_quoted}
        OR exists(
            select 1 from `tabVault Credential Group Member` m
            where m.parent = `tabVault Credential Group`.name
              and m.user = {user_quoted}
        )
    )"""


def credential_entry_query(user: str) -> str:
    """Limit Credential Entry list to entries the user can see."""
    if not user:
        user = frappe.session.user
    if _is_admin(user):
        return ""
    user_quoted = frappe.db.escape(user)
    return f"""(
        exists(
            select 1 from `tabVault Credential Group` g
            left join `tabVault Credential Group Member` m on m.parent = g.name
            where g.name = `tabVault Credential Entry`.credential_group
              and (g.owner_user = {user_quoted} or m.user = {user_quoted})
        )
        OR exists(
            select 1 from `tabVault Access Grant` ag
            where ag.credential = `tabVault Credential Entry`.name
              and ag.user = {user_quoted}
              and ag.is_active = 1
        )
    )"""


def access_log_query(user: str) -> str:
    if not user:
        user = frappe.session.user
    if _is_admin(user):
        return ""
    user_quoted = frappe.db.escape(user)
    return f"`tabVault Access Log`.accessed_by = {user_quoted}"


def access_grant_query(user: str) -> str:
    if not user:
        user = frappe.session.user
    if _is_admin(user):
        return ""
    user_quoted = frappe.db.escape(user)
    return f"`tabVault Access Grant`.user = {user_quoted}"


def credential_group_has_permission(doc, user: str = None, permission_type: str = None) -> bool:
    if not user:
        user = frappe.session.user
    if _is_admin(user):
        return True
    if doc.owner_user == user:
        return True
    for member in (doc.get("members") or []):
        if member.user == user:
            return True
    return False


def credential_entry_has_permission(doc, user: str = None, permission_type: str = None) -> bool:
    if not user:
        user = frappe.session.user
    if _is_admin(user):
        return True

    # Group-based access
    if doc.credential_group:
        group = frappe.get_cached_doc("Vault Credential Group", doc.credential_group)
        if group.owner_user == user:
            return True
        for member in (group.members or []):
            if member.user == user:
                return True

    # Per-credential active grant
    grant = frappe.db.exists(
        "Vault Access Grant",
        {"credential": doc.name, "user": user, "is_active": 1},
    )
    return bool(grant)


def user_has_active_grant(credential_name: str, user: str) -> bool:
    grant_name = frappe.db.exists(
        "Vault Access Grant",
        {
            "credential": credential_name,
            "user": user,
            "is_active": 1,
        },
    )
    if not grant_name:
        return False
    grant = frappe.db.get_value(
        "Vault Access Grant",
        grant_name,
        ["access_expires_on"],
        as_dict=True,
    )
    if grant and grant.access_expires_on:
        from frappe.utils import getdate, today
        if getdate(grant.access_expires_on) < getdate(today()):
            return False
    return True

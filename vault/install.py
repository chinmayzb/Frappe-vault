import frappe


DEFAULT_ROLES = [
    {"role_name": "Vault Admin", "desk_access": 1},
    {"role_name": "Vault Manager", "desk_access": 1},
    {"role_name": "Vault Member", "desk_access": 1},
]


def after_install():
    create_default_roles()


def after_migrate():
    set_desktop_icon_app()


def before_uninstall():
    pass


def set_desktop_icon_app():
    frappe.db.set_value(
        "Desktop Icon",
        {"label": "Vault", "app": ("is", "not set")},
        "app",
        "vault",
        update_modified=False,
    )


def create_default_roles():
    for role in DEFAULT_ROLES:
        if not frappe.db.exists("Role", role["role_name"]):
            doc = frappe.get_doc(
                {
                    "doctype": "Role",
                    "role_name": role["role_name"],
                    "desk_access": role["desk_access"],
                }
            )
            doc.insert(ignore_permissions=True)
    # Roles must be persisted before the rest of the install hooks run
    # (subsequent code assigns these roles to default users).
    frappe.db.commit()  # nosemgrep

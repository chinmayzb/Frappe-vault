import frappe


DEFAULT_ROLES = [
    {"role_name": "Vault Admin", "desk_access": 1},
    {"role_name": "Vault Manager", "desk_access": 1},
    {"role_name": "Vault Member", "desk_access": 1},
]


def after_install():
    create_default_roles()


def before_uninstall():
    pass


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
    frappe.db.commit()

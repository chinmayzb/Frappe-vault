import frappe
from frappe.utils import add_days, getdate, today

from vault.audit import log_access


def run_expiry_checker():
    """Daily job — flag expiring credentials and notify owners."""
    today_d = getdate(today())

    # 1. Mark expired
    expired = frappe.get_all(
        "Vault Credential Entry",
        filters={"account_expiry_date": ["<", today_d], "status": "Active"},
        pluck="name",
    )
    for name in expired:
        frappe.db.set_value("Vault Credential Entry", name, "status", "Expired")

    # 2. Send reminders for 30 / 7 / 1 day windows
    for window in (30, 7, 1):
        target = add_days(today_d, window)
        rows = frappe.get_all(
            "Vault Credential Entry",
            filters={"account_expiry_date": target, "status": "Active"},
            fields=["name", "portal_name", "owner", "credential_group"],
        )
        for row in rows:
            recipients = _resolve_owners(row.credential_group, row.owner)
            if not recipients:
                continue
            try:
                frappe.sendmail(
                    recipients=recipients,
                    subject=f"[Vault] {row.portal_name} expires in {window} day(s)",
                    message=(
                        f"Credential <b>{row.portal_name}</b> is set to expire on {target}.<br>"
                        f"Please rotate it before then."
                    ),
                )
            except Exception:
                frappe.log_error(frappe.get_traceback(), "Vault expiry email failed")
    frappe.db.commit()


def _resolve_owners(group_name: str, fallback: str) -> list:
    recipients = set()
    if fallback:
        recipients.add(fallback)
    if group_name:
        owner_user = frappe.db.get_value("Vault Credential Group", group_name, "owner_user")
        if owner_user:
            recipients.add(owner_user)
    return [r for r in recipients if r and r not in {"Administrator", "Guest"}]


def sweep_expired_grants():
    """Hourly — auto-revoke grants past access_expires_on."""
    today_d = getdate(today())
    grants = frappe.get_all(
        "Vault Access Grant",
        filters={"is_active": 1, "access_expires_on": ["<", today_d]},
        fields=["name", "credential", "user"],
    )
    for grant in grants:
        frappe.db.set_value("Vault Access Grant", grant.name, "is_active", 0)
        log_access(
            grant.credential,
            "Access Revoked",
            user=grant.user,
            extra=f"Auto-revoked: grant {grant.name} expired",
        )
    frappe.db.commit()


def notify_password_reset_due():
    """Daily — alert group owners when a credential's Password Reset Due date is today or overdue."""
    today_d = getdate(today())

    overdue = frappe.get_all(
        "Vault Credential Entry",
        filters={"password_reset_due": ["<=", today_d], "status": "Active"},
        fields=["name", "portal_name", "owner", "credential_group", "password_reset_due"],
    )
    for row in overdue:
        recipients = _resolve_owners(row.credential_group, row.owner)
        if not recipients:
            continue
        due_label = "today" if row.password_reset_due == today_d else f"on {row.password_reset_due} (overdue)"
        try:
            frappe.sendmail(
                recipients=recipients,
                subject=f"[Vault] Password rotation due — {row.portal_name}",
                message=(
                    f"The password for <b>{row.portal_name}</b> is due for rotation {due_label}.<br>"
                    f"Please rotate it and save the credential to reset the next due date."
                ),
            )
        except Exception:
            frappe.log_error(frappe.get_traceback(), "Vault password reset email failed")
    frappe.db.commit()


def archive_old_logs():
    """Monthly — delete access logs older than 12 months unless config overrides."""
    retention_days = frappe.db.get_single_value("System Settings", "vault_log_retention_days") or 365
    cutoff = add_days(getdate(today()), -int(retention_days))
    frappe.db.delete("Vault Access Log", {"timestamp": ["<", cutoff]})
    frappe.db.commit()

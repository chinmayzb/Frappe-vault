import frappe
from frappe.utils import add_days, getdate, today

from vault.audit import log_access


def _get_settings():
    """Return Vault Settings as a dict with safe defaults."""
    try:
        return frappe.get_single("Vault Settings")
    except Exception:
        return frappe._dict(
            notify_password_reset_due=1,
            notify_days_before_reset=7,
            notify_administrator=1,
            additional_notify_emails="",
            notify_account_expiry=1,
            expiry_notify_days_before=30,
            notify_on_grant=0,
            notify_on_revoke=0,
        )


def _resolve_owners(group_name: str, fallback: str, include_admin: bool = False, extra_emails: str = "") -> list:
    recipients = set()
    if fallback and fallback not in {"Administrator", "Guest"}:
        recipients.add(fallback)
    if group_name:
        owner_user = frappe.db.get_value("Vault Credential Group", group_name, "owner_user")
        if owner_user and owner_user not in {"Administrator", "Guest"}:
            recipients.add(owner_user)
    if include_admin:
        admin_email = frappe.db.get_value("User", "Administrator", "email")
        if admin_email:
            recipients.add(admin_email)
    if extra_emails:
        for e in extra_emails.split(","):
            e = e.strip()
            if e:
                recipients.add(e)
    return list(recipients)


def run_expiry_checker():
    """Daily job — flag expiring credentials and notify owners."""
    settings = _get_settings()
    today_d = getdate(today())

    # 1. Mark expired
    expired = frappe.get_all(
        "Vault Credential Entry",
        filters={"account_expiry_date": ["<", today_d], "status": "Active"},
        pluck="name",
    )
    for name in expired:
        frappe.db.set_value("Vault Credential Entry", name, "status", "Expired")

    if not settings.notify_account_expiry:
        frappe.db.commit()
        return

    # 2. Send reminders — always at 7 and 1 day, plus the configured window
    windows = sorted({int(settings.expiry_notify_days_before or 30), 7, 1}, reverse=True)
    for window in windows:
        target = add_days(today_d, window)
        rows = frappe.get_all(
            "Vault Credential Entry",
            filters={"account_expiry_date": target, "status": "Active"},
            fields=["name", "portal_name", "owner", "credential_group"],
        )
        for row in rows:
            recipients = _resolve_owners(
                row.credential_group, row.owner,
                include_admin=settings.notify_administrator,
                extra_emails=settings.additional_notify_emails or "",
            )
            if not recipients:
                continue
            try:
                frappe.sendmail(
                    recipients=recipients,
                    subject=f"[Vault] {row.portal_name} account expires in {window} day(s)",
                    message=(
                        f"The account for <b>{row.portal_name}</b> is set to expire on <b>{target}</b>.<br><br>"
                        f"Please renew the subscription or update the credential before then."
                    ),
                )
            except Exception:
                frappe.log_error(frappe.get_traceback(), "Vault expiry email failed")
    frappe.db.commit()


def sweep_expired_grants():
    """Hourly — auto-revoke grants past access_expires_on."""
    settings = _get_settings()
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
        if settings.notify_on_revoke:
            _notify_user_access_change(grant.user, grant.credential, revoked=True)
    frappe.db.commit()


def notify_password_reset_due():
    """Daily — alert when a credential's password reset is due or approaching."""
    settings = _get_settings()
    if not settings.notify_password_reset_due:
        return

    today_d = getdate(today())
    advance = int(settings.notify_days_before_reset or 0)

    # Collect: overdue + today + advance-day heads-up
    due_dates = {today_d}
    if advance > 0:
        due_dates.add(add_days(today_d, advance))
    overdue_filter = ["<=", today_d]

    # Overdue and today
    rows = frappe.get_all(
        "Vault Credential Entry",
        filters={"password_reset_due": overdue_filter, "status": "Active"},
        fields=["name", "portal_name", "owner", "credential_group", "password_reset_due"],
    )
    # Advance warning
    if advance > 0:
        advance_target = add_days(today_d, advance)
        rows += frappe.get_all(
            "Vault Credential Entry",
            filters={"password_reset_due": advance_target, "status": "Active"},
            fields=["name", "portal_name", "owner", "credential_group", "password_reset_due"],
        )

    seen = set()
    for row in rows:
        if row.name in seen:
            continue
        seen.add(row.name)

        recipients = _resolve_owners(
            row.credential_group, row.owner,
            include_admin=settings.notify_administrator,
            extra_emails=settings.additional_notify_emails or "",
        )
        if not recipients:
            continue

        if row.password_reset_due == today_d:
            due_label = "today"
        elif getdate(row.password_reset_due) < today_d:
            due_label = f"on {row.password_reset_due} <b>(overdue)</b>"
        else:
            due_label = f"on {row.password_reset_due} ({advance} days from now)"

        try:
            frappe.sendmail(
                recipients=recipients,
                subject=f"[Vault] Password rotation due — {row.portal_name}",
                message=(
                    f"The password for <b>{row.portal_name}</b> is due for rotation {due_label}.<br><br>"
                    f"Open the credential in Vault, change the password, and save — "
                    f"the next due date will be recalculated automatically."
                ),
            )
        except Exception:
            frappe.log_error(frappe.get_traceback(), "Vault password reset email failed")
    frappe.db.commit()


def notify_access_granted(credential: str, user: str):
    """Called from VaultAccessGrant.after_insert when notify_on_grant is enabled."""
    settings = _get_settings()
    if not settings.notify_on_grant:
        return
    _notify_user_access_change(user, credential, revoked=False)


def _notify_user_access_change(user: str, credential: str, revoked: bool):
    user_email = frappe.db.get_value("User", user, "email")
    if not user_email or user_email in {"Administrator", "Guest"}:
        return
    portal_name = frappe.db.get_value("Vault Credential Entry", credential, "portal_name") or credential
    action = "revoked" if revoked else "granted"
    subject = f"[Vault] Your access to {portal_name} has been {action}"
    message = (
        f"Your access to the credential <b>{portal_name}</b> has been <b>{action}</b>.<br><br>"
        + (f"You can no longer reveal or copy this password." if revoked
           else f"Log in to Vault to reveal or copy the password.")
    )
    try:
        frappe.sendmail(recipients=[user_email], subject=subject, message=message)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "Vault access change email failed")


def archive_old_logs():
    """Monthly — delete access logs older than 12 months unless config overrides."""
    retention_days = 365
    cutoff = add_days(getdate(today()), -int(retention_days))
    frappe.db.delete("Vault Access Log", {"timestamp": ["<", cutoff]})
    frappe.db.commit()

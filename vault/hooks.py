app_name = "vault"
app_title = "Vault"
app_publisher = "Codeyard"
app_description = "Enterprise-grade credentials manager for the Frappe ecosystem."
app_email = "chinmaybhatk@gmail.com"
app_license = "MIT"
app_icon = "octicon octicon-lock"
app_color = "#1a1a1a"
required_apps = ["frappe"]

# DocType lifecycle methods are defined on the Document classes themselves.
doc_events = {}

# Permission query conditions — restrict list views to authorised users
permission_query_conditions = {
    "Vault Credential Entry": "vault.permissions.credential_entry_query",
    "Vault Credential Group": "vault.permissions.credential_group_query",
    "Vault Access Log": "vault.permissions.access_log_query",
    "Vault Access Grant": "vault.permissions.access_grant_query",
}

has_permission = {
    "Vault Credential Entry": "vault.permissions.credential_entry_has_permission",
    "Vault Credential Group": "vault.permissions.credential_group_has_permission",
}

# Scheduled tasks
scheduler_events = {
    "daily": [
        "vault.scheduled.run_expiry_checker",
        "vault.scheduled.notify_password_reset_due",
    ],
    "hourly": [
        "vault.scheduled.sweep_expired_grants",
    ],
    "monthly": [
        "vault.scheduled.archive_old_logs",
    ],
}

# Fixtures — install default roles on first install
fixtures = [
    {
        "doctype": "Role",
        "filters": [["name", "in", ["Vault Admin", "Vault Manager", "Vault Member"]]],
    }
]

after_install = "vault.install.after_install"
before_uninstall = "vault.install.before_uninstall"

# Override messages where useful
website_route_rules = []

# Include CSS/JS if present
app_include_css = "/assets/vault/css/vault.css"
app_include_js = "/assets/vault/js/vault.js"

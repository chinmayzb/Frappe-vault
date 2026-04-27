frappe.ui.form.on("Vault Credential Entry", {
    refresh(frm) {
        if (frm.is_new()) return;

        frm.add_custom_button(__("Reveal Password"), () => {
            frappe.call({
                method: "vault.api.reveal_password",
                args: { credential: frm.doc.name },
                callback: (r) => {
                    if (!r.message) return;
                    const pw = r.message.password || "";
                    const ttl = r.message.ttl_seconds || 30;
                    frappe.msgprint({
                        title: __("Password (auto-hides in {0}s)", [ttl]),
                        message: `<pre style="font-size:14px">${frappe.utils.escape_html(pw)}</pre>`,
                        indicator: "orange",
                    });
                    setTimeout(() => frappe.hide_msgprint && frappe.hide_msgprint(), ttl * 1000);
                },
            });
        }, __("Actions"));

        frm.add_custom_button(__("Copy Username"), () => {
            frappe.call({
                method: "vault.api.copy_username",
                args: { credential: frm.doc.name },
                callback: (r) => {
                    if (r.message?.username) {
                        frappe.utils.copy_to_clipboard(r.message.username);
                        frappe.show_alert({ message: __("Username copied"), indicator: "green" });
                    }
                },
            });
        }, __("Actions"));

        frm.add_custom_button(__("Copy Password"), () => {
            frappe.call({
                method: "vault.api.copy_password",
                args: { credential: frm.doc.name },
                callback: (r) => {
                    if (r.message?.password) {
                        frappe.utils.copy_to_clipboard(r.message.password);
                        frappe.show_alert({ message: __("Password copied"), indicator: "orange" });
                    }
                },
            });
        }, __("Actions"));
    },
});

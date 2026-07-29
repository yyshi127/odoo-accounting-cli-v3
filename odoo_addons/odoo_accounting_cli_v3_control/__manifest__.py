{
    "name": "Odoo Accounting CLI V3 Control",
    "summary": "Server-side trusted sessions and controlled CLI accounting writes",
    "version": "19.0.0.7.0",
    "category": "Accounting/Accounting",
    "license": "LGPL-3",
    "depends": ["base", "account"],
    "data": [
        "security/odoo_accounting_cli_v3_security.xml",
        "security/ir.model.access.csv",
        "views/approval_wizard_views.xml",
    ],
    "installable": True,
    "application": False,
}

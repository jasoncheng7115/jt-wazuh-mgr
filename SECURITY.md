# Security Policy

## Supported Versions

Only the latest released version of **JT Wazuh Agent Manager** receives security
updates. Please always run the newest version before reporting an issue.

| Version | Supported          |
|---------|--------------------|
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public GitHub
issue**. Instead, report it privately using GitHub's
[private vulnerability reporting](https://github.com/jasoncheng7115/jt-wazuh-mgr/security/advisories/new)
(Security → Report a vulnerability), or contact the maintainer
[@jasoncheng7115](https://github.com/jasoncheng7115).

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce (proof of concept if possible)
- Affected version(s)
- Any suggested remediation

You can expect an initial response within a few business days. Once the issue is
confirmed, a fix will be prepared and released, and you will be credited in the
release notes unless you prefer to remain anonymous.

## Scope & Deployment Notes

This tool is a **management interface for the Wazuh Manager** and is intended to
be installed **on the Wazuh Manager itself** (the Master node in cluster mode).
Because it can restart, delete, and upgrade agents and edit node configuration,
treat it as a privileged administrative application:

- **Run it on a trusted management network only.** Do not expose port `5000`
  directly to the public Internet. Place it behind a VPN, firewall, or reverse
  proxy with access control.
- **Always use HTTPS.** The bundled `--ssl-auto` generates a self-signed
  certificate; for production use a certificate from your own CA.
- **Authentication** is delegated to the Wazuh API — users log in with their
  Wazuh API credentials, and a JWT is stored in the server-side session. No
  Wazuh passwords are written to `config.yaml` in Web UI mode.
- **Brute-force protection:** repeated failed logins from an IP trigger a
  temporary lockout (default: 3 failures = 30 minutes).
- **Least privilege:** create a dedicated Wazuh API user/role with only the
  permissions your operators need (see `create_api_user.py`).

## Built-in Hardening

The application includes input-validation and injection-prevention measures,
including:

- Strict validators for agent IDs, group names, node names, and usernames
- Path-whitelist validation to prevent path traversal
- Shell-argument escaping (`shlex.quote`) for all CLI invocations
- Secure file-upload handling (`werkzeug.utils.secure_filename`) for WPK uploads
- Log sanitization to prevent log injection
- Operation logging / audit trail for administrative actions

## Disclaimer

This software is provided "as is", without warranty of any kind. Before
performing destructive operations (delete, restart, upgrade), back up important
configurations and test in a non-production environment first. Use at your own
risk.

# Security

Before relying on Veyl, read its [security model and
limitations](docs/security.md). The current v0.1.0-rc.1 development candidate is
not production-ready or independently security-audited. Veyl provides session
checks over a writable gocryptfs-backed virtual directory; it does not claim
production-grade isolation from the same UID or root.

## Reporting a vulnerability

Do not post passwords, real plaintext, personal encrypted stores, private runtime
directories or a working exploit in a public issue or pull request.

If this repository's GitHub **Security** tab offers **Report a vulnerability**,
use that private reporting channel. If private reporting is unavailable, open a
minimal public issue asking for a private security contact, without exploit
details or sensitive attachments. No dedicated email address or response-time
commitment is published here.

A useful private report includes the affected version, Linux/kernel and dependency
versions, expected security boundary, impact, and a reproduction using a newly
created synthetic store. State whether the issue bypasses Veyl session checks,
exposes credentials, or leaves plaintext resources after reported cleanup.

Same-UID/root access, previously copied plaintext, cache retention and manual
crash recovery are documented limits, not protections Veyl promises. Reports
showing behavior beyond those limits are still useful; explain the distinction.

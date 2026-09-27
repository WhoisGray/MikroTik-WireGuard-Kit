# Contributing

Use Python 3.9+ on macOS or Linux. No third-party Python packages are needed.

Run `python3 -m unittest -v` before submitting a change. Tests must run offline using synthetic users and a simulated API. Never use real client keys, passwords or production routers in CI.

For provisioning changes, cover partial execution/resume, unchanged repeat runs, ownership checks, revocation, and preservation of unrelated configuration. Changes to logging must test credential redaction. Keep the minimum supported RouterOS version and its limitations documented.

Do not weaken a preflight check merely to accommodate one router. Explain the supported topology and verify both the accepted and rejected cases. Describe the behavior change and validation in pull requests.

Do not attach your real CSV, state, client configurations, snapshots, backups or unreviewed verbose logs. Use fictional examples in issues. Discuss security-sensitive findings privately; see SECURITY.md.

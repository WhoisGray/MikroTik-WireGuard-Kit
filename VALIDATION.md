# Validation

## Version 1.1.0

Local validation: Python 3.9.6 on macOS. All 30 offline unittest tests passed; CLI help, version output, and Git whitespace checks passed. The GitHub Actions matrix is configured for Python 3.9 and 3.12 on Linux and macOS, but has not been run on GitHub in this session.

Covered behavior:

- Check, apply and repeat using fictional example users, without router writes on check or unchanged repeat.
- Plain API and certificate-pinned TLS paths; TLS mismatch cleanup.
- RouterOS 7.12.1 peer compatibility, persisted naming mode across upgrades and version boundaries.
- Resume at provisioning boundaries, including the reported interrupted address and firewall additions.
- Invalid runtime flags on dependent IPv4/IPv6 rules while the owned interface is disabled.
- Complete-object verification before activation, delayed runtime flags, and attempts to disable newly activated interfaces after verification failure.
- Address overlap, foreign ownership, rule drift, deleted/disabled peers, and preservation of unrelated rules.
- Client key/address persistence, private output permissions and reproducible exports.
- API framing, Unicode, error draining and empty responses.
- Verbose request logging, default quiet behavior, redaction of credentials/private keys/unknown attributes, no response-body logging, and generic login errors that do not echo credentials.

Tests do not need a router, credentials, real client keys, the local deployment CSV, or the `wg` executable. They use users.example.csv and a simulated API. The example public IP in tests is synthetic fixture data and is never contacted.

A user reported a successful deployment on CHR 7.12.1 before the verbose logging and repository cleanup changes. That report is not independent verification of VPN connectivity, security policy, or compatibility with other RouterOS versions/topologies. No live router modifications were made while preparing version 1.1.0.

## Reproduce

```bash
python3 -m unittest -v
python3 wg_manager.py --help
python3 wg_manager.py --version
```

## Repository hygiene

Local users.csv is preserved and excluded from the Git index. Default deployment outputs, sensitive files in custom workdirs, logs, backups and archives are ignored. Public documentation and tests use fictional users and explicit connection parameters.

The existing initial Git commit contains historical deployment-specific data. Ignore rules and current-file cleanup do not sanitize past commits. Review or separately sanitize history before publishing it. No remote was configured and no push was performed during this work.

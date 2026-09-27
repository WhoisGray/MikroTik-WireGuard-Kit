# Changelog

## 1.1.0

- Add `-v` / `--verbose` API request and progress logging with credential redaction.
- Add `--version`; require explicit management host and public VPN endpoint.
- Support explicit plain API connections and RouterOS 7.12.1 comment-based peers.
- Preserve deployment identity and client keys across repeat and interrupted runs.
- Handle runtime invalid flags during staged interface construction; verify all objects before activation and attempt to disable newly activated interfaces if final verification fails.
- Add public example users, English/Persian documentation, Git exclusions, and offline CI.

## 1.0.0

- Initial RouterOS WireGuard provisioning, persistent state, client export, preflight checks and offline tests.

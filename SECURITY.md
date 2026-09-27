# Security

Deployment state and client `.conf` files contain private keys. Keep them outside version control and back them up securely. Never publish router passwords, backup files, real user lists or archives containing deployment output.

Prefer API-SSL with a certificate fingerprint obtained through a trusted channel. Plain API is explicitly supported but sends credentials and management traffic unencrypted. Restrict management services to trusted sources.

Verbose mode redacts authentication inputs and unknown API attributes, and does not print API response bodies. It still reveals network topology, user comments and public keys. Review logs before sharing them.

To report a security issue, use GitHub private vulnerability reporting on the repository if enabled, or contact [@whoisGray](https://github.com/whoisGray) privately. Do not open a public issue containing secrets or exploit details before coordination.

`.gitignore` does not remove data from existing commits. A repository that previously tracked personal deployment inputs needs a separate history review before public publication. Removing a tracked file in a later commit does not erase earlier versions.

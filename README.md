# MikroTik WireGuard Kit

A Python CLI for provisioning an isolated WireGuard network on MikroTik RouterOS, with a reviewable plan, persistent client keys, and resumable changes.

Maintained by [@whoisGray](https://github.com/whoisGray). [راهنمای فارسی](README.fa.md)

## Requirements

- macOS or Linux, Python 3.9+, and `wg` from `wireguard-tools`.
- Stable RouterOS 7.12.1 or newer within major version 7.
- An API account with read/write access to the relevant configuration and permission to use the API.
- A reachable RouterOS API service: API-SSL (default port 8729), or plain API (8728).

No pip packages, Docker, or local root privileges are required to run the script. Native Windows is not supported (`fcntl` is used for file locking). Clients need a WireGuard app.

On a Mac with Homebrew:

```bash
brew install python wireguard-tools
python3 wg_manager.py --help
```

## First deployment

Copy the sample only for a **new deployment**; preserve an existing `users.csv`:

```bash
cp -n users.example.csv users.csv
```

The CSV header is `id,name,name_fa`. The legacy `name_fa` column is a required Unicode display label; it can contain any language. IDs must be unique, start with a lowercase letter, contain only lowercase letters, digits, `_` or `-`, and be at most 48 characters. English names must be unique, 2–80 characters, and contain only letters, spaces, periods or hyphens.

Set your actual router details in your terminal:

```bash
ROUTER_HOST='YOUR_MANAGEMENT_IP_OR_HOSTNAME'
VPN_ENDPOINT='YOUR_PUBLIC_IPV4'
API_USER='YOUR_API_USERNAME'
WAN_INTERFACE='YOUR_WAN_INTERFACE'
```

There is no built-in server IP. `--host` is the management address; `--endpoint` is the public IPv4 address directly assigned to the selected WAN.

For plain API, enable the router's `api` service and permit TCP 8728 from your management IP. It transmits credentials and management traffic without encryption; use a trusted network or an existing VPN.

Run a check first:

```bash
python3 wg_manager.py \
  --plain-api \
  --host "$ROUTER_HOST" --endpoint "$VPN_ENDPOINT" \
  --user "$API_USER" --wan "$WAN_INTERFACE" \
  --csv users.csv --workdir wg-output -v
```

The password is prompted interactively, never supplied on the command line. Check mode reads the router and writes a local plan, snapshot, rollback script and private state; it does not change router configuration or export client configurations.

Review `wg-output/plan.json`. Take and download a current router backup. Then rerun the same command with `--apply --backup-confirmed`. The backup flag is your acknowledgment; the script cannot verify your backup.

For API-SSL, omit `--plain-api` and supply `--tls-fingerprint YOUR_VERIFIED_SHA256`. Obtain the certificate through a trusted management channel. The script uses a certificate pin instead of CA/hostname validation. `--api-port` overrides either default port.

## Verbose output

`-v` or `--verbose` logs requests and progress to stderr:

```text
[DEBUG] API request /ip/firewall/filter/add {"chain": "...", "action": "drop", ...}
[DEBUG] API completed /ip/firewall/filter/add (0 rows)
[DEBUG] Keep verified object /interface/wireguard ...
```

These are API paths and attributes, not RouterOS terminal commands to paste. Login values, passwords, private/preshared keys and unknown attributes are redacted. Response bodies and local key-generation output are not dumped. Logs still expose topology, IPs and user comments; review them before sharing.

## Repeat runs and adding users

Always preserve the same workdir, connection mode and network arguments. Existing peers, client keys and addresses are retained. An unchanged apply sends no configuration changes and regenerates client files with the same contents.

Append a new unique CSV row and rerun check/apply to add a user. Do not rename existing IDs or names. Removing a CSV row does not revoke access or recycle its IP. Disabling or deleting a managed peer on the router causes future runs to stop rather than silently restoring access.

On RouterOS before 7.15, identify peers using their ownership comments; later versions support named peers for new deployments. Existing deployments retain their naming mode across upgrades.

## Output and recovery

| File | Purpose |
| --- | --- |
| `state.json` | Private keys, allocations, ownership and deployment state; keep an encrypted backup |
| `plan.json` | Proposed additions and retained objects |
| `preflight-snapshot.json` | Router inventory from the check before apply |
| `rollback.rsc` | Reviewed, manual removal of this deployment's objects |
| `clients/*.conf` | One secret client configuration per user, generated after successful apply |
| `manifest.csv` | Client file and address index |

Give each user only their own configuration. Never commit the workdir, real CSV, exported certificates, backups or deployment archives. `.gitignore` covers the default outputs and sensitive filenames in custom workdirs.

Changes are not transactional. After interruption, keep state and rerun with the same arguments. The new interface remains disabled during construction. Runtime invalid flags are deferred only for its owned address and directly dependent filter rules. Activation requires all objects to exist, followed by strict validation. If validation fails, the script attempts to disable the interface it just activated; it does not perform a full rollback. If the connection is lost, inspect actual router state before retrying.

## Scope and limitations

Defaults: `wg-staff`, subnet `10.220.10.1/24`, UDP 51820, DNS `1.1.1.1,1.0.0.1`. Override them before your first deployment. Permit the WireGuard UDP port in the upstream firewall.

This design provides IPv4 internet access and blocks VPN access to the router, private networks, other VPN clients and IPv6 forwarding. It is not a device-level kill switch. Test handshake, internet, DNS/IPv6 behavior and existing tunnels before distributing configurations.

Automatic provisioning requires one active main default route through the selected WAN, a directly assigned public endpoint, forwarding/connection tracking enabled, and a conflict-free subnet. Active raw/mangle/routing rules, dstnat, non-main VRFs, non-template IPsec policies, ECMP and overlapping peer ranges stop the run for manual review. Existing tunnels alone do not prevent provisioning. Do not remove those protections to force a deployment on an incompatible topology.

No reboot, upgrade, reset or automatic deletion of unrelated configuration is performed. Run from one workdir on one machine at a time; the local lock does not coordinate multiple computers.

## Development

```bash
python3 -m unittest -v
python3 wg_manager.py --help
python3 wg_manager.py --version
```

Tests use the fictional `users.example.csv` and a simulated API, without a router, credentials or `wg`. GitHub Actions runs them on Linux and macOS. Offline tests do not establish full RouterOS compatibility. See [VALIDATION.md](VALIDATION.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

Official references: [RouterOS API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API), [WireGuard](https://help.mikrotik.com/docs/spaces/ROS/pages/69664792/WireGuard).

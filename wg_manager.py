#!/usr/bin/env python3
"""Conservative, resumable MikroTik WireGuard provisioning. See README.md."""
import argparse
import csv
import fcntl
import getpass
import hashlib
import ipaddress as ip
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = '1.1.0'
LOG = logging.getLogger('wg_manager')
LOG.addHandler(logging.NullHandler())

def configure_logging(verbose):
    LOG.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG if verbose else logging.WARNING)
    LOG.propagate = False

def safe_api_attributes(command, attrs):
    # Log only known non-secret parameters; never dump arbitrary API inputs or responses.
    allowed = {'.id', '.proplist', 'name', 'interface', 'comment', 'disabled', 'listen-port',
               'mtu', 'address', 'chain', 'action', 'connection-state', 'in-interface',
               'out-interface', 'src-address', 'dst-address', 'ipsec-policy', 'jump-target',
               'protocol', 'dst-port', 'allowed-address', 'place-before', 'public-key'}
    return {k: v if command != '/login' and k in allowed else '<redacted>' for k, v in attrs.items()}
WG = '/interface/wireguard'
PEER = WG + '/peers'
ADDR = '/ip/address'
FILTER = '/ip/firewall/filter'
NAT = '/ip/firewall/nat'
V6FILTER = '/ipv6/firewall/filter'
BLOCKED = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
           '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
           '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']

class Stop(Exception):
    pass

class InvalidObject(Stop):
    pass

def require(condition, message):
    if not condition:
        raise Stop(message)

def yes(value):
    return str(value).lower() in ('true', 'yes', '1')

def active(row):
    return not yes(row.get('disabled', 'false'))

def length(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return struct.pack('!H', n | 0x8000)
    if n < 0x200000:
        return (n | 0xc00000).to_bytes(3, 'big')
    if n < 0x10000000:
        return struct.pack('!I', n | 0xe0000000)
    return b'\xf0' + struct.pack('!I', n)

class API:
    def __init__(self, host, port, fingerprint):
        LOG.debug('Connecting to %s:%s (%s)', host, port, 'plain API' if fingerprint is None else 'API-SSL')
        if fingerprint is None:
            self.sock = socket.create_connection((host, port), timeout=20)
            return
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # A mandatory out-of-band SHA-256 certificate pin replaces CA validation.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=20)
        try:
            self.sock = context.wrap_socket(raw, server_hostname=host)
            actual = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
            require(actual == fingerprint, 'TLS certificate pin mismatch; no credentials sent.')
        except BaseException:
            raw.close()
            if hasattr(self, 'sock'):
                self.sock.close()
            raise

    def read(self, count):
        data = b''
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise Stop('API connection closed. Outcome may be partial; keep state and rerun.')
            data += chunk
        return data

    def word(self):
        b = self.read(1)[0]
        if b < 0x80:
            n = b
        elif b < 0xc0:
            n = ((b & 0x3f) << 8) | self.read(1)[0]
        elif b < 0xe0:
            n = ((b & 0x1f) << 16) | int.from_bytes(self.read(2), 'big')
        elif b < 0xf0:
            n = ((b & 0x0f) << 24) | int.from_bytes(self.read(3), 'big')
        elif b == 0xf0:
            n = int.from_bytes(self.read(4), 'big')
        else:
            raise Stop('Unsupported API control byte.')
        require(n <= 16 * 1024 * 1024, 'API response word too large.')
        return self.read(n).decode('utf-8') if n else ''

    def call(self, command, **attrs):
        LOG.debug('API request %s %s', command, json.dumps(safe_api_attributes(command, attrs), ensure_ascii=True))
        words = [command] + ['=' + k + '=' + str(v) for k, v in attrs.items()]
        data = b''
        for word in words:
            encoded = word.encode('utf-8')
            data += length(len(encoded)) + encoded
        self.sock.sendall(data + b'\0')
        rows, errors, done = [], [], {}
        while True:
            sentence = []
            while True:
                word = self.word()
                if not word:
                    break
                sentence.append(word)
            if not sentence:
                continue
            row = dict(w[1:].split('=', 1) for w in sentence[1:] if w.startswith('=') and '=' in w[1:])
            kind = sentence[0]
            if kind == '!re':
                rows.append(row)
            elif kind == '!trap':
                errors.append(row.get('message', 'API error'))
            elif kind == '!fatal':
                raise Stop('API fatal error: ' + ('login failed' if command == '/login' else row.get('message', 'closed')))
            elif kind == '!done':
                done = row
                break
            elif kind != '!empty':
                raise Stop('Unexpected API response.')
        if errors:
            raise Stop(command + ': ' + ('authentication failed' if command == '/login' else '; '.join(errors)))
        LOG.debug('API completed %s (%d rows)', command, len(rows))
        return rows, done

    def rows(self, path, props=None):
        attrs = {'.proplist': props} if props else {}
        return self.call(path + '/print', **attrs)[0]

# Never collect credentials or WireGuard private keys from the router.
PROPS = {
    WG: '.id,name,comment,disabled,running,listen-port,mtu,public-key',
    PEER: '.id,name,comment,disabled,interface,public-key,allowed-address,endpoint-address,endpoint-port',
    '/ppp/secret': '.id,name,local-address,remote-address,disabled',
    '/ppp/profile': '.id,name,local-address,remote-address',
    '/ppp/active': '.id,name,address',
}
PATHS = ['/system/resource', '/system/identity', '/interface', WG, PEER, ADDR,
         '/ip/route', '/ip/pool', '/ip/dhcp-server/lease', '/ip/dhcp-server/network',
         '/ppp/secret', '/ppp/profile', '/ppp/active', '/ip/firewall/raw',
         '/ip/firewall/mangle', '/routing/rule', '/ip/vrf', '/ip/ipsec/policy',
         '/ip/firewall/connection/tracking', '/ip/settings', FILTER, NAT, V6FILTER]

def router_version(version):
    m = re.fullmatch(r'(\d+)\.(\d+)(?:\.(\d+))?(?: \((?:stable|long-term)\))?', version)
    require(m and int(m[1]) == 7 and
            (int(m[2]), int(m[3] or 0)) >= (12, 1),
            'Stable RouterOS 7.12.1+ (major 7) required; no automatic upgrade.')
    return tuple(int(x or 0) for x in m.groups())

def properties(path, peer_names=True):
    props = PROPS.get(path)
    if path == PEER and not peer_names:
        props = ','.join(p for p in props.split(',') if p != 'name')
    return props

def inventory(api):
    inv = {'/system/resource': api.rows('/system/resource')}
    version = router_version(inv['/system/resource'][0].get('version', ''))
    for path in PATHS[1:]:
        inv[path] = api.rows(path, properties(path, version >= (7, 15, 0)))
    return inv

def atomic(path, content):
    path = Path(path)
    require(not path.is_symlink(), 'Refusing symlink: ' + str(path))
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.tmp-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def save(path, state):
    atomic(path, json.dumps(state, indent=2, ensure_ascii=False) + '\n')

def users_csv(path):
    with open(path, encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        require(reader.fieldnames == ['id', 'name', 'name_fa'], 'CSV header must be id,name,name_fa')
        users = list(reader)
    require(users, 'CSV contains no users.')
    seen = set()
    for u in users:
        require(all(isinstance(u.get(k), str) and u[k].strip() == u[k] and u[k] for k in ('id', 'name', 'name_fa')),
                'Empty or malformed CSV value.')
        require(re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', u['id']), 'Invalid stable user id.')
        require(re.fullmatch(r'[A-Za-z][A-Za-z .-]{1,79}', u['name']), 'Use an English display name.')
        require(u['id'] not in seen, 'Duplicate CSV id: ' + u['id'])
        seen.add(u['id'])
    return users

def public_key(private):
    return subprocess.run(['wg', 'pubkey'], input=private + '\n', text=True,
                          capture_output=True, check=True).stdout.strip()

def keypair():
    private = subprocess.run(['wg', 'genkey'], text=True, capture_output=True, check=True).stdout.strip()
    return private, public_key(private)

def tag(state, suffix):
    return 'wgkit:' + state['owner'] + ':' + suffix

def canonical(v):
    if str(v).lower() in ('yes', 'true'):
        return 'true'
    if str(v).lower() in ('no', 'false'):
        return 'false'
    return str(v)

def match_expected(row, desired, ignore=(), allow_invalid=False):
    for k, v in desired.items():
        if k not in ignore:
            require(canonical(row.get(k, '')) == canonical(v),
                    'Managed object drift: ' + desired.get('comment', '') + ' field=' + k)
    if not allow_invalid and yes(row.get('invalid', False)):
        raise InvalidObject('Managed object is invalid: ' + desired.get('comment', ''))

def pending_interface_dependency(state, path, fields, interfaces):
    """Defer runtime validity only for objects referencing our staged interface."""
    if state.get('complete'):
        return False
    iface = state['config']['interface']
    if path == ADDR:
        dependent = fields.get('comment') == tag(state, 'address') and fields.get('interface') == iface
    elif path in (FILTER, V6FILTER):
        dependent = iface in (fields.get('in-interface'), fields.get('out-interface'))
    else:
        dependent = False
    if not dependent or not fields.get('comment', '').startswith('wgkit:' + state['owner'] + ':'):
        return False
    owned = [r for r in interfaces if r.get('name') == state['config']['interface']]
    return (len(owned) == 1 and owned[0].get('comment') == tag(state, 'interface')
            and yes(owned[0].get('disabled')) and not yes(owned[0].get('invalid')))

# Ignore counters/uptime, but retain selectors, comments, order and disabled flags.
VOLATILE = {'bytes', 'packets', 'last-handshake', 'rx', 'tx', 'running', 'invalid'}
def stable_rule(row):
    return {k: canonical(v) for k, v in row.items() if k not in VOLATILE and k != '.id'}

def desired_objects(state):
    c = state['config']
    iface, wan, net = c['interface'], c['wan'], str(ip.ip_interface(c['subnet']).network)
    chain = 'wgk-' + state['owner'][:10]
    objects = []
    def add(path, suffix, top=False, **fields):
        fields.update(comment=tag(state, suffix), disabled='no')
        objects.append({'path': path, 'fields': fields, 'top': top})
    add(WG, 'interface', name=iface, **{'listen-port': str(c['wg_port']), 'mtu': '1420'})
    add(ADDR, 'address', address=c['subnet'], interface=iface)
    # Build the private chain before inserting jumps into built-in chains.
    add(FILTER, 'f-invalid', chain=chain, action='drop', **{'connection-state': 'invalid'})
    add(FILTER, 'f-spoof', chain=chain, action='drop', **{'in-interface': iface, 'src-address': '!' + net})
    for i, cidr in enumerate(BLOCKED):
        add(FILTER, 'f-private-' + str(i), chain=chain, action='drop', **{'in-interface': iface, 'dst-address': cidr})
    add(FILTER, 'f-internet', chain=chain, action='accept',
        **{'in-interface': iface, 'out-interface': wan, 'src-address': net, 'ipsec-policy': 'out,none'})
    add(FILTER, 'f-return', chain=chain, action='accept',
        **{'in-interface': wan, 'out-interface': iface, 'dst-address': net,
           'connection-state': 'established,related'})
    add(FILTER, 'f-final', chain=chain, action='drop')
    add(FILTER, 'input-deny', top=True, chain='input', action='drop', **{'in-interface': iface})
    add(FILTER, 'forward-in', top=True, chain='forward', action='jump',
        **{'in-interface': iface, 'jump-target': chain})
    add(FILTER, 'forward-out', top=True, chain='forward', action='jump',
        **{'out-interface': iface, 'jump-target': chain})
    add(V6FILTER, 'v6-input', top=True, chain='input', action='drop', **{'in-interface': iface})
    add(V6FILTER, 'v6-forward-in', top=True, chain='forward', action='drop', **{'in-interface': iface})
    add(V6FILTER, 'v6-forward-out', top=True, chain='forward', action='drop', **{'out-interface': iface})
    add(NAT, 'nat', top=True, chain='srcnat', action='masquerade',
        **{'src-address': net, 'out-interface': wan, 'ipsec-policy': 'out,none'})
    add(FILTER, 'udp-listener', top=True, chain='input', action='accept',
        **{'in-interface': wan, 'dst-address': c['endpoint'], 'protocol': 'udp', 'dst-port': str(c['wg_port'])})
    for uid, u in state['users'].items():
        add(PEER, 'user:' + uid + ' | ' + u['name'], interface=iface,
            **{'public-key': u['public'], 'allowed-address': u['address'] + '/32'})
        objects[-1]['user_id'] = uid
        if state.get('peer_names', True):
            objects[-1]['fields']['name'] = uid
    return objects

def own_row(rows, fields):
    found = [r for r in rows if r.get('comment') == fields['comment']]
    require(len(found) <= 1, 'Duplicate ownership comment: ' + fields['comment'])
    return found[0] if found else None

def overlap(value, network):
    if not value:
        return False
    try:
        candidate = ip.ip_network(value, strict=False)
    except ValueError:
        return False  # e.g. a PPP pool name; the pool itself is checked separately
    return candidate.version == 4 and candidate.overlaps(network)

def preflight(inv, state):
    c = state['config']
    net = ip.ip_interface(c['subnet']).network
    version = inv['/system/resource'][0].get('version', '')
    supports_names = router_version(version) >= (7, 15, 0)
    # Existing deployments without this field were created with named peers.
    state.setdefault('peer_names', True if state.get('complete') or state.get('server_public') else supports_names)
    require(not state['peer_names'] or supports_names,
            'Deployment uses peer names unavailable on this RouterOS; preserve state and review downgrade.')
    iface = c['interface']
    owned = [r for r in inv[WG] if r.get('name') == iface]
    require(len(owned) <= 1, 'Duplicate interface name.')
    if owned:
        require(owned[0].get('comment') == tag(state, 'interface'), 'Interface name already belongs to someone else. Do not adopt it.')
        if state.get('server_public'):
            require(owned[0].get('public-key') == state['server_public'], 'Router WireGuard public key changed.')
    else:
        require(not state.get('server_public'), 'Previously managed interface is missing; restore it, do not rotate server key silently.')
    for r in inv['/interface']:
        if r.get('name') == iface:
            require(owned, 'Interface name used by a non-WireGuard interface.')
    wans = [r for r in inv['/interface'] if r.get('name') == c['wan']]
    require(len(wans) == 1 and active(wans[0]) and yes(wans[0].get('running')), 'WAN must exist, be enabled and running.')
    require(c['wan'] != iface, 'WAN cannot be the new WireGuard interface.')
    require(any(active(r) and r.get('interface') == c['wan'] and
                str(ip.ip_interface(r['address']).ip) == c['endpoint'] for r in inv[ADDR]),
            'Public endpoint must be assigned directly to the selected WAN. NAT/loopback/multi-WAN needs a tailored review.')
    for r in inv[WG]:
        if r.get('name') != iface:
            require(r.get('listen-port') != str(c['wg_port']), 'WireGuard UDP port already reserved by another interface.')
    for path in ['/ip/firewall/raw', '/ip/firewall/mangle', '/routing/rule']:
        require(not any(active(r) for r in inv[path]), 'Enabled rules in ' + path + '; stop for routing/firewall review.')
    require(all(r.get('name') == 'main' for r in inv['/ip/vrf']), 'Non-main VRF exists; manual review required.')
    require(not any(active(r) and not yes(r.get('template')) for r in inv['/ip/ipsec/policy']),
            'Active IPsec policies exist; manual review required.')
    require(inv['/ip/settings'] and yes(inv['/ip/settings'][0].get('ip-forward')), 'IPv4 forwarding must already be enabled.')
    tracking = inv['/ip/firewall/connection/tracking']
    require(tracking and canonical(tracking[0].get('enabled')) != 'false', 'Connection tracking is disabled.')
    defaults = [r for r in inv['/ip/route'] if r.get('dst-address') == '0.0.0.0/0'
                and r.get('routing-table', 'main') == 'main' and yes(r.get('active'))]
    require(len(defaults) == 1, 'Exactly one active main default route required (no ECMP).')
    gateway = defaults[0].get('immediate-gw', '')
    require(not yes(defaults[0].get('ecmp')) and ',' not in gateway and ';' not in gateway,
            'ECMP default route is not supported.')
    require(gateway == c['wan'] or gateway.endswith('%' + c['wan']), 'Default route does not resolve through selected WAN.')
    for path, fields in [(ADDR, ['address']), ('/ip/route', ['dst-address']),
                         ('/ip/dhcp-server/lease', ['address', 'active-address']),
                         ('/ip/dhcp-server/network', ['address']),
                         ('/ppp/secret', ['local-address', 'remote-address']),
                         ('/ppp/profile', ['local-address', 'remote-address']),
                         ('/ppp/active', ['address'])]:
        for r in inv[path]:
            if path == ADDR and r.get('comment') == tag(state, 'address') and r.get('interface') == iface:
                continue
            if path == '/ip/route':
                if r.get('dst-address') == '0.0.0.0/0':
                    continue
                if (r.get('dst-address') == str(net) and yes(r.get('dynamic')) and
                    r.get('routing-table', 'main') == 'main' and r.get('gateway') == iface):
                    continue
            for f in fields:
                require(not overlap(r.get(f), net), 'Subnet overlap in ' + path + ' (' + f + '=' + r.get(f, '') + ')')
    for r in inv['/ip/pool']:
        for part in r.get('ranges', '').split(','):
            if not part:
                continue
            bits = part.split('-')
            if len(bits) == 2:
                a, b = map(ip.ip_address, bits)
                conflict = int(a) <= int(net.broadcast_address) and int(b) >= int(net.network_address)
            else:
                conflict = overlap(part, net)
            require(not conflict, 'Subnet overlaps IP pool: ' + r.get('name', ''))
    peers_by_comment = {obj['fields']['comment']: obj['fields'] for obj in desired_objects(state) if obj['path'] == PEER}
    keys = {u['public'] for u in state['users'].values()}
    for r in inv[PEER]:
        if r.get('comment') in peers_by_comment:
            match_expected(r, peers_by_comment[r['comment']])
            continue
        require(r.get('interface') != iface, 'Unknown peer on managed interface.')
        require(r.get('public-key') not in keys, 'Client public key already used by another peer.')
        for a in r.get('allowed-address', '').split(','):
            require(not overlap(a, net), 'Subnet overlaps another WireGuard peer (including broad prefixes).')
    objects = desired_objects(state)
    for obj in objects:
        if obj['path'] == PEER:
            fields = obj['fields']
            uid = obj['user_id']
            existing = own_row(inv[PEER], fields)
            require(existing or uid not in state.get('provisioned_users', []),
                    'Previously provisioned peer missing (possibly revoked): ' + uid)
            require(not any(r.get('name') == uid and r.get('comment') != fields['comment']
                            for r in inv[PEER]), 'Peer name already used: ' + uid)
    expected_comments = {o['fields']['comment'] for o in objects}
    for path in [WG, PEER, ADDR, FILTER, NAT, V6FILTER]:
        for r in inv[path]:
            if r.get('comment', '').startswith('wgkit:' + state['owner'] + ':'):
                require(r['comment'] in expected_comments, 'Unknown managed object; preserve state and review.')
    for obj in objects:
        path, fields = obj['path'], obj['fields']
        row = own_row(inv[path], fields)
        if row:
            ignore = ('disabled',) if path == WG and not state.get('complete') else ()
            match_expected(row, fields, ignore, allow_invalid=pending_interface_dependency(state, path, fields, inv[WG]))
            baseline = state.get('rule_baselines', {}).get(fields['comment'])
            if baseline:
                require(stable_rule(row) == baseline, 'Managed firewall rule changed; stop for review.')
        elif state.get('complete') and path != PEER:
            raise Stop('Previously completed managed object missing: ' + fields['comment'])
    chain = 'wgk-' + state['owner'][:10]
    chain_rows = [r for r in inv[FILTER] if r.get('chain') == chain]
    expected_chain = [o['fields']['comment'] for o in objects if o['path'] == FILTER and o['fields'].get('chain') == chain]
    comments = [r.get('comment') for r in chain_rows]
    # Partial execution must form a prefix; adding at end preserves the chain order.
    require(comments == expected_chain[:len(comments)], 'Private firewall chain has foreign, missing or reordered rules.')
    for path in [FILTER, NAT, V6FILTER]:
        rows = inv[path]
        for obj in objects:
            if obj['path'] != path or not obj['top']:
                continue
            fields = obj['fields']
            positions = [i for i, r in enumerate(rows) if r.get('comment') == fields['comment']]
            if positions:
                for r in rows[:positions[0]]:
                    if active(r) and r.get('chain') == fields['chain']:
                        require(r.get('comment') in expected_comments or
                                (yes(r.get('dynamic')) and r.get('action') == 'passthrough'),
                                'Existing rule is before managed protections; no automatic reorder.')
    # Existing dstnat can steal the UDP listener or rewrite client traffic before filter.
    require(not any(active(r) and r.get('chain') == 'dstnat' for r in inv[NAT]),
            'Enabled dstnat rules exist; manual review required.')
    if state.get('complete'):
        for r in inv[PEER]:
            if r.get('interface') == iface:
                require(active(r), 'Disabled managed peer: do not silently re-enable a revoked user.')
    return version

def add_users(state, users):
    netif = ip.ip_interface(state['config']['subnet'])
    used = {u['address'] for u in state['users'].values()}
    names = {u['name'] for u in state['users'].values()}
    new = [u for u in users if u['id'] not in state['users']]
    available = [str(a) for a in netif.network.hosts() if int(a) > int(netif.ip) and str(a) not in used]
    require(len(available) >= len(new), 'Not enough sequential client addresses.')
    # Allocate above the highest previous address; never recycle removed users.
    high = max([int(netif.ip)] + [int(ip.ip_address(a)) for a in used])
    available = [a for a in available if int(ip.ip_address(a)) > high]
    require(len(available) >= len(new), 'Sequential address space exhausted.')
    for u in users:
        uid = u['id']
        if uid in state['users']:
            require(state['users'][uid]['name'] == u['name'] and state['users'][uid]['name_fa'] == u['name_fa'],
                    'Name changed for stable id ' + uid + '; review state instead of creating a duplicate.')
            continue
        require(u['name'] not in names, 'Duplicate English display name; distinguish devices/users.')
        private, public = keypair()
        state['users'][uid] = dict(u, private=private, public=public, address=available.pop(0))
        names.add(u['name'])

def rollback_text(state):
    lines = ['# DANGER: explicitly removes this entire wgkit deployment only.',
             '# Review in WinBox first. Does not touch unrelated objects or management setup.']
    for obj in reversed(desired_objects(state)):
        path, f = obj['path'].replace('/', ' ').strip(), obj['fields']
        # Comments are exclusively generated from validated ASCII names and IDs.
        lines.append('/' + path + ' remove [find where comment="' + f['comment'] + '"]')
    return '\n'.join(lines) + '\n'

def ensure(api, state, obj, state_path):
    path, fields = obj['path'], obj['fields']
    allow_invalid = pending_interface_dependency(state, path, fields, api.rows(WG, PROPS[WG])) if path in (ADDR, FILTER, V6FILTER) else False
    rows = api.rows(path, properties(path, state.get('peer_names', True)))
    row = own_row(rows, fields)
    if row:
        match_expected(row, fields, ('disabled',) if path == WG and not state.get('complete') else (),
                       allow_invalid=allow_invalid)
        if path in (FILTER, NAT, V6FILTER) and fields['comment'] not in state.get('rule_baselines', {}):
            state.setdefault('rule_baselines', {})[fields['comment']] = stable_rule(row)
            save(state_path, state)
        LOG.debug('Keep verified object %s %s', path, fields['comment'])
        return
    # Never silently reconstruct a removed/revoked peer from an earlier successful run.
    if path == PEER:
        uid = obj['user_id']
        require(uid not in state.get('provisioned_users', []), 'Previously provisioned peer missing: ' + uid)
        for r in rows:
            require(r.get('name') != uid, 'Peer name already used by another account: ' + uid)
            require(r.get('public-key') != fields['public-key'], 'Duplicate client public key.')
            for a in r.get('allowed-address', '').split(','):
                require(not overlap(a, ip.ip_network(fields['allowed-address'])), 'IP allocation collision during apply.')
    attrs = dict(fields)
    if path == WG:
        attrs['disabled'] = 'yes'  # no traffic until all protections exist
    if obj['top']:
        static = [r for r in rows if not yes(r.get('dynamic'))]
        if static:
            attrs['place-before'] = static[0]['.id']
    api.call(path + '/add', **attrs)
    row = own_row(api.rows(path, properties(path, state.get('peer_names', True))), fields)
    require(row is not None, 'Add could not be verified; keep state and rerun.')
    match_expected(row, fields, ('disabled',) if path == WG else (), allow_invalid=allow_invalid)
    if path in (FILTER, NAT, V6FILTER):
        state.setdefault('rule_baselines', {})[fields['comment']] = stable_rule(row)
        save(state_path, state)
    print('Added:', fields['comment'])

def finish_deployment(api, state, objects, state_path):
    LOG.debug('Verifying all %d objects before activation', len(objects))
    final = inventory(api)
    preflight(final, state)
    # Incomplete deployments allow missing objects during resume, but never at activation.
    for obj in objects:
        require(own_row(final[obj['path']], obj['fields']) is not None,
                'Cannot activate: missing managed object: ' + obj['fields']['comment'])
    interface = own_row(final[WG], objects[0]['fields'])
    require(interface and interface.get('public-key'), 'Server public key unavailable.')
    state['server_public'] = interface['public-key']
    save(state_path, state)
    activating = not active(interface)
    was_complete = state.get('complete', False)
    try:
        if activating:
            LOG.debug('Activating verified managed interface %s', state['config']['interface'])
            api.call(WG + '/set', **{'.id': interface['.id'], 'disabled': 'no'})
        state['complete'] = True
        for attempt in range(6):
            try:
                preflight(inventory(api), state)
                break
            except InvalidObject:
                if not activating or attempt == 5:
                    raise
                # RouterOS runtime flags may lag activation; never retry configuration drift.
                time.sleep(0.2)
    except BaseException:
        state['complete'] = was_complete
        if activating:
            # Only undo activation of our own staged interface; retain all objects/state.
            try:
                api.call(WG + '/set', **{'.id': interface['.id'], 'disabled': 'yes'})
                print('Activation verification failed; managed WireGuard interface disabled again.', file=sys.stderr)
            except BaseException:
                print('Could not confirm interface disabled after activation failure; check wg-staff in WinBox.', file=sys.stderr)
        raise
    state['provisioned_users'] = list(state['users'])
    save(state_path, state)
    LOG.debug('Deployment verified; state saved to %s', state_path)

def export_clients(root, state):
    c = state['config']
    output = root / 'clients'
    require(not output.is_symlink(), 'clients directory must not be a symlink.')
    output.mkdir(mode=0o700, exist_ok=True)
    os.chmod(output, 0o700)
    manifest = []
    for uid, u in state['users'].items():
        v6 = str(ip.IPv6Address(int(ip.IPv6Address('fd6d:220:10::')) + int(ip.ip_address(u['address']))))
        filename = u['name'].replace(' ', '_') + '.conf'
        content = ('[Interface]\nPrivateKey = ' + u['private'] + '\nAddress = ' + u['address'] + '/32, ' + v6 + '/128\n'
                   'DNS = ' + ', '.join(c['dns']) + '\nMTU = 1380\n\n[Peer]\nPublicKey = ' + state['server_public'] + '\n'
                   'Endpoint = ' + c['endpoint'] + ':' + str(c['wg_port']) + '\n'
                   'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')
        atomic(output / filename, content)
        manifest.append({'id': uid, 'name': u['name'], 'name_fa': u['name_fa'], 'address': u['address'], 'file': filename})
    import io
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=['id', 'name', 'name_fa', 'address', 'file'])
    writer.writeheader()
    writer.writerows(manifest)
    atomic(root / 'manifest.csv', stream.getvalue())


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    p.add_argument('-v', '--verbose', action='store_true', help='Log API requests and progress to stderr; secrets are redacted')
    p.add_argument('--host', required=True, help='Router management IP or hostname')
    p.add_argument('--api-port', type=int, help='Default: 8728 with --plain-api, otherwise 8729')
    p.add_argument('--plain-api', action='store_true', help='Use unencrypted RouterOS API (password sent in plaintext)')
    p.add_argument('--user', required=True)
    p.add_argument('--tls-fingerprint', help='Required unless --plain-api: SHA256 of API server certificate, verified out of band')
    p.add_argument('--wan', required=True, help='Exact existing WAN interface name')
    p.add_argument('--endpoint', required=True, help='Directly assigned public IPv4 endpoint for VPN clients')
    p.add_argument('--interface', default='wg-staff')
    p.add_argument('--subnet', default='10.220.10.1/24', help='Router IPv4 address/prefix')
    p.add_argument('--wg-port', type=int, default=51820)
    p.add_argument('--dns', default='1.1.1.1,1.0.0.1')
    p.add_argument('--csv', default='users.csv')
    p.add_argument('--workdir', default='wg-output')
    p.add_argument('--apply', action='store_true')
    p.add_argument('--backup-confirmed', action='store_true', help='You made and downloaded a current RouterOS backup')
    args = p.parse_args()
    configure_logging(args.verbose)
    LOG.debug('Starting %s; workdir=%s', 'apply' if args.apply else 'check only', args.workdir)
    require(sys.version_info >= (3, 9), 'Python 3.9+ required.')
    require(shutil.which('wg'), 'wg missing. On Mac: brew install wireguard-tools')
    if args.plain_api:
        require(args.tls_fingerprint is None, '--plain-api cannot be combined with --tls-fingerprint.')
        fingerprint = None
        print('Warning: plain API sends credentials and management traffic without encryption.', file=sys.stderr)
    else:
        fingerprint = (args.tls_fingerprint or '').replace(':', '').lower()
        require(re.fullmatch(r'[a-f0-9]{64}', fingerprint), 'A verified SHA256 certificate fingerprint (64 hex digits) is required unless --plain-api is selected.')
    if args.api_port is None:
        args.api_port = 8728 if args.plain_api else 8729
    require(1 <= args.api_port <= 65535 and 1024 <= args.wg_port <= 65535, 'Invalid port.')
    require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,29}', args.interface), 'Invalid interface name.')
    require(args.wan and not any(ord(x) < 32 for x in args.wan), 'Invalid WAN name.')
    subnet = ip.ip_interface(args.subnet)
    require(subnet.version == 4 and 16 <= subnet.network.prefixlen <= 29, 'Use an IPv4 subnet between /16 and /29.')
    require(subnet.ip == subnet.network.network_address + 1, 'Router must use first usable subnet address.')
    require(any(subnet.network.subnet_of(ip.ip_network(n)) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')),
            'VPN subnet must be RFC1918 private space.')
    require(ip.ip_address(args.endpoint).version == 4 and ip.ip_address(args.endpoint).is_global, 'Endpoint must be a public IPv4 address.')
    dns = [x.strip() for x in args.dns.split(',')]
    require(all(ip.ip_address(x).version == 4 and ip.ip_address(x).is_global for x in dns), 'Use public IPv4 DNS servers.')
    require(not args.apply or args.backup_confirmed, 'Before --apply, download a current router backup; then add --backup-confirmed.')
    users = users_csv(args.csv)
    root = Path(args.workdir).expanduser().absolute()
    require(not root.is_symlink(), 'workdir must not be a symlink.')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    lock_path = root / '.lock'
    require(not lock_path.is_symlink(), 'Lock file must not be a symlink.')
    lock = open(lock_path, 'a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Stop('Another run is using this workdir.')
    state_path = root / 'state.json'
    require(not state_path.is_symlink(), 'state.json must not be a symlink.')
    config = {k: getattr(args, k) for k in ('host', 'api_port', 'wan', 'endpoint', 'interface', 'wg_port')}
    config.update(subnet=str(subnet), fingerprint=fingerprint, dns=dns)
    if state_path.exists():
        LOG.debug('Loading existing deployment state from %s', state_path)
        state = json.loads(state_path.read_text(encoding='utf-8'))
        require(state.get('schema') == 1 and state['config'] == config, 'State/config mismatch; preserve original arguments and state.')
        require(re.fullmatch(r'[a-f0-9]{32}', state['owner']), 'Invalid state owner.')
        seen_addresses, seen_keys = set(), set()
        for uid, u in state['users'].items():
            require(re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', uid) and
                    re.fullmatch(r'[A-Za-z][A-Za-z .-]{1,79}', u['name']), 'Invalid state user.')
            address = ip.ip_address(u['address'])
            require(address in subnet.network and subnet.ip < address < subnet.network.broadcast_address, 'State IP outside client range.')
            require(u['address'] not in seen_addresses and u['public'] not in seen_keys, 'Duplicate state IP/key.')
            seen_addresses.add(u['address'])
            seen_keys.add(u['public'])
            require(public_key(u['private']) == u['public'], 'State key mismatch.')
    else:
        state = {'schema': 1, 'owner': uuid.uuid4().hex, 'config': config, 'users': {}, 'complete': False}
    # Password is requested interactively, never argv/environment/state/logs.
    api = API(args.host, args.api_port, fingerprint)
    try:
        api.call('/login', name=args.user, password=getpass.getpass('Router API password: '))
        LOG.debug('Authenticated; collecting router inventory')
        inv = inventory(api)
        identity = inv['/system/identity'][0].get('name', '')
        if state.get('router_identity'):
            require(state['router_identity'] == identity, 'Router identity changed; review before continuing.')
        state['router_identity'] = identity
        preflight(inv, state)  # No local client key changes before router conflict checks.
        add_users(state, users)
        save(state_path, state)  # durable secrets BEFORE the first router write
        version = preflight(inv, state)
        # Explicitly selected properties prevent collection of router credentials.
        save(root / 'preflight-snapshot.json', inv)
        objects = desired_objects(state)
        plan = [{'action': 'keep' if own_row(inv[o['path']], o['fields']) else 'add',
                 'path': o['path'], 'fields': o['fields']} for o in objects]
        save(root / 'plan.json', {'router': identity, 'version': version, 'objects': plan})
        atomic(root / 'rollback.rsc', rollback_text(state))
        print('Router:', identity, '| RouterOS:', version)
        print('Range:', subnet, '| WAN:', args.wan, '| retained users:', len(state['users']))
        print('Planned additions:', sum(x['action'] == 'add' for x in plan))
        for u in state['users'].values():
            print(u['address'], '|', u['name'])
        if not args.apply:
            print('CHECK ONLY: no router configuration changed. Review plan.json, then rerun with --apply --backup-confirmed.')
            return
        # Re-read after the plan; concurrent administrators must still be excluded operationally.
        preflight(inventory(api), state)
        for obj in objects:
            ensure(api, state, obj, state_path)
        finish_deployment(api, state, objects, state_path)
        export_clients(root, state)
        print('SUCCESS: client files:', root / 'clients')
        print('Keep state.json private and backed up. Send each user only their own .conf file.')
    finally:
        api.sock.close()
        lock.close()

if __name__ == '__main__':
    try:
        main()
    except (Stop, OSError, ValueError, KeyError, subprocess.CalledProcessError) as e:
        print('STOP:', str(e), file=sys.stderr)
        print('No automatic rollback. Preserve workdir/state.json. Fix the reported issue and rerun the same command.', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\nInterrupted. Preserve state; a write may have completed. Rerun to reconcile.', file=sys.stderr)
        sys.exit(130)

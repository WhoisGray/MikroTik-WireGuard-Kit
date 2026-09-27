"""Offline safety tests. No router access, keys or passwords required."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import wg_manager as w


def fixture():
    state = {'schema': 1, 'owner': 'a' * 32, 'complete': False,
             'config': {'host': '8.8.8.8', 'api_port': 8729, 'wan': 'ether1',
                        'endpoint': '8.8.8.8', 'interface': 'wg-staff', 'wg_port': 51820,
                        'subnet': '10.220.10.1/24', 'fingerprint': 'b' * 64, 'dns': ['1.1.1.1']},
             'users': {'alice': {'id': 'alice', 'name': 'Alice Example', 'name_fa': 'نمونه',
                                 'private': 'PRIVATE', 'public': 'PUBLIC', 'address': '10.220.10.2'}}}
    inv = {p: [] for p in w.PATHS}
    inv['/system/resource'] = [{'version': '7.20.8'}]
    inv['/system/identity'] = [{'name': 'example'}]
    inv['/interface'] = [{'name': 'ether1', 'running': 'true', 'disabled': 'false'}]
    inv[w.ADDR] = [{'address': '8.8.8.8/24', 'interface': 'ether1'}]
    inv['/ip/route'] = [{'dst-address': '0.0.0.0/0', 'routing-table': 'main',
                         'active': 'true', 'immediate-gw': '8.8.8.1%ether1'}]
    inv['/ip/vrf'] = [{'name': 'main'}]
    inv['/ip/settings'] = [{'ip-forward': 'true'}]
    inv['/ip/firewall/connection/tracking'] = [{'enabled': 'auto'}]
    inv[w.FILTER] = [{'.id': '*1', 'chain': 'input', 'action': 'drop', 'comment': 'old-input'},
                     {'.id': '*2', 'chain': 'forward', 'action': 'fasttrack-connection', 'comment': 'old-fasttrack'}]
    inv[w.NAT] = [{'.id': '*3', 'chain': 'srcnat', 'action': 'masquerade', 'comment': 'old-nat'}]
    return state, inv


class FakeAPI:
    def __init__(self, inv):
        self.inv = inv
        self.writes = []
        self.counter = 100
        self.sock = type('Socket', (), {'close': lambda self: None})()

    def rows(self, path, props=None):
        if path == w.PEER and self.inv['/system/resource'][0]['version'].startswith('7.12.1'):
            assert props and 'name' not in props.split(','), '7.12.1 has no peer name property'
        rows = copy.deepcopy(self.inv[path])
        if path in (w.ADDR, w.FILTER, w.V6FILTER):
            for row in rows:
                references = (row.get('interface'), row.get('in-interface'), row.get('out-interface'))
                if any(r.get('name') in references and w.yes(r.get('disabled'))
                       for r in self.inv[w.WG]):
                    row['invalid'] = 'true'
        return rows

    def call(self, command, **attrs):
        if command == '/login':
            return [], {}
        path, action = command.rsplit('/', 1)
        if path == w.PEER and self.inv['/system/resource'][0]['version'].startswith('7.12.1'):
            assert 'name' not in attrs, '7.12.1 rejects peer name'
        if action == 'add':
            self.writes.append((command, copy.deepcopy(attrs)))
            fields = dict(attrs)
            before = fields.pop('place-before', None)
            fields['.id'] = '*' + str(self.counter)
            self.counter += 1
            for k, v in list(fields.items()):
                fields[k] = w.canonical(v)
            if path == w.WG:
                fields['public-key'] = 'SERVER_PUBLIC'
            if before:
                position = next(i for i, r in enumerate(self.inv[path]) if r['.id'] == before)
                self.inv[path].insert(position, fields)
            else:
                self.inv[path].append(fields)
            return [], {'ret': fields['.id']}
        if action == 'set':
            self.writes.append((command, dict(attrs)))
            row = next(r for r in self.inv[path] if r['.id'] == attrs['.id'])
            row.update({k: w.canonical(v) for k, v in attrs.items()})
            return [], {}
        raise AssertionError(command)


class SafetyTests(unittest.TestCase):
    def test_resume_reported_firewall_failure_and_activate(self):
        state, inv = fixture()
        inv['/system/resource'][0]['version'] = '7.12.1 (stable)'
        api = FakeAPI(inv)
        with tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()):
            path = Path(d) / 'state.json'
            w.preflight(w.inventory(api), state)
            objects = w.desired_objects(state)
            for obj in objects[:4]:
                w.ensure(api, state, obj, path)
            # Exactly the logged failure: add succeeded, verification stopped before baseline save.
            failed = objects[4]
            self.assertTrue(failed['fields']['comment'].endswith(':f-private-0'))
            api.call(failed['path'] + '/add', **failed['fields'])
            self.assertNotIn(failed['fields']['comment'], state['rule_baselines'])
            w.preflight(w.inventory(api), state)
            for obj in objects:
                w.ensure(api, state, obj, path)
            self.assertIn(failed['fields']['comment'], state['rule_baselines'])
            staged = w.inventory(api)
            for firewall in (w.FILTER, w.V6FILTER):
                self.assertTrue(any(w.yes(r.get('invalid')) for r in staged[firewall]))
            w.finish_deployment(api, state, objects, path)
            self.assertTrue(state['complete'])
            self.assertTrue(w.active(inv[w.WG][0]))
            writes = len(api.writes)
            for obj in objects:
                w.ensure(api, state, obj, path)
            w.finish_deployment(api, state, objects, path)
            self.assertEqual(writes, len(api.writes))
            self.assertEqual(sum(command.endswith('/add') for command, _ in api.writes), len(objects))

    def test_invalid_rules_after_activation_disable_staged_interface(self):
        for firewall, suffix in ((w.FILTER, 'f-private-0'), (w.V6FILTER, 'v6-input')):
            with self.subTest(path=firewall), tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()), patch.object(w.time, 'sleep'):
                state, inv = fixture()
                api = FakeAPI(inv)
                path = Path(d) / 'state.json'
                objects = w.desired_objects(state)
                for obj in objects:
                    w.ensure(api, state, obj, path)
                row = next(r for r in inv[firewall] if r.get('comment') == w.tag(state, suffix))
                row['invalid'] = 'true'  # persists even with the interface enabled
                with self.assertRaisesRegex(w.Stop, 'Managed object is invalid'):
                    w.finish_deployment(api, state, objects, path)
                self.assertFalse(state['complete'])
                self.assertFalse(w.active(inv[w.WG][0]))
                self.assertFalse(json.loads(path.read_text())['complete'])
                self.assertEqual(api.writes[-1][1]['disabled'], 'yes')

    def test_activation_waits_for_runtime_flags_to_settle(self):
        state, inv = fixture()
        api = FakeAPI(inv)
        with tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()):
            path = Path(d) / 'state.json'
            objects = w.desired_objects(state)
            for obj in objects:
                w.ensure(api, state, obj, path)
            row = next(r for r in inv[w.FILTER] if r.get('comment') == w.tag(state, 'f-private-0'))
            row['invalid'] = 'true'
            with patch.object(w.time, 'sleep', side_effect=lambda _: row.pop('invalid')) as wait:
                w.finish_deployment(api, state, objects, path)
                wait.assert_called_once_with(0.2)
            self.assertTrue(state['complete'])
            self.assertTrue(w.active(inv[w.WG][0]))

    def test_staging_does_not_ignore_unrelated_invalid_rules_or_drift(self):
        state, inv = fixture()
        api = FakeAPI(inv)
        with tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()):
            path = Path(d) / 'state.json'
            objects = w.desired_objects(state)
            for obj in objects:
                w.ensure(api, state, obj, path)
            for table, suffix in ((w.NAT, 'nat'), (w.FILTER, 'udp-listener'), (w.FILTER, 'f-invalid')):
                row = next(r for r in inv[table] if r.get('comment') == w.tag(state, suffix))
                row['invalid'] = 'true'
                with self.assertRaisesRegex(w.Stop, 'Managed object is invalid'):
                    w.preflight(w.inventory(api), state)
                del row['invalid']
            row = next(r for r in inv[w.FILTER] if r.get('comment') == w.tag(state, 'f-private-0'))
            row['action'] = 'accept'
            with self.assertRaisesRegex(w.Stop, 'Managed object drift'):
                w.preflight(w.inventory(api), state)

    def test_missing_object_prevents_activation(self):
        state, inv = fixture()
        api = FakeAPI(inv)
        with tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()):
            path = Path(d) / 'state.json'
            objects = w.desired_objects(state)
            for obj in objects[:-1]:
                w.ensure(api, state, obj, path)
            with self.assertRaisesRegex(w.Stop, 'Cannot activate: missing managed object'):
                w.finish_deployment(api, state, objects, path)
            self.assertFalse(w.active(inv[w.WG][0]))

    def test_pending_address_resume_and_strict_validity(self):
        state, inv = fixture()
        inv['/system/resource'][0]['version'] = '7.12.1 (stable)'
        api = FakeAPI(inv)
        with tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()):
            path = Path(d) / 'state.json'
            w.preflight(w.inventory(api), state)
            objects = w.desired_objects(state)
            w.ensure(api, state, objects[0], path)
            # Reproduce the previous failed run: address exists but was not verified.
            api.call(w.ADDR + '/add', **objects[1]['fields'])
            self.assertEqual(api.rows(w.ADDR)[-1]['invalid'], 'true')
            w.preflight(w.inventory(api), state)
            w.ensure(api, state, objects[1], path)
            self.assertEqual(len(api.writes), 2)
            # Deferring validity must never hide address/configuration drift.
            inv[w.ADDR][-1]['address'] = '10.220.10.2/24'
            with self.assertRaises(w.Stop):
                w.preflight(w.inventory(api), state)
            inv[w.ADDR][-1]['address'] = state['config']['subnet']
            self.apply_all(api, state, path)
            self.assertFalse(w.yes(api.rows(w.ADDR)[-1].get('invalid')))
            inv[w.ADDR][-1]['invalid'] = 'true'
            with self.assertRaisesRegex(w.Stop, 'Managed object is invalid'):
                w.preflight(w.inventory(api), state)
            state['complete'] = False
            with self.assertRaisesRegex(w.Stop, 'Managed object is invalid'):
                w.preflight(w.inventory(api), state)

    def apply_all(self, api, state, path):
        with patch('sys.stdout', io.StringIO()):
            for obj in w.desired_objects(state):
                w.ensure(api, state, obj, path)
        w.preflight(api.inv, state)
        api.inv[w.WG][0]['disabled'] = 'false'
        state['server_public'] = 'SERVER_PUBLIC'
        state['complete'] = True
        state['provisioned_users'] = list(state['users'])
        w.preflight(api.inv, state)

    def test_repeat_keeps_all_objects_and_foreign_order(self):
        state, inv = fixture()
        old_filter = copy.deepcopy(inv[w.FILTER])
        old_nat = copy.deepcopy(inv[w.NAT])
        api = FakeAPI(inv)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'state.json'
            self.apply_all(api, state, p)
            count = len(api.writes)
            self.apply_all(api, state, p)
            self.assertEqual(count, len(api.writes))
        self.assertEqual([r for r in inv[w.FILTER] if r.get('comment', '').startswith('old-')], old_filter)
        self.assertEqual([r for r in inv[w.NAT] if r.get('comment', '').startswith('old-')], old_nat)

    def test_resume_after_every_partial_step(self):
        sample, _ = fixture()
        for stop in range(1, len(w.desired_objects(sample))):
            state, inv = fixture()
            api = FakeAPI(inv)
            with tempfile.TemporaryDirectory() as d, patch('sys.stdout', io.StringIO()):
                p = Path(d) / 'state.json'
                for obj in w.desired_objects(state)[:stop]:
                    w.ensure(api, state, obj, p)
                w.preflight(inv, state)
                self.apply_all(api, state, p)
                self.assertEqual(len(api.writes), len(w.desired_objects(state)))

    def test_ecmp_same_route_is_rejected(self):
        state, inv = fixture()
        inv['/ip/route'][0]['immediate-gw'] = '8.8.8.1%ether2,8.8.8.2%ether1'
        with self.assertRaises(w.Stop):
            w.preflight(inv, state)

    def test_collision_sources(self):
        examples = [(w.ADDR, {'address': '10.220.10.15/32', 'interface': 'old-tunnel'}),
                    ('/ip/route', {'dst-address': '10.0.0.0/8'}),
                    ('/ip/pool', {'name': 'old-pool', 'ranges': '10.220.9.250-10.220.10.9'}),
                    ('/ip/dhcp-server/lease', {'address': '10.220.10.2'}),
                    ('/ppp/secret', {'remote-address': '10.220.10.9'}),
                    (w.PEER, {'allowed-address': '10.220.10.2/32', 'interface': 'old-wg'}),
                    (w.PEER, {'allowed-address': '0.0.0.0/0', 'interface': 'old-wg'})]
        for path, row in examples:
            state, inv = fixture()
            inv[path].append(row)
            with self.subTest(path=path), self.assertRaises(w.Stop):
                w.preflight(inv, state)

    def test_complex_policy_fails_closed(self):
        for path, row in [('/ip/firewall/mangle', {'action': 'mark-routing'}),
                          ('/ip/firewall/raw', {'action': 'notrack'}),
                          ('/routing/rule', {'action': 'lookup'}),
                          ('/ip/vrf', {'name': 'private'}),
                          ('/ip/ipsec/policy', {'template': 'false'}),
                          (w.NAT, {'chain': 'dstnat', 'action': 'dst-nat'})]:
            state, inv = fixture()
            inv[path].append(row)
            with self.subTest(path=path), self.assertRaises(w.Stop):
                w.preflight(inv, state)

    def test_foreign_interface_and_peer_name_not_adopted(self):
        for path, row in [(w.WG, {'name': 'wg-staff', 'comment': 'someone else'}),
                          (w.PEER, {'name': 'alice', 'interface': 'other', 'public-key': 'OTHER'})]:
            state, inv = fixture()
            inv[path].append(row)
            with self.assertRaises(w.Stop):
                w.preflight(inv, state)

    def test_deleted_or_disabled_peer_is_not_restored(self):
        for remove in (True, False):
            state, inv = fixture()
            api = FakeAPI(inv)
            with tempfile.TemporaryDirectory() as d:
                self.apply_all(api, state, Path(d) / 'state.json')
            if remove:
                inv[w.PEER].clear()
            else:
                inv[w.PEER][0]['disabled'] = 'true'
            with self.assertRaises(w.Stop):
                w.preflight(inv, state)

    def test_filter_tampering_and_rule_order_stop(self):
        for change in ('selector', 'order', 'before'):
            state, inv = fixture()
            api = FakeAPI(inv)
            with tempfile.TemporaryDirectory() as d:
                self.apply_all(api, state, Path(d) / 'state.json')
            if change == 'selector':
                row = next(r for r in inv[w.FILTER] if r.get('comment', '').endswith(':f-final'))
                row['src-address'] = '1.2.3.4'
            elif change == 'before':
                inv[w.FILTER].insert(0, {'chain': 'forward', 'action': 'accept', 'comment': 'new-unrelated-rule'})
            else:
                chain = [r for r in inv[w.FILTER] if r.get('chain', '').startswith('wgk-')]
                i, j = inv[w.FILTER].index(chain[0]), inv[w.FILTER].index(chain[1])
                inv[w.FILTER][i], inv[w.FILTER][j] = inv[w.FILTER][j], inv[w.FILTER][i]
            with self.subTest(change=change), self.assertRaises(w.Stop):
                w.preflight(inv, state)

    def test_append_preserves_all_existing_addresses_and_keys(self):
        state, _ = fixture()
        old = copy.deepcopy(state['users']['alice'])
        users = [{'id': 'bob', 'name': 'Bob Example', 'name_fa': 'باب'}]
        with patch.object(w, 'keypair', return_value=('BOB_PRIVATE', 'BOB_PUBLIC')):
            w.add_users(state, users)
            w.add_users(state, users)
        self.assertEqual(state['users']['alice'], old)
        self.assertEqual(state['users']['bob']['address'], '10.220.10.3')
        self.assertEqual(len(state['users']), 2)

    def test_csv_current_users_have_unique_ids(self):
        users = w.users_csv(Path(__file__).with_name('users.example.csv'))
        self.assertTrue(users)
        self.assertEqual(len({u['id'] for u in users}), len(users))

    def test_export_regeneration_and_permissions(self):
        state, _ = fixture()
        state['server_public'] = 'SERVER_PUBLIC'
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            w.export_clients(root, state)
            path = root / 'clients/Alice_Example.conf'
            data = path.read_bytes()
            w.export_clients(root, state)
            self.assertEqual(data, path.read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn(b'AllowedIPs = 0.0.0.0/0, ::/0', data)
            self.assertIn(b'8.8.8.8:51820', data)

    def test_subnet_capacity_fails_before_key_generation(self):
        state, _ = fixture()
        state['config']['subnet'] = '10.220.10.1/29'
        users = [{'id': 'person' + str(i), 'name': 'Person ' + str(i), 'name_fa': 'نمونه'} for i in range(8)]
        with patch.object(w, 'keypair') as kp, self.assertRaises(w.Stop):
            w.add_users(state, users)
        kp.assert_not_called()

    def test_duplicate_ownership_comments_stop(self):
        state, inv = fixture()
        obj = w.desired_objects(state)[0]['fields']
        inv[w.WG] = [dict(obj), dict(obj)]
        with self.assertRaises(w.Stop):
            w.preflight(inv, state)


class MainWorkflowTests(unittest.TestCase):
    def test_check_apply_and_repeat_with_actual_csv_rows(self):
        self.check_workflow(False)

    def test_plain_api_check_apply_and_repeat(self):
        self.check_workflow(True)

    def test_7121_plain_api_check_apply_repeat_and_revocation(self):
        self.check_workflow(True, '7.12.1 (stable)')

    def check_workflow(self, plain, version='7.20.8'):
        state, inv = fixture()
        expected_users = w.users_csv(Path(__file__).with_name('users.example.csv'))
        user_count = len(expected_users)
        inv['/system/resource'][0]['version'] = version
        api = FakeAPI(inv)
        serial = iter(range(100))
        def kp():
            n = str(next(serial))
            return 'PRIVATE' + n, 'PUBLIC' + n
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'wg-output'
            args = ['wg_manager.py', '--user', 'wgprovision', '--wan', 'ether1',
                    '--host', '8.8.8.8', '--endpoint', '8.8.8.8',
                    '--workdir', str(root),
                    '--csv', str(Path(__file__).with_name('users.example.csv'))]
            args += ['--plain-api'] if plain else ['--tls-fingerprint', 'b' * 64]
            def run(extra=()):
                with patch('sys.argv', args + list(extra)), patch.object(w, 'API', return_value=api) as connect, \
                     patch.object(w.shutil, 'which', return_value='/opt/homebrew/bin/wg'), \
                     patch.object(w.getpass, 'getpass', return_value='NOT_LOGGED'), \
                     patch.object(w, 'keypair', side_effect=kp), \
                     patch.object(w, 'public_key', side_effect=lambda x: x.replace('PRIVATE', 'PUBLIC')), \
                     patch('sys.stdout', io.StringIO()):
                    w.main()
                    connect.assert_called_once_with('8.8.8.8', 8728 if plain else 8729,
                                                    None if plain else 'b' * 64)
            run()
            self.assertEqual(api.writes, [])
            before = json.loads((root / 'state.json').read_text())
            self.assertEqual(list(before['users']), [u['id'] for u in expected_users])
            self.assertFalse((root / 'clients').exists())
            run(['--apply', '--backup-confirmed'])
            first = {p.name: p.read_bytes() for p in (root / 'clients').glob('*.conf')}
            count = len(api.writes)
            run(['--apply', '--backup-confirmed'])
            self.assertEqual(count, len(api.writes))
            self.assertEqual(first, {p.name: p.read_bytes() for p in (root / 'clients').glob('*.conf')})
            self.assertEqual(len(first), user_count)
            after = json.loads((root / 'state.json').read_text())
            self.assertEqual(before['users'], after['users'])
            self.assertEqual([u['address'] for u in after['users'].values()],
                             ['10.220.10.' + str(i) for i in range(2, 2 + user_count)])
            self.assertNotIn('NOT_LOGGED', (root / 'state.json').read_text())
            if version.startswith('7.12.1'):
                self.assertFalse(after['peer_names'])
                self.assertTrue(all('name' not in row for row in api.inv[w.PEER]))
                # An OS upgrade preserves the original comment-based deployment.
                api.inv['/system/resource'][0]['version'] = '7.20.8'
                run(['--apply', '--backup-confirmed'])
                self.assertEqual(count, len(api.writes))
                api.inv[w.PEER][0]['disabled'] = 'true'
                with self.assertRaises(w.Stop):
                    run(['--apply', '--backup-confirmed'])
                api.inv[w.PEER].pop(0)
                with self.assertRaisesRegex(w.Stop, 'Previously provisioned peer missing'):
                    run(['--apply', '--backup-confirmed'])
                self.assertEqual(count, len(api.writes))


class ProtocolTests(unittest.TestCase):
    def test_verbose_api_requests_redact_secrets_and_do_not_dump_responses(self):
        api = w.API.__new__(w.API)
        api.sock = Mock()
        secret = 'NEVER_PRINT_THIS_SECRET'
        for command, attrs in [('/login', {'name': 'admin', 'password': secret}),
                               (w.PEER + '/add', {'interface': 'wg-test', 'public-key': 'PUBLIC',
                                                'private-key': secret, 'preshared-key': secret,
                                                'unknown-option': secret})]:
            with self.subTest(command=command), self.assertLogs(w.LOG, level='DEBUG') as logs, \
                 patch.object(api, 'word', side_effect=['!re', '=private-key=' + secret, '', '!done', '']):
                rows, _ = api.call(command, **attrs)
            output = '\n'.join(logs.output)
            self.assertIn(command, output)
            self.assertIn('<redacted>', output)
            self.assertNotIn(secret, output)
            self.assertEqual(rows[0]['private-key'], secret)
            self.assertIn(secret.encode(), api.sock.sendall.call_args.args[0])
        self.assertIn('wg-test', output)
        self.assertIn('PUBLIC', output)

    def test_api_trace_is_off_without_verbose(self):
        api = w.API.__new__(w.API)
        api.sock = Mock()
        output = io.StringIO()
        try:
            with patch('sys.stderr', output):
                w.configure_logging(False)
                with patch.object(api, 'word', side_effect=['!done', '']):
                    api.call('/login', password='secret')
            self.assertEqual(output.getvalue(), '')
        finally:
            w.configure_logging(False)

    def test_login_error_does_not_echo_credentials(self):
        api = w.API.__new__(w.API)
        api.sock = Mock()
        with patch.object(api, 'word', side_effect=['!trap', '=message=password secret', '', '!done', '']):
            with self.assertRaisesRegex(w.Stop, '^/login: authentication failed$'):
                api.call('/login', password='secret')

    def test_supported_version_boundaries(self):
        for version in ['7.12.1', '7.12.1 (stable)', '7.15', '7.20.8 (stable)']:
            self.assertEqual(w.router_version(version)[0], 7)
        for version in ['7.12', '7.12.0', '6.49.10', '8.1', '7.15rc1', '7.15beta2', 'unknown']:
            with self.assertRaises(w.Stop):
                w.router_version(version)

    def test_plain_connection_does_not_use_tls(self):
        with patch.object(w.socket, 'create_connection') as connect, patch.object(w.ssl, 'SSLContext') as tls:
            api = w.API('router', 8728, None)
            connect.assert_called_once_with(('router', 8728), timeout=20)
            self.assertIs(api.sock, connect.return_value)
            tls.assert_not_called()

    def test_tls_pin_mismatch_closes_connection(self):
        with patch.object(w.socket, 'create_connection') as connect, patch.object(w.ssl, 'SSLContext') as tls:
            sock = tls.return_value.wrap_socket.return_value
            sock.getpeercert.return_value = b'certificate'
            with self.assertRaisesRegex(w.Stop, 'TLS certificate pin mismatch'):
                w.API('router', 8729, '0' * 64)
            connect.return_value.close.assert_called_once()
            sock.close.assert_called_once()
            sock.sendall.assert_not_called()

    def test_all_api_length_encodings(self):
        for n in [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455]:
            encoded = w.length(n)
            b = encoded[0]
            mask = [0x7f, 0x3f, 0x1f, 0x0f][len(encoded) - 1]
            decoded = ((b & mask) << (8 * (len(encoded) - 1))) | int.from_bytes(encoded[1:], 'big')
            self.assertEqual(decoded, n)
        self.assertEqual(w.length(268435456), b'\xf0\x10\x00\x00\x00')

    def test_trap_drained_before_next_command_and_empty_supported(self):
        class Sock:
            def __init__(self, data): self.data, self.sent = data, b''
            def recv(self, n):
                out, self.data = self.data[:min(n, 2)], self.data[min(n, 2):]
                return out
            def sendall(self, data): self.sent += data
        def sentence(*words):
            return b''.join(w.length(len(x.encode())) + x.encode() for x in words) + b'\0'
        api = w.API.__new__(w.API)
        api.sock = Sock(sentence('!trap', '=message=bad command') + sentence('!done') +
                        sentence('!empty') + sentence('!done') +
                        sentence('!re', '=comment=نام فارسی', '=key=a=b') + sentence('!done'))
        with self.assertRaises(w.Stop): api.call('/bad')
        self.assertEqual(api.call('/good')[0], [])
        self.assertEqual(api.call('/read')[0], [{'comment': 'نام فارسی', 'key': 'a=b'}])

if __name__ == '__main__':
    unittest.main(verbosity=2)

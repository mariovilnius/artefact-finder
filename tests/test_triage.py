import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import yaml

MODULE = Path(__file__).resolve().parents[1] / 'skills/mail-log-triage/scripts/triage.py'
spec = importlib.util.spec_from_file_location('triage', MODULE)
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


class TriageTests(unittest.TestCase):
    def test_remote_not_local_and_no_guessed_year(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap-login: Login: user=<user@example.test>, rip=192.0.2.1, lip=198.51.100.2, TLS, session=<sample>')
        self.assertEqual(event['source_ip'], '192.0.2.1')
        self.assertEqual(event['local_ip'], '198.51.100.2')
        self.assertEqual(event['time_status'], 'unknown')

    def test_dst_ambiguous_and_nonexistent(self):
        self.assertEqual(triage.normalize_time('Oct 25 03:30:00', 2026, 'Europe/Vilnius')['time_status'], 'ambiguous')
        self.assertEqual(len(triage.normalize_time('Oct 25 03:30:00', 2026, 'Europe/Vilnius')['utc_candidates']), 2)
        self.assertEqual(triage.normalize_time('Mar 29 03:30:00', 2026, 'Europe/Vilnius')['time_status'], 'nonexistent')

    def test_action_has_no_invented_ip(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap(user@example.test): expunge: box=INBOX, uid=1, msgid=<x@example.test>, size=12, subject==?utf-8?Q?PIN_code?=')
        self.assertEqual(event['subject'], 'PIN code')
        self.assertIsNone(event['source_ip'])
        self.assertEqual(event['event_type'], 'mail_expunge')

    def test_abort_is_not_automatically_auth_failure(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap-login: Aborted login (no auth attempts): user=<>, rip=192.0.2.1, lip=198.51.100.2')
        self.assertEqual(event['event_type'], 'login_aborted')
        self.assertEqual(event['tls_marker'], 'unknown')

    def test_retr_is_command_count(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: pop3(user@example.test): Disconnected: Logged out retr=4/123, del=0/2')
        self.assertEqual(event['retr_commands'], 4)
        self.assertNotIn('unique_messages', event)
        self.assertEqual(event['del_pair_raw'], '0/2')

    def test_binary_provenance_and_source_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'sample.txt'
            first = b'not a dovecot row\r\n'
            login = b'Oct  7 18:56:25 mail dovecot: pop3-login: Login: user=<u@example.test>, rip=192.0.2.1, lip=198.51.100.2, session=<same>\n'
            original = first + login + login
            source.write_bytes(original)
            manifest = triage.run([source], root / 'out')
            events = [json.loads(x) for x in (root / 'out/events.jsonl').read_text().splitlines()]
            self.assertEqual(events[0]['byte_offset'], len(first))
            self.assertTrue(events[1]['duplicate_session_record'])
            self.assertEqual(manifest['coverage']['lines'], 3)
            self.assertEqual(manifest['coverage']['unparsed'], 1)
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(FileExistsError):
                triage.run([source], root / 'out')

    def test_invalid_date_is_flagged(self):
        self.assertEqual(triage.normalize_time('Feb 30 12:00:00', 2026, 'UTC')['time_status'], 'invalid')

    def test_backend_formats_keep_protocol_unknown(self):
        bodies = [
            'auth-worker(42): pam(u@example.test,192.0.2.10,<s1>): pam_authenticate() failed: Authentication failure (password mismatch?)',
            'auth: passwd-file(u@example.test,192.0.2.10): unknown user',
            'auth-worker(42): Info: conn unix:auth-worker (pid=2,uid=3): auth-worker<7>: sql(u@example.test,192.0.2.10,<s1>): Password mismatch',
            'auth<9>: ldap(u@example.test,192.0.2.10): Invalid credentials',
        ]
        for body in bodies:
            with self.subTest(body=body):
                event = triage.parse('Oct  7 18:56:25 mail dovecot: ' + body)
                self.assertEqual(event['event_type'], 'auth_failure')
                self.assertEqual(event['account'], 'u@example.test')
                self.assertEqual(event['source_ip'], '192.0.2.10')
                self.assertIsNone(event['protocol'])

    def test_pam_syslog_envelope(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot-auth[42]: pam_unix(dovecot:auth): authentication failure; logname= uid=0 euid=0 tty=dovecot ruser=u@example.test rhost=2001:db8::5 user=u@example.test')
        self.assertEqual(event['source_ip'], '2001:db8::5')
        self.assertEqual(event['account'], 'u@example.test')
        self.assertEqual(event['event_type'], 'auth_failure')

    def test_backend_database_error_not_bad_password(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: auth-worker(42): sql(u@example.test,192.0.2.1): database connection failed')
        self.assertEqual(event['event_type'], 'unknown')
        self.assertEqual(event['source_ip'], '192.0.2.1')

    def test_modern_login_attempt_count_and_ipv6(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap-login: Info: Disconnected: Connection closed (auth failed, 3 attempts in 8 secs): user=<u@example.test>, rip=2001:db8::1, lip=2001:db8::2, TLS')
        self.assertEqual(event['event_type'], 'auth_failure')
        self.assertEqual(event['attempts_reported'], 3)
        self.assertEqual(event['source_ip'], '2001:db8::1')
        self.assertEqual(event['tls_marker'], 'present')

    def test_non_mail_login_protocols_preserved(self):
        for protocol in ['submission', 'managesieve']:
            event = triage.parse(f'Oct  7 18:56:25 mail dovecot: {protocol}-login: Login: user=<u@example.test>, rip=192.0.2.1, lip=198.51.100.1')
            self.assertEqual(event['protocol'], protocol)
            self.assertEqual(event['event_type'], 'auth_success')

    def test_incomplete_connection_separate_from_auth_failure(self):
        for reason in ['no auth attempts', 'disconnected during TLS handshake', "client didn't finish SASL auth"]:
            event = triage.parse(f'Oct  7 18:56:25 mail dovecot: imap-login: Disconnected ({reason}): user=<>, rip=192.0.2.1, lip=198.51.100.1')
            self.assertEqual(event['event_type'], 'login_aborted')

    def test_temporary_failure_not_invalid_credentials(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap-login: Disconnected (Temporary authentication failure): user=<u@example.test>, rip=192.0.2.1')
        self.assertEqual(event['auth_reason'], 'temporary_failure')

    def test_username_text_cannot_change_login_failure_reason(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap-login: Disconnected (no auth attempts): user=<auth failed 999 attempts@example.test>, rip=192.0.2.1')
        self.assertEqual(event['event_type'], 'login_aborted')
        self.assertIsNone(event['attempts_reported'])

    def test_invalid_peer_is_not_invented(self):
        event = triage.parse('Oct  7 18:56:25 mail dovecot: imap-login: Login: user=<u@example.test>, rip=invalid-ip, lip=198.51.100.1')
        self.assertIsNone(event['source_ip'])
        self.assertEqual(event['source_ip_invalid'], 'invalid-ip')


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.rules = triage.load_rules()

    def ids(self, event, **kwargs):
        return [r['id'] for r in triage.evaluate_rules(event, self.rules, **kwargs)]

    def test_pin_rule_excludes_known_false_positive(self):
        self.assertIn('AF-MAIL-001', self.ids({'event_type': 'mail_expunge', 'subject': 'PIN code for sign in'}))
        self.assertNotIn('AF-MAIL-001', self.ids({'event_type': 'mail_expunge', 'subject': 'RE: Pin brazing'}))
        self.assertNotIn('AF-MAIL-001', self.ids({'event_type': 'auth_success', 'subject': 'PIN code'}))

    def test_rules_never_match_missing_values(self):
        self.assertEqual(self.ids({}), [])

    def test_extended_connection_profile(self):
        event = {'event_type': 'login_aborted'}
        self.assertEqual(self.ids(event), [])
        self.assertIn('AF-CONNECTION-001', self.ids(event, profile='extended'))

    def test_threshold_override_does_not_modify_yaml_rule(self):
        event = {'protocol': 'pop3', 'retr_bytes': 50}
        self.assertNotIn('AF-TRANSFER-001', self.ids(event))
        self.assertIn('AF-TRANSFER-001', self.ids(event, large_bytes=40))
        self.assertNotIn('AF-TRANSFER-001', self.ids(event))

    def test_custom_yaml_changes_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            rule = {k: v for k, v in self.rules[0].items() if not k.startswith('_')}
            rule['match'] = [{'field': 'event_type', 'op': 'equals', 'value': 'auth_success'}]
            path = Path(temp) / 'custom.yaml'
            path.write_text(yaml.safe_dump(rule), encoding='utf-8')
            rules = triage.load_rules(temp)
            self.assertEqual(len(triage.evaluate_rules({'event_type': 'auth_success'}, rules)), 1)
            self.assertEqual(triage.evaluate_rules({'event_type': 'auth_failure'}, rules), [])

    def test_unsafe_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / 'unsafe.yaml').write_text('!!python/object/apply:builtins.str [unsafe]', encoding='utf-8')
            with self.assertRaises(yaml.YAMLError):
                triage.load_rules(temp)

    def test_invalid_rule_operator_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rule = {k: v for k, v in self.rules[0].items() if not k.startswith('_')}
            rule['match'] = [{'field': 'event_type', 'op': 'execute', 'value': 'anything'}]
            (Path(temp) / 'bad.yaml').write_text(yaml.safe_dump(rule), encoding='utf-8')
            with self.assertRaises(ValueError):
                triage.load_rules(temp)

    def test_duplicate_ids_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            rule = {k: v for k, v in self.rules[0].items() if not k.startswith('_')}
            for name in ['a.yaml', 'b.yaml']:
                (Path(temp) / name).write_text(yaml.safe_dump(rule), encoding='utf-8')
            with self.assertRaises(ValueError):
                triage.load_rules(temp)

    def test_end_to_end_backend_and_rules_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'synthetic.txt'
            source.write_text('Oct  7 18:56:25 mail dovecot: auth: sql(u@example.test,192.0.2.1): Password mismatch\nOct  7 18:56:25 mail dovecot: pop3-login: Login: user=<u@example.test>, rip=192.0.2.1\nOct  7 18:56:26 mail dovecot: pop3(u@example.test): Logged out retr=2/50000000\n', encoding='utf-8')
            manifest = triage.run([source], root / 'out', year=2026, zone='Europe/Vilnius')
            self.assertEqual(manifest['coverage']['auth_failure'], 1)
            self.assertEqual(manifest['coverage']['review_candidate_events'], 2)
            self.assertEqual(len(manifest['rules']), 4)
            self.assertTrue(all(len(r['sha256']) == 64 for r in manifest['rules']))
            findings = [json.loads(x) for x in (root / 'out/findings.jsonl').read_text().splitlines()]
            self.assertEqual(findings[0]['rules'][0]['id'], 'AF-AUTH-001')
            self.assertIn('false_positives', findings[0]['rules'][0])


if __name__ == '__main__':
    unittest.main()

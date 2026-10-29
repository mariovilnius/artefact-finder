import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()

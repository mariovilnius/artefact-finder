import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import yaml
from datetime import datetime

MODULE = Path(__file__).resolve().parents[1] / 'skills/mail-log-triage/scripts/triage.py'
spec = importlib.util.spec_from_file_location('triage_multi', MODULE)
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


def event(second=0, ip='192.0.2.1', day=7, account='u@example.test', protocol='pop3', host='mail', number=1, month='Oct', normalize=True):
    raw = f'{month} {day:2d} 12:00:{second:02d} {host} dovecot: {protocol}-login: Login: user=<{account}>, rip={ip}, lip=198.51.100.1, session=<s{number}>'
    row = triage.parse(raw, 2026 if normalize else None, 'Europe/Vilnius' if normalize else None)
    row.update(event_id=f'event-{number}', source_id='synthetic', file='synthetic.txt', line=number, byte_offset=number)
    return row


def detect(rows, window=5, excluded=()):
    with tempfile.TemporaryDirectory() as temp:
        detector = triage.MultiIPDetector(':memory:', window, excluded)
        try:
            for row in rows:
                detector.add(row)
            summaries = list(detector.summaries(temp))
            occurrences = [json.loads(s) for s in (Path(temp)/'multi-ip-occurrences.jsonl').read_text().splitlines()]
            return summaries, occurrences, dict(detector.stats)
        finally:
            detector.close()


class MultiIPTests(unittest.TestCase):
    def test_exact_second_is_a_pair_not_session_overlap(self):
        summaries, occurrences, _ = detect([event(number=1), event(ip='192.0.2.2', number=2)])
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]['exact_second_occurrences'], 1)
        self.assertEqual(occurrences[0]['delta_seconds'], 0)
        self.assertIn('not_session_overlap', summaries[0]['attribution'])
        self.assertEqual(occurrences[0]['login_a']['line'], 1)

    def test_window_boundary_and_override_semantics(self):
        rows = [event(), event(second=5, ip='192.0.2.2', number=2)]
        self.assertEqual(len(detect(rows, 5)[0]), 1)
        self.assertEqual(detect(rows, 4)[0], [])
        self.assertEqual(detect(rows, 0)[0], [])
        self.assertEqual(len(detect([event(), event(ip='192.0.2.2', number=2)], 0)[0]), 1)

    def test_duplicate_endpoint_seconds_do_not_inflate_pairs(self):
        rows = [event(), event(number=3), event(ip='192.0.2.2', number=2), event(ip='192.0.2.2', number=4)]
        summaries, occurrences, stats = detect(rows)
        self.assertEqual(stats['distinct_endpoint_seconds'], 2)
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(summaries[0]['pair_occurrences'], 1)

    def test_later_exact_match_replaces_near_match_same_ending_second(self):
        rows = [event(), event(second=3, ip='192.0.2.2', number=2), event(second=3, number=3)]
        summaries, occurrences, _ = detect(rows)
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0]['delta_seconds'], 0)
        self.assertEqual(summaries[0]['exact_second_occurrences'], 1)

    def test_repeated_pair_days_and_yaml_minimum(self):
        rows = [event(), event(ip='192.0.2.2', number=2), event(day=8, number=3), event(day=8, ip='192.0.2.2', number=4)]
        summaries, _, _ = detect(rows)
        self.assertEqual(summaries[0]['pair_occurrences'], 2)
        self.assertEqual(summaries[0]['pair_days'], 2)
        self.assertEqual(triage.evaluate_rules(summaries[0], triage.load_rules())[0]['id'], 'AF-CORRELATION-001')
        single = detect(rows[:2])[0][0]
        self.assertEqual(triage.evaluate_rules(single, triage.load_rules()), [])

    def test_same_ip_and_different_identities_are_not_pairs(self):
        variants = [dict(ip='192.0.2.1'), dict(ip='192.0.2.2', account='other@example.test'), dict(ip='192.0.2.2', protocol='imap'), dict(ip='192.0.2.2', host='other')]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertEqual(detect([event(), event(number=2, **variant)])[0], [])

    def test_out_of_order_rows_produce_same_summary(self):
        rows = [event(), event(second=3, ip='192.0.2.2', number=2), event(day=8, number=3), event(day=8, ip='192.0.2.2', number=4)]
        self.assertEqual(detect(rows)[0], detect(list(reversed(rows)))[0])

    def test_three_ips_are_three_pairs(self):
        summaries, occurrences, _ = detect([event(), event(ip='192.0.2.2', number=2), event(ip='192.0.2.3', number=3)])
        self.assertEqual(len(summaries), 3)
        self.assertEqual(len(occurrences), 3)

    def test_ambiguous_and_missing_times_are_skipped(self):
        ambiguous = event()
        ambiguous.update(triage.normalize_time('Oct 25 03:30:00', 2026, 'Europe/Vilnius'))
        _, _, stats = detect([ambiguous, event(normalize=False)])
        self.assertEqual(stats['nonunique_time_rows'], 2)
        self.assertEqual(stats['distinct_endpoint_seconds'], 0)

    def test_ipv4_mapped_address_is_not_a_second_endpoint(self):
        self.assertEqual(detect([event(), event(ip='::ffff:192.0.2.1', number=2)])[0], [])

    def test_excluded_ip_is_only_a_correlation_exclusion(self):
        summaries, _, stats = detect([event(), event(ip='192.0.2.2', number=2)], excluded=['192.0.2.2'])
        self.assertEqual(summaries, [])
        self.assertEqual(stats['excluded_ip_rows'], 1)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);source = root/'synthetic.txt'
            source.write_text('Oct  7 12:00:00 mail dovecot: pop3-login: Login: user=<u@example.test>, rip=192.0.2.2\nOct  7 12:00:01 mail dovecot: imap(u@example.test): expunge: box=INBOX, uid=1, msgid=<pin@example.test>, size=10, subject=PIN code\n')
            result = triage.run([source], root/'out', 2026, 'Europe/Vilnius', exclude_correlation_ips=['192.0.2.2'])
            self.assertEqual(result['coverage']['auth_success'], 1)
            findings = [json.loads(s) for s in (root/'out/findings.jsonl').read_text().splitlines()]
            self.assertEqual(findings[0]['rules'][0]['id'], 'AF-MAIL-001')

    def test_cross_file_repetition_and_run_window_override(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp);inputs=[]
            for day in [7,8]:
                path=root/f'day-{day}.txt'
                path.write_text(f'Oct {day:2d} 12:00:00 mail dovecot: pop3-login: Login: user=<u@example.test>, rip=192.0.2.1\nOct {day:2d} 12:00:06 mail dovecot: pop3-login: Login: user=<u@example.test>, rip=192.0.2.2\n')
                inputs.append(path)
            result=triage.run(list(reversed(inputs)),root/'out',2026,'Europe/Vilnius',multi_ip_window=6)
            self.assertEqual(result['coverage']['review_candidate_correlations'],1)
            self.assertEqual(result['multi_ip_correlation']['window_seconds'],6)
            self.assertEqual(result['engine']['name'],'Artefact Finder')
            self.assertEqual(result['engine']['url'],'https://github.com/mariovilnius/artefact-finder')
            self.assertEqual(result['engine']['version'],triage.VERSION)
            self.assertIsNotNone(datetime.fromisoformat(result['generated_at_utc']).utcoffset())
            self.assertTrue(result['generated_at_local'].endswith(('+02:00','+03:00')))
            findings=[json.loads(s) for s in (root/'out/findings.jsonl').read_text().splitlines()]
            self.assertEqual(findings[0]['finding_type'],'correlation')
            self.assertEqual(findings[0]['pair_days'],2)
            triage.run(inputs,root/'default',2026,'Europe/Vilnius')
            self.assertEqual((root/'default/multi-ip-summary.jsonl').read_text(),'')

    def test_window_validation_and_yaml_thresholds(self):
        with self.assertRaises(ValueError):
            triage.MultiIPDetector(':memory:',-1)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            rule=next(r for r in triage.load_rules() if 'correlation' in r)
            rule={k:v for k,v in rule.items() if not k.startswith('_')}
            rule['correlation']['window_seconds']=86401
            (root/'bad.yaml').write_text(yaml.safe_dump(rule))
            with self.assertRaises(ValueError):triage.load_rules(root)

    def test_yaml_can_require_cross_day_repetition(self):
        rows=[event(),event(ip='192.0.2.2',number=2),event(second=3,number=3),event(second=3,ip='192.0.2.2',number=4)]
        summary=detect(rows)[0][0]
        self.assertGreaterEqual(summary['pair_occurrences'],2)
        self.assertEqual(summary['pair_days'],1)
        with tempfile.TemporaryDirectory() as temp:
            rule=next(r for r in triage.load_rules() if 'correlation' in r)
            rule={k:v for k,v in rule.items() if not k.startswith('_')}
            for condition in rule['match']:
                if condition['field']=='pair_days':condition['value']=2
            (Path(temp)/'custom.yaml').write_text(yaml.safe_dump(rule))
            self.assertEqual(triage.evaluate_rules(summary,triage.load_rules(temp)),[])

    def test_failures_never_form_success_pairs(self):
        row=event(ip='192.0.2.2',number=2)
        row['event_type']='auth_failure'
        self.assertEqual(detect([event(),row])[0],[])

    def test_invalid_override_fails_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'synthetic.txt';source.write_text('synthetic')
            with self.assertRaises(ValueError):triage.run([source],root/'out',multi_ip_window=-1)
            self.assertFalse((root/'out').exists())


if __name__ == '__main__':
    unittest.main()

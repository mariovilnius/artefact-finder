import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('relations',ROOT/'skills/mail-log-triage/scripts/ip_relations.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class RelationsTests(unittest.TestCase):
    def test_unknown_ownership_and_mapped_ipv6(self):
        a=r.enrichment('::ffff:192.0.2.7',[])
        self.assertEqual(a['ip'],'192.0.2.7');self.assertIsNone(a['operator'])
        self.assertEqual(a['comparison_network'],'192.0.2.0/24')

    def test_longest_prefix_and_separate_networks_same_operator(self):
        records=[dict(network='192.0.0.0/16',operator='broad'),dict(network='192.0.2.0/24',operator='specific')]
        self.assertEqual(r.enrichment('192.0.2.1',records)['operator'],'specific')
        self.assertEqual(r.enrichment('2001:db8::1',[])['comparison_network'],'2001:db8::/64')

    def test_sequence_memberships_and_no_identity_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Path(tmp);db=t/'in.sqlite';c=sqlite3.connect(db)
            c.execute('CREATE TABLE logins(host,account,protocol,ip,second,local,evidence)')
            rows=[('h','a','pop3','192.0.2.1',1),('h','a','pop3','198.51.100.1',2),('h','a','pop3','192.0.2.1',3),('h','a','imap','198.51.100.1',4),('h','b','pop3','192.0.2.1',5),('h','a','pop3','203.0.113.1',999)]
            for h,a,p,ip,s in rows:c.execute('INSERT INTO logins VALUES(?,?,?,?,?,?,?)',(h,a,p,ip,s,'2026-01-01T00:00:00+00:00',json.dumps(dict(file='synthetic',line=s))))
            c.commit();c.close()
            owners=t/'owners.json';owners.write_text(json.dumps([dict(network='192.0.2.0/24',operator='Example'),dict(network='198.51.100.0/24',operator='Example')]))
            m=r.run(db,t/'out',ROOT/'skills/mail-log-triage/relation-rules/ip-associations.yaml',owners)
            self.assertEqual(m['counts']['sequence_occurrences'],2)
            self.assertEqual(m['counts']['shared_ips'],1)
            groups=json.loads((t/'out/association-groups.json').read_text())
            self.assertEqual(len(groups),1);self.assertFalse(groups[0]['historical_ownership_confirmed'])
            self.assertIn('not_identity',groups[0]['status'])

if __name__=='__main__':unittest.main()

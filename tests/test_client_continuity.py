import importlib.util,json,sqlite3,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('continuity',ROOT/'skills/mail-log-triage/scripts/client_continuity.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RULES=ROOT/'skills/mail-log-triage/relation-rules/client-continuity.yaml'

class ContinuityTests(unittest.TestCase):
 def db(self,t):
  path=t/'case.sqlite';db=sqlite3.connect(path);db.execute('CREATE TABLE events(account,host,protocol,kind,ip,second,time,file,line,raw)');return path,db
 def add(self,db,account,ip,second,line,kind='auth_success'):
  db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',(account,'mail','pop3',kind,ip,second,datetime.fromtimestamp(second or 0,timezone.utc).isoformat(),'synthetic.txt',line,'synthetic evidence'))
 def fixture(self,db,after=True):
  for n,(account,ip,second) in enumerate([('a@example.test','192.0.2.1',0),('b@example.test','192.0.2.1',1),('a@example.test','198.51.100.1',100),('b@example.test','198.51.100.1',101)]+([('a@example.test','192.0.2.1',200),('b@example.test','192.0.2.1',201)] if after else [])):self.add(db,account,ip,second,n)
 def test_handover_is_only_compatibility_and_keeps_exact_refs(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);path,db=self.db(t);self.fixture(db);db.commit();db.close();m.run(path,t/'out',RULES,reference_ip='192.0.2.1')
   rows=json.loads((t/'out/handover-evidence.json').read_text());self.assertEqual(len(rows),2)
   self.assertTrue(all(x['status']=='compatible_with_handover_unconfirmed' for x in rows))
   self.assertEqual(rows[0]['candidate_first']['line'],2);self.assertEqual(rows[0]['identity_attribution'],'person_and_device_unknown')
 def test_overlap_does_not_assert_different_person(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);path,db=self.db(t);self.fixture(db);self.add(db,'a@example.test','192.0.2.1',120,8);self.add(db,'a@example.test','198.51.100.1',150,9);db.commit();db.close();m.run(path,t/'out',RULES,reference_ip='192.0.2.1',accounts=['a@example.test'])
   rows=json.loads((t/'out/handover-evidence.json').read_text());self.assertEqual(len(rows),1);self.assertEqual(rows[0]['status'],'overlapping_endpoint_activity');self.assertEqual(rows[0]['reference_raw_logins_during'],1);self.assertEqual(rows[0]['identity_attribution'],'person_and_device_unknown')
 def test_missing_history_remains_unknown(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);path,db=self.db(t);self.fixture(db,False);db.commit();db.close();m.run(path,t/'out',RULES,reference_ip='192.0.2.1')
   rows=json.loads((t/'out/handover-evidence.json').read_text());self.assertTrue(all(x['status']=='insufficient_history' for x in rows))
 def test_empty_data_is_not_a_detected_client(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);path,db=self.db(t);db.commit();db.close();r=m.run(path,t/'out',RULES);self.assertEqual(r['counts']['observed_ips'],0);self.assertIsNone(r['reference_ip'])
 def test_mapped_ip_duplicate_ambiguous_failure_and_proxy_handling(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);path,db=self.db(t)
   for n,(account,ip,second,kind) in enumerate([('a@example.test','192.0.2.1',0,'auth_success'),('a@example.test','::ffff:192.0.2.1',0,'auth_success'),('b@example.test','192.0.2.1',1,'auth_success'),('a@example.test','198.51.100.1',None,'auth_success'),('a@example.test','203.0.113.1',2,'auth_failure'),('b@example.test','198.51.100.1',3,'auth_success')]):self.add(db,account,ip,second,n,kind)
   db.commit();db.close();r=m.run(path,t/'out',RULES,exclude_ips=['198.51.100.1']);self.assertEqual(r['counts']['observed_ips'],1);self.assertEqual(r['counts']['same_second_endpoint_duplicates_ignored'],1);self.assertEqual(r['counts']['nonunique_auth_success_rows_excluded'],1)
 def test_long_gap_not_called_simple_handover(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);path,db=self.db(t);self.fixture(db,False)
   self.add(db,'a@example.test','192.0.2.1',3000000,8);self.add(db,'b@example.test','192.0.2.1',3000001,9);db.commit();db.close();m.run(path,t/'out',RULES,reference_ip='192.0.2.1');rows=json.loads((t/'out/handover-evidence.json').read_text());self.assertTrue(all(x['status']=='observation_gap_too_long' for x in rows));self.assertTrue(all(not x['intermediate_endpoint_intervals'] for x in rows))

if __name__=='__main__':unittest.main()

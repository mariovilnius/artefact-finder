import importlib.util,json,sqlite3,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cross',ROOT/'skills/mail-log-triage/scripts/cross_mailbox.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RULES=ROOT/'skills/mail-log-triage/relation-rules/cross-mailbox.yaml'

class CrossMailboxTests(unittest.TestCase):
 def database(self,t):
  p=t/'test.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE events('+m.SCHEMA+')')
  return p,db
 def add(self,db,account,kind,ip,second,line,host='h',protocol='pop3',retr=0,bytes=0):
  db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(account,host,protocol,kind,ip,second,'2026-01-01T00:00:00+00:00','synthetic.txt',line,'synthetic evidence',None,retr,bytes,0))
 def test_shared_endpoint_sequence_and_unknown_action_source(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);p,db=self.database(t)
   self.add(db,'a@example.test','auth_failure','192.0.2.1',0,1)
   self.add(db,'a@example.test','auth_success','192.0.2.1',4,2)
   self.add(db,'a@example.test','logout',None,5,3,retr=10,bytes=60000000)
   self.add(db,'a@example.test','mail_expunge',None,6,4)
   self.add(db,'b@example.test','auth_success','192.0.2.1',4,5)
   self.add(db,'b@example.test','mail_expunge',None,5,6)
   db.commit();db.close();result=m.run(p,t/'out',RULES)
   self.assertEqual(result['counts']['shared_success_ips'],1)
   chains=json.loads((t/'out/failure-success-actions.json').read_text())
   self.assertEqual(len(chains),1);self.assertEqual(len(chains[0]['following_actions']),2)
   self.assertTrue(all(x['ip'] is None for x in chains[0]['following_actions']))
   transfers=json.loads((t/'out/large-transfers-context.json').read_text())
   self.assertEqual(transfers[0]['attribution'],'transfer_source_IP_unknown')
   self.assertEqual(len(transfers[0]['login_candidates']),1)
 def test_host_protocol_ambiguity_and_window_boundaries(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);p,db=self.database(t)
   self.add(db,'a@example.test','auth_failure','192.0.2.1',0,1)
   self.add(db,'a@example.test','auth_success','192.0.2.1',1,2,host='other')
   self.add(db,'a@example.test','auth_success','192.0.2.1',2,3,protocol='imap')
   self.add(db,'a@example.test','auth_success','192.0.2.1',1801,4)
   self.add(db,'a@example.test','auth_failure','192.0.2.1',None,5)
   db.commit();db.close();result=m.run(p,t/'out',RULES)
   self.assertEqual(result['counts']['failure_success_sequences'],0)
   self.assertEqual(result['counts']['nonunique_auth_time_rows'],1)
 def test_events_index_preserves_evidence_and_ambiguous_time(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);events=t/'events.jsonl'
   e=dict(account='u@example.test',host='h',protocol='pop3',event_type='logout',source_ip=None,utc_candidates=[],local_candidates=['2026-10-25T03:10:00+03:00','2026-10-25T03:10:00+02:00'],file='synthetic.txt',line=1,raw='retr=2/50000001, del=0/2')
   events.write_text(json.dumps(e)+'\n');digest=m.index_events(events,t/'index.sqlite')
   self.assertEqual(len(digest),64)
   db=sqlite3.connect(t/'index.sqlite');row=db.execute('SELECT second,retr_commands,retr_bytes FROM events').fetchone();db.close()
   self.assertEqual(row,(None,2,50000001))
 def test_proxy_flag_keeps_auth_and_actions(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);p,db=self.database(t)
   for n,a in enumerate(['a@example.test','b@example.test']):self.add(db,a,'auth_success','192.0.2.1',1,n)
   db.commit();db.close();parent=t/'manifest.json';parent.write_text(json.dumps(dict(multi_ip_correlation=dict(excluded_ips=['192.0.2.1']))))
   m.run(p,t/'out',RULES,parent)
   group=json.loads((t/'out/shared-ips.json').read_text())[0]
   self.assertTrue(group['known_provider_proxy']);self.assertEqual(len(group['success_accounts']),2)
 def test_bulk_keys_do_not_count_duplicate_actions(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);p,db=self.database(t)
   for n in range(21):
    self.add(db,'a@example.test','mail_expunge',None,n,n)
    db.execute('UPDATE events SET raw=? WHERE line=?',('expunge: box=INBOX, uid=1, msgid=<one@example.test>',n))
   db.commit();db.close();result=m.run(p,t/'out',RULES)
   self.assertEqual(result['counts']['bulk_action_groups'],0)
 def test_security_message_following_stays_account_scoped(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);p,db=self.database(t)
   for n,(a,raw) in enumerate([('a@example.test','copy: box=Trash, uid=1, msgid=<one@example.test>, subject=PIN'),('a@example.test','expunge: box=INBOX, uid=2, msgid=<one@example.test>'),('b@example.test','expunge: box=INBOX, uid=3, msgid=<one@example.test>')]):
    self.add(db,a,'mail_expunge',None,n,n);db.execute('UPDATE events SET raw=? WHERE line=?',(raw,n))
   db.commit();db.close();result=m.run(p,t/'out',RULES)
   self.assertEqual(result['counts']['security_message_groups'],1)
   self.assertEqual(result['counts']['security_message_action_rows'],2)
 def test_empty_message_id_does_not_join_unrelated_actions(self):
  with tempfile.TemporaryDirectory() as tmp:
   t=Path(tmp);p,db=self.database(t)
   for n,subject in enumerate(['PIN','ordinary message']):
    self.add(db,'a@example.test','mail_expunge',None,n,n)
    db.execute('UPDATE events SET raw=? WHERE line=?',('expunge: box=INBOX, uid='+str(n)+', msgid=<>, subject='+subject,n))
   db.commit();db.close();result=m.run(p,t/'out',RULES)
   self.assertEqual(result['counts']['security_message_action_rows'],1)

if __name__=='__main__':unittest.main()

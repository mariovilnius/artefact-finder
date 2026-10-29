import importlib.util,json,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('renderer',ROOT/'skills/mail-log-triage/scripts/render_cross_mailbox.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class RenderTests(unittest.TestCase):
 def test_empty_case_and_injection_safe_metadata(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)
   manifest=dict(engine=dict(name='<script>alert(1)</script>',url='https://example.test',version='synthetic'),rules=dict(action_after_success_seconds=12,large_retr_bytes=123,failure_success_seconds=90,transfer_login_before_seconds=45,transfer_login_after_seconds=6,bulk_min_message_keys=2,bulk_gap_seconds=1),counts={},source_timezone='UTC')
   (p/'manifest.json').write_text(json.dumps(manifest))
   for name in ['shared-ips.json','failure-success-actions.json','large-transfers-context.json','bulk-actions-context.json']:(p/name).write_text('[]')
   result=r.render(p);doc=result.read_text(encoding='utf-8')
   self.assertNotIn('<script>',doc);self.assertIn('&lt;script&gt;',doc)
   self.assertTrue((p/'report-metadata.json').exists())

if __name__=='__main__':unittest.main()

import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import threat_hunter as t

class Rules(unittest.TestCase):
    def test_normal_process(self):
        self.assertEqual(t.process_findings([{'pid':1,'exe':'/usr/bin/python3'}]), [])
    def test_temp_deleted(self):
        self.assertEqual({f['rule'] for f in t.process_findings([{'pid':2,'exe':'/dev/shm/demo (deleted)'}])}, {'PROC_TEMP','PROC_DELETED'})
    def test_wildcard_not_loopback(self):
        rows=t.parse_listeners('tcp LISTEN 0 128 [::]:22 [::]:*\ntcp LISTEN 0 1 127.0.0.1:80 *:*\nudp UNCONN 0 0 0.0.0.0:53 *:*')
        self.assertEqual(len(t.listener_findings(rows)),2)
    def test_ssh_source_threshold(self):
        prefix='Jan 1 demo sshd[42]: Failed password for invalid user x from '
        text='\n'.join([prefix+'2001:db8::1 port 5 ssh2']*5+[prefix+'bad-ip port 5 ssh2','web: Failed password for x from 192.0.2.1 port 5'])
        summary, findings=t.ssh_summary(text,5)
        self.assertEqual(summary['failed_password_messages'],5)
        self.assertEqual(findings[0]['subject'],'2001:db8::1')
        self.assertEqual(t.ssh_summary(text,6)[1],[])
    def test_comments_and_secrets(self):
        self.assertEqual(t.inspect_config('cron','# /tmp/demo'),[])
        found=t.inspect_config('unit','ExecStart=/tmp/demo --secret=abc')
        self.assertEqual(len(found),1)
        self.assertNotIn('abc',json.dumps(found))
    def test_missing_ss(self):
        with patch('threat_hunter.shutil.which',return_value=None):
            self.assertEqual(t.collect_listeners()[1]['status'],'unavailable')
    def test_missing_log(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(t.collect_ssh(str(Path(directory)/'missing'),5)[2]['status'],'unavailable')
    def test_html_escaping(self):
        report=t.demo(); report['generated_at']='demo'
        report['findings'][0]['subject']='<script>alert(1)</script>'
        body=t.render_html(report)
        self.assertNotIn('<script>',body)
        self.assertIn('&lt;script&gt;',body)
    def test_demo_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'reports'
            self.assertEqual(t.main(['--demo','--output',str(output)]),0)
            report=json.loads((output/'report.json').read_text())
            self.assertEqual(report['mode'],'synthetic-demo')
            self.assertEqual(len(report['findings']),5)
            with self.assertRaises(SystemExit):
                t.main(['--demo','--output',str(output)])

if __name__=='__main__':
    unittest.main()

"""Only a private printf/sleep function runs; never real conntrack or ss."""
import json,os,re,subprocess,tempfile,time,unittest
from pathlib import Path
from fixture_process_guard import run_fixture
SOURCE=Path(__file__).resolve().parents[1]/'scripts/csf_ban_wp_login_attackers'
class CleanupTests(unittest.TestCase):
 def setUp(self):
  self.root=Path(tempfile.mkdtemp(prefix='cleanup-fixture-',dir=os.environ['TMPDIR']));self.bin=self.root/'bin';self.bin.mkdir(mode=0o700)
  self.function=re.search(r'^blacklist_cleanup_ip\(\) \{.*?^\}',SOURCE.read_text(),re.S|re.M).group(0)
  shim=self.bin/'timeout';shim.write_text('''#!/usr/bin/python3.12
import json,os,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
(root/'argv.json').write_text(json.dumps(sys.argv[1:]))
if sys.argv[1:4]!=['-s','KILL','2']:sys.exit(89)
os.execv('/usr/bin/timeout',['timeout',*sys.argv[1:]])
''');shim.chmod(0o700)
 def run_body(self,body):
  return run_fixture(['bash','-c',self.function+'\nterminate_live_sessions_for_ip() { '+body+'; }\nblacklist_cleanup_ip 203.0.113.1'],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':str(self.bin)+':/usr/bin:/bin','LANG':'C','TMPDIR':str(self.root),'SECRET_TEST_SENTINEL':'must-not-inherit'},timeout=6)
 def test_legacy_flags_and_no_inherited_environment(self):
  r=self.run_body('[[ -z "${SECRET_TEST_SENTINEL:-}" ]] || return 77; printf "%s\\n" "$1"');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout,'203.0.113.1\n');self.assertEqual(json.loads((self.root/'argv.json').read_text())[:3],['-s','KILL','2'])
 def test_actual_kill_timeout_is_bounded_and_status_preserved(self):
  start=time.monotonic();r=self.run_body('sleep 20; :');self.assertEqual(r.returncode,137,r.stderr);self.assertLess(time.monotonic()-start,4)
if __name__=='__main__':unittest.main(verbosity=2)

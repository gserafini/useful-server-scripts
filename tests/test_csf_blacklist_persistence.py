"""Extract only blacklist functions; all firewall/session/policy calls are fakes."""
import unittest,subprocess,tempfile,os,re,json
from pathlib import Path
SCRIPT=Path(os.environ.get('SCRIPT',Path(__file__).resolve().parents[1]/'scripts/csf_ban_wp_login_attackers'))
class BatchTests(unittest.TestCase):
 def run_case(self,inputs,tracker='',fail_ip='',bad_tracker=False,single=False,initial_live=''):
  root=Path(os.environ['TMPDIR']);d=Path(tempfile.mkdtemp(prefix='batch-fixture-',dir=root));src=SCRIPT.read_text();functions=[]
  for name in ['validate_ip','perform_blacklist','perform_blacklist_file','report_ban_counts']:
   match=re.search(r'^'+name+r'\(\) \{.*?^\}',src,re.S|re.M);self.assertIsNotNone(match,name);functions.append(match.group(0))
  (d/'input').write_text(inputs);(d/'tracker').write_text(tracker);(d/'allow').write_text('');(d/'deny').write_text('');(d/'live').write_text(initial_live);(d/'events').write_text('')
  if bad_tracker:(d/'tracker').unlink();(d/'tracker').mkdir()
  bash='\n'.join(functions)+r"""
IP_SET_NAME=high_volume_bans
IP_TRACKING_FILE="$FIXTURE/tracker"
CSF_ALLOW_FILE="$FIXTURE/allow"
CSF_DENY_FILE="$FIXTURE/deny"
MAX_BANS=250000
MAX_PERMANENT_BANS=5000
START_TIME=$(date +%s)
event() { printf '%s\n' "$*" >> "$FIXTURE/events"; }
ensure_setup() { event setup; }
ensure_live_ipset_capacity() { event capacity; }
build_protected_ipv4_file() { event policy; printf '%s\n' 203.0.113.13 > "$1"; }
ipv4_matches_policy_file() { [ "$1" = 203.0.113.13 ]; }
terminate_live_sessions_for_ip() { event "teardown $1"; }
count_active_csf_deny_entries() { printf '%s\n' 0; }
geoiplookup() { printf '%s\n' 'GeoIP Country Edition: ZZ, Fixture'; }
mktemp() { local template="${@: -1}"; template="${template##*/}"; [ "$template" != '-d' ] || template='fixture.XXXXXX'; /usr/bin/mktemp "$FIXTURE/$template"; }
ipset() {
 event "ipset $*"
 case "$1" in
 test) /usr/bin/grep -Fxq "$3" "$FIXTURE/live";;
 add) [ "$3" != "$FAIL_IP" ] || return 1; /usr/bin/grep -Fxq "$3" "$FIXTURE/live" || printf '%s\n' "$3" >> "$FIXTURE/live";;
 list) printf '%s\n' 'Members:'; cat "$FIXTURE/live";;
 restore) while read -r command set ip flag; do [ "$command" = add ] || return 1; [ "$ip" != "$FAIL_IP" ] || return 1; /usr/bin/grep -Fxq "$ip" "$FIXTURE/live" || printf '%s\n' "$ip" >> "$FIXTURE/live"; done;;
 *) printf 'UNEXPECTED IPSET CALL\n' >&2; return 98;;
 esac
}
perform_blacklist_file "$FIXTURE/input" 'fixture reason'
"""
  if single:bash=bash.replace("perform_blacklist_file \"$FIXTURE/input\" 'fixture reason'", "perform_blacklist 203.0.113.1 'fixture reason'")
  script=d/'case.sh';script.write_text(bash);syntax=subprocess.run(['bash','-n',str(script)],capture_output=True,text=True);self.assertEqual(syntax.returncode,0,syntax.stderr)
  result=subprocess.run(['strace','-f','-e','trace=openat','-o',str(d/'opens'),'bash',str(script)],capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':str(d),'FIXTURE':str(d),'FAIL_IP':fail_ip},timeout=15)
  events=(d/'events').read_text().splitlines();live=(d/'live').read_text().splitlines();tracked=(d/'tracker').read_text() if not bad_tracker else ''
  reads=sum('"'+str(d/'tracker')+'"' in line and 'O_RDONLY' in line for line in (d/'opens').read_text().splitlines())
  (d/'receipt.json').write_text(json.dumps({'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'events':events,'trackerReads':reads,'live':live,'tracked':tracked},indent=2))
  return result,events,reads,live,tracked
 def test_partial_live_failure_persists_verified_successes_only(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n203.0.113.2\n203.0.113.3\n',fail_ip='203.0.113.2');self.assertNotEqual(r.returncode,0);self.assertEqual(set(l),{'203.0.113.1','203.0.113.3'});self.assertIn('203.0.113.1',t);self.assertNotIn('203.0.113.2',t);self.assertIn('203.0.113.3',t)
 def test_single_new_ban_reports_tracking_failure_without_removing_live_coverage(self):
  r,e,n,l,t=self.run_case('',bad_tracker=True,single=True);self.assertNotEqual(r.returncode,0,'new live ban must not falsely report persistence success');self.assertEqual(l,['203.0.113.1']);self.assertIn('tracking',r.stdout+r.stderr)
 def test_single_new_ban_preserves_message_and_persistence(self):
  r,e,n,l,t=self.run_case('',single=True);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(l,['203.0.113.1']);self.assertEqual(t.count('203.0.113.1'),1);self.assertIn('fixture reason',t)
 def test_single_already_live_repairs_tracking(self):
  r,e,n,l,t=self.run_case('',single=True,initial_live='203.0.113.1\n');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(l,['203.0.113.1']);self.assertEqual(t.count('203.0.113.1'),1);self.assertIn('fixture reason',t)
 def test_single_existing_tracking_reason_preserved(self):
  original='203.0.113.1 # original reason do not delete\n'
  r,e,n,l,t=self.run_case('',tracker=original,single=True,initial_live='203.0.113.1\n');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(t,original)
if __name__=='__main__':unittest.main(verbosity=2)

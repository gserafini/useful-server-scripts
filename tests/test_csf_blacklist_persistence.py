"""Extract only blacklist functions; all firewall/session/policy calls are fakes."""
import unittest,subprocess,tempfile,os,re,json
from pathlib import Path
from fixture_process_guard import run_fixture
SCRIPT=Path(os.environ.get('SCRIPT',Path(__file__).resolve().parents[1]/'scripts/csf_ban_wp_login_attackers'))
class BatchTests(unittest.TestCase):
 def run_case(self,inputs,tracker='',fail_ip='',bad_tracker=False,single=False,initial_live='',publish_fail=False,cleanup_advance=0,cleanup_exit=0):
  root=Path(os.environ['TMPDIR']);d=Path(tempfile.mkdtemp(prefix='batch-fixture-',dir=root));src=SCRIPT.read_text();functions=[]
  for name in ['validate_ip','tracking_lock','tracking_snapshot','tracking_publish','tracking_discard','tracking_record_failure','filter_ipv4_records_against_policy','blacklist_preflight','blacklist_report_inputs','blacklist_cleanup_ip','execute_blacklist_batch','perform_blacklist','perform_blacklist_file','report_ban_counts']:
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
blacklist_cleanup_ip() { event "bounded-teardown $1"; SECONDS=$((SECONDS + CLEANUP_ADVANCE)); return "$CLEANUP_EXIT"; }
count_active_csf_deny_entries() { printf '%s\n' 0; }
geoiplookup() { printf '%s\n' 'GeoIP Country Edition: ZZ, Fixture'; }
mktemp() {
 local template="${@: -1}"; local flags=()
 [ "$1" != -d ] || flags=(-d)
 case "$template" in /tmp/high_volume*) template="$FIXTURE/${template##*/}";; esac
 case "$template" in "$FIXTURE"/*) /usr/bin/mktemp "${flags[@]}" "$template";; *) return 98;; esac
}
mv() { [ "$PUBLISH_FAIL" != yes ] || [ "${@: -1}" != "$IP_TRACKING_FILE" ] || return 9; /usr/bin/mv "$@"; }
ipset() {
 event "ipset $*"
 case "$1" in
 test) /usr/bin/grep -Fxq "$3" "$FIXTURE/live";;
 add) [ "$3" != "$FAIL_IP" ] || return 1; /usr/bin/grep -Fxq "$3" "$FIXTURE/live" || printf '%s\n' "$3" >> "$FIXTURE/live";;
 list) printf '%s\n' 'Members:'; cat "$FIXTURE/live";;
 save) printf '%s\n' 'create high_volume_bans hash:ip'; while read -r ip; do printf 'add high_volume_bans %s\n' "$ip"; done < "$FIXTURE/live";;
 restore) while read -r command set ip flag; do [ "$command" = add ] || return 1; [ "$ip" != "$FAIL_IP" ] || return 1; /usr/bin/grep -Fxq "$ip" "$FIXTURE/live" || printf '%s\n' "$ip" >> "$FIXTURE/live"; done;;
 *) printf 'UNEXPECTED IPSET CALL\n' >&2; return 98;;
 esac
}
perform_blacklist_file "$FIXTURE/input" 'fixture reason'
"""
  if single:bash=bash.replace("perform_blacklist_file \"$FIXTURE/input\" 'fixture reason'", "perform_blacklist 203.0.113.1 'fixture reason'")
  script=d/'case.sh';script.write_text(bash);syntax=run_fixture(['bash','-n',str(script)],timeout=5,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);self.assertEqual(syntax.returncode,0,syntax.stderr)
  result=run_fixture(['strace','-f','-e','trace=openat','-o',str(d/'opens'),'bash',str(script)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':str(d),'FIXTURE':str(d),'FAIL_IP':fail_ip,'PUBLISH_FAIL':'yes' if publish_fail else 'no','CLEANUP_ADVANCE':str(cleanup_advance),'CLEANUP_EXIT':str(cleanup_exit)},timeout=15)
  events=(d/'events').read_text().splitlines();live=(d/'live').read_text().splitlines();tracked=(d/'tracker').read_text() if not bad_tracker else ''
  reads=sum('"'+str(d/'tracker')+'"' in line and 'O_RDONLY' in line for line in (d/'opens').read_text().splitlines())
  (d/'receipt.json').write_text(json.dumps({'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'events':events,'trackerReads':reads,'live':live,'tracked':tracked},indent=2))
  return result,events,reads,live,tracked
 def test_partial_live_failure_persists_verified_successes_only(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n203.0.113.2\n203.0.113.3\n',fail_ip='203.0.113.2');self.assertNotEqual(r.returncode,0);self.assertTrue(set(l)<= {'203.0.113.1','203.0.113.3'});self.assertIn('203.0.113.1',l);self.assertIn('203.0.113.1',t);self.assertNotIn('203.0.113.2',t);self.assertEqual('203.0.113.3' in l,'203.0.113.3' in t)
 def test_single_new_ban_reports_tracking_failure_without_removing_live_coverage(self):
  r,e,n,l,t=self.run_case('',bad_tracker=True,single=True);self.assertNotEqual(r.returncode,0,'new live ban must not falsely report persistence success');self.assertEqual(l,[]);self.assertIn('Tracker',r.stdout+r.stderr)
 def test_single_publish_failure_retains_live_and_exact_original_tracker(self):
  original='203.0.113.9 # retained original\n'
  r,e,n,l,t=self.run_case('',tracker=original,single=True,publish_fail=True);self.assertNotEqual(r.returncode,0);self.assertEqual(l,['203.0.113.1']);self.assertEqual(t,original);self.assertIn('failure.tsv',r.stderr)
 def test_single_new_ban_preserves_message_and_persistence(self):
  r,e,n,l,t=self.run_case('',single=True);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(l,['203.0.113.1']);self.assertEqual(t.count('203.0.113.1'),1);self.assertIn('fixture reason',t)
 def test_single_already_live_repairs_tracking(self):
  r,e,n,l,t=self.run_case('',single=True,initial_live='203.0.113.1\n');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(l,['203.0.113.1']);self.assertEqual(t.count('203.0.113.1'),1);self.assertIn('fixture reason',t)
 def test_single_existing_tracking_reason_preserved(self):
  original='203.0.113.1 # original reason do not delete\n'
  r,e,n,l,t=self.run_case('',tracker=original,single=True,initial_live='203.0.113.1\n');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(t,original)
if __name__=='__main__':unittest.main(verbosity=2)

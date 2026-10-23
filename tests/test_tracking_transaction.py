"""Tracker I/O only: real process/lock/filesystem fixtures, no firewall code."""
import hashlib, os, re, subprocess, tempfile, unittest
from pathlib import Path
from fixture_process_guard import capture_fixture,run_fixture,spawn_fixture
SCRIPT=Path(__file__).resolve().parents[1]/'scripts/csf_ban_wp_login_attackers'
class TransactionTests(unittest.TestCase):
 def setUp(self):
  self.root=Path(tempfile.mkdtemp(prefix='tracker-txn-',dir=os.environ['TMPDIR']));self.tracker=self.root/'tracker';self.tracker.write_text('203.0.113.9 # retain\n');self.tracker.chmod(0o600)
  source=SCRIPT.read_text();pieces=[]
  for name in ['tracking_lock','tracking_snapshot','tracking_publish','tracking_discard']:
   match=re.search(r'^'+name+r'\(\) \{.*?^\}',source,re.S|re.M)
   self.assertIsNotNone(match,'missing shared tracker I/O primitive '+name)
   pieces.append(match.group(0))
  self.lib=self.root/'functions.sh';self.lib.write_text('\n'.join(pieces)+'\n');self.env={'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':str(self.root),'IP_TRACKING_FILE':str(self.tracker)}
 def run_shell(self,body):return run_fixture(['bash','-c','source "$1"; '+body,'fixture',str(self.lib)],env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 def snapshot(self):
  r=self.run_shell('tracking_snapshot');self.assertEqual(r.returncode,0,r.stderr);return Path(r.stdout.strip())
 def publish(self,ctx,extra=''):return self.run_shell(extra+' tracking_publish "'+str(ctx)+'"')
 def test_snapshot_preserves_source_and_releases_mutex(self):
  original=self.tracker.read_bytes();ctx=self.snapshot();self.assertEqual((ctx/'source').read_bytes(),original);self.assertEqual(self.tracker.read_bytes(),original);self.assertEqual(ctx.stat().st_mode&0o777,0o700)
  r=run_fixture(['flock','-w','1',str(self.tracker)+'.lock','true'],timeout=3,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.assertEqual(r.returncode,0)
 def test_publish_preserves_owner_group_mode(self):
  self.tracker.chmod(0o640);before=self.tracker.stat();ctx=self.snapshot();(ctx/'next').write_text('203.0.113.9 # retain\n203.0.113.10 # added\n');r=self.publish(ctx);self.assertEqual(r.returncode,0,r.stderr);after=self.tracker.stat();self.assertEqual((before.st_uid,before.st_gid,before.st_mode&0o777),(after.st_uid,after.st_gid,after.st_mode&0o777));self.assertIn('203.0.113.10',self.tracker.read_text())
 def test_external_append_stops_stale_publish_and_preserves_new_data(self):
  ctx=self.snapshot();(ctx/'next').write_text('stale replacement\n');self.tracker.write_text(self.tracker.read_text()+'203.0.113.11 # concurrent\n');r=self.publish(ctx);self.assertNotEqual(r.returncode,0);self.assertIn('beforeimage',r.stderr);self.assertIn('concurrent',self.tracker.read_text());self.assertTrue(ctx.exists())
 def test_inode_replacement_same_bytes_stops_publish(self):
  ctx=self.snapshot();(ctx/'next').write_text('stale replacement\n');new=self.root/'replacement';new.write_bytes(self.tracker.read_bytes());new.chmod(0o600);new.replace(self.tracker);r=self.publish(ctx);self.assertNotEqual(r.returncode,0);self.assertIn('retain',self.tracker.read_text())
 def test_symlink_and_multilink_targets_refused(self):
  real=self.root/'real';self.tracker.rename(real);self.tracker.symlink_to(real);r=self.run_shell('tracking_snapshot');self.assertNotEqual(r.returncode,0);self.tracker.unlink();os.link(real,self.tracker);r=self.run_shell('tracking_snapshot');self.assertNotEqual(r.returncode,0)
 def test_foreign_owner_refused(self):
  os.chown(self.tracker,65534,65534);r=self.run_shell('tracking_snapshot');self.assertNotEqual(r.returncode,0);self.assertIn('owner',r.stderr)
 def test_failed_atomic_publish_leaves_original_and_evidence(self):
  before=self.tracker.read_bytes();ctx=self.snapshot();(ctx/'next').write_text('new\n');r=self.publish(ctx,'mv() { return 9; };');self.assertNotEqual(r.returncode,0);self.assertEqual(self.tracker.read_bytes(),before);self.assertTrue((ctx/'next').exists())
 def test_symlink_candidate_refused(self):
  ctx=self.snapshot();(ctx/'next').symlink_to(self.tracker);r=self.publish(ctx);self.assertNotEqual(r.returncode,0);self.assertIn('retain',self.tracker.read_text())
 def test_modified_snapshot_refused(self):
  ctx=self.snapshot();(ctx/'source').write_text('changed source\n');(ctx/'next').write_text('new\n');r=self.publish(ctx);self.assertNotEqual(r.returncode,0);self.assertIn('retain',self.tracker.read_text())
 def test_hash_guard_independent_of_stat(self):
  ctx=self.snapshot();(ctx/'next').write_text('new\n');old=self.tracker.read_text();self.tracker.write_text(old.replace('retain','RETAIN'));r=self.publish(ctx,'stat() { if [ "${@: -1}" = "$IP_TRACKING_FILE" ]; then cat "'+str(ctx)+'/metadata"; else command stat "$@"; fi; };');self.assertNotEqual(r.returncode,0);self.assertIn('RETAIN',self.tracker.read_text())
 def test_snapshot_mode_tamper_refused(self):
  ctx=self.snapshot();(ctx/'source').chmod(0o666);(ctx/'next').write_text('new\n');r=self.publish(ctx);self.assertNotEqual(r.returncode,0);self.assertEqual(self.tracker.stat().st_mode&0o777,0o600)
 def cleanup_worker(self,proc):
  if not getattr(proc,'_fixture_finished',False):self.capture_worker(proc,0,force_stop='private worker teardown')
 def capture_worker(self,proc,timeout,force_stop=None):
  result=capture_fixture(proc,timeout,force_stop=force_stop);proc._fixture_finished=True
  import json
  (self.root/('worker-'+str(proc.pid)+'.json')).write_text(json.dumps(result,indent=2))
  if result['error'] and force_stop is None:self.fail('private worker capture failed: '+repr(result))
  self.assertTrue(result['cleanup']['directChildReaped'],'private direct child not reaped; retained receipt')
  self.assertFalse(result['cleanup']['pipeWritersUnknown'],'unknown pipe writers; inspect retained receipt')
  self.assertEqual(result['cleanup']['errors'],[],'guarded worker cleanup errors; inspect receipt')
  return result['stdout'],result['stderr']
 def test_two_process_stale_writer_cannot_overwrite_winner(self):
  worker='source "$1"; ctx=$(tracking_snapshot) || exit; printf "%s\\n" "$ctx" > "$2"; while [ ! -e "$3" ]; do sleep 0.02; done; cp "$ctx/source" "$ctx/next"; printf "%s\\n" "$4" >> "$ctx/next"; tracking_publish "$ctx"'
  processes=[]
  for n in [1,2]:
   processes.append(spawn_fixture(['bash','-c',worker,'fixture',str(self.lib),str(self.root/('ready'+str(n))),str(self.root/('go'+str(n))),'203.0.113.'+str(n)+' # writer'+str(n)],env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE))
   self.addCleanup(self.cleanup_worker,processes[-1])
  import time
  deadline=time.monotonic()+5
  while not all((self.root/('ready'+str(n))).exists() for n in [1,2]):
   if time.monotonic()>deadline:
    for proc in processes:self.capture_worker(proc,0,force_stop='private snapshot barrier deadline')
    self.fail('workers did not reach private snapshot barrier')
   time.sleep(0.02)
  (self.root/'go1').touch();out1=self.capture_worker(processes[0],5);self.assertEqual(processes[0].returncode,0,out1[1]);(self.root/'go2').touch();out2=self.capture_worker(processes[1],5);self.assertNotEqual(processes[1].returncode,0);self.assertIn('beforeimage',out2[1]);self.assertIn('writer1',self.tracker.read_text());self.assertNotIn('writer2',self.tracker.read_text())
 def test_published_image_and_hash_retained_until_explicit_discard(self):
  ctx=self.snapshot();after=b'203.0.113.9 # retain\n203.0.113.1 # new\n';(ctx/'next').write_bytes(after);r=self.publish(ctx);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual((ctx/'published').read_bytes(),after);self.assertEqual((ctx/'after.sha').read_text().strip(),hashlib.sha256(after).hexdigest());self.assertRegex((ctx/'commit').read_text(),r'^published [0-9]{4}-')
 def test_cross_device_candidate_refused_before_rename(self):
  ctx=self.snapshot();(ctx/'next').write_text('new\n');before=self.tracker.read_bytes()
  stub='stat() { if [[ "$1" = -c && "$2" = "%d|%i|%h|%u|%g|%a|%s" && "${@: -1}" = "'+str(ctx)+'/next" ]]; then command stat "$@" | sed "s/^[^|]*/999999/"; else command stat "$@"; fi; };'
  r=self.publish(ctx,stub);self.assertNotEqual(r.returncode,0);self.assertIn('filesystem',r.stderr);self.assertEqual(self.tracker.read_bytes(),before)
 def test_failed_lock_and_exception_release_file_descriptor(self):
  r=self.run_shell('flock() { return 1; }; tracking_snapshot');self.assertNotEqual(r.returncode,0)
  r=self.run_shell('tracking_lock || exit; exit 42');self.assertEqual(r.returncode,42);ctx=self.snapshot();self.assertTrue(ctx.exists())
 def test_context_discard_only_removes_own_known_files(self):
  ctx=self.snapshot();(ctx/'next').write_text('new\n');r=self.run_shell('tracking_discard "'+str(ctx)+'"');self.assertEqual(r.returncode,0,r.stderr);self.assertFalse(ctx.exists());self.assertTrue(self.tracker.exists())
if __name__=='__main__':unittest.main(verbosity=2)

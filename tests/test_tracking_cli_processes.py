"""Actual private CLI copies with kernel/config paths exclusively replaced by fakes."""
import hashlib, json, os, re, signal, subprocess, tempfile, time, unittest
from pathlib import Path
from fixture_process_guard import capture_fixture,run_fixture,spawn_fixture
SOURCE=Path(__file__).resolve().parents[1]/'scripts/csf_ban_wp_login_attackers'
class CLIProcesses(unittest.TestCase):
 def setUp(self):
  self.root=Path(tempfile.mkdtemp(prefix='cli-process-fixture-',dir=os.environ['TMPDIR']));self.bin=self.root/'bin';self.bin.mkdir(mode=0o700);(self.root/'tmp').mkdir(mode=0o700);(self.root/'logs').mkdir(mode=0o700)
  self.tracker=self.root/'tracker';self.tracker.write_text('203.0.113.9 # retained\n');self.tracker.chmod(0o600)
  for name,text in [('allow',''),('ignore',''),('deny',''),('csf.conf','DENY_IP_LIMIT = "200"\n'),('csfpost',''),('tempip',''),('lfd.log',''),('live','203.0.113.9\n')]:
   f=self.root/name;f.write_text(text);f.chmod(0o600)
  code=SOURCE.read_text();code=code.replace('/usr/sbin/csf -r','"$CSF_BIN" -r').replace('/tmp/',str(self.root/'tmp')+'/')
  override='\n'.join([f'PATH="{self.bin}:/usr/bin:/bin"',f'IP_TRACKING_FILE="{self.tracker}"',f'CSF_ALLOW_FILE="{self.root}/allow"',f'CSF_IGNORE_FILE="{self.root}/ignore"',f'CSF_DENY_FILE="{self.root}/deny"',f'CSF_CONF_FILE="{self.root}/csf.conf"',f'CSF_TEMPIP_FILE="{self.root}/tempip"',f'CSF_POST_FILE="{self.root}/csfpost"',f'CSF_PROMOTE_LOCK_FILE="{self.root}/promotion.lock"',f'LFD_LOG_FILE="{self.root}/lfd.log"',f'CSF_BIN="{self.bin}/csf"',f'DEFAULT_LOG_PATHS="{self.root}/logs"',f'get_iptables_path() {{ printf "%s\\n" "{self.bin}/iptables"; }}','ensure_setup() { :; }','ensure_live_ipset_capacity() { :; }','repopulate_ipset_from_tracking_file() { :; }',f'''build_protected_ipv4_file() {{ printf '%s\\n' 127.0.0.1 10.20.30.40 > "$1"; awk '$1 ~ /^[0-9]/ {{print $1}}' "{self.root}/allow" >> "$1"; }}'''])+'\n'
  marker='# --- COMMAND LINE ARGUMENT PARSING ---';self.assertEqual(code.count(marker),1);code=code.replace(marker,override+marker);self.cli=self.root/'cli.sh';self.cli.write_text(code);self.cli.chmod(0o700);(self.root/'source-hashes.json').write_text(json.dumps({'reviewedSourceSHA256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'isolatedAdapterSHA256':hashlib.sha256(self.cli.read_bytes()).hexdigest()}))
  (self.root/'fixture_process_guard.py').write_text((SOURCE.parents[1]/'tests/fixture_process_guard.py').read_text())
  fake=r'''#!/usr/bin/python3.12
import fcntl,json,os,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parents[1];name=Path(sys.argv[0]).name;args=sys.argv[1:]
sys.path.insert(0,str(root))
from fixture_process_guard import run_fixture
# Every kernel/reload hook must run with the real tracker mutex released.
lock=root/'tracker.lock'
if lock.exists():
 with lock.open('r+') as f:
  try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:print('FORBIDDEN native call while tracker mutex held',file=sys.stderr);sys.exit(98)
with (root/'calls.jsonl').open('a') as log:log.write(json.dumps({'name':name,'args':args})+'\n')
def wait(command,ip):
 if os.environ.get('WAIT_COMMAND')==command and os.environ.get('WAIT_IP')==ip:
  (root/'ready').write_text('ready');deadline=time.monotonic()+12
  while not (root/'go').exists():
   if time.monotonic()>deadline:sys.exit(97)
   time.sleep(.01)
def perform(command,ip=''):
 wait(command,ip)
 with (root/'kernel.lock').open('a+') as guard:
  fcntl.flock(guard,fcntl.LOCK_EX);live=(root/'live').read_text().splitlines()
  if command=='test':return 0 if ip in live else 1
  if command=='add':
   if ip not in live:live.append(ip)
  elif command=='del':live=[x for x in live if x!=ip]
  elif command=='flush':live=[]
  (root/'live').write_text(''.join(x+'\n' for x in live))
 return 0
if name=='ipset':
 command=args[0]
 if command in ['add','del','test']:sys.exit(perform(command,args[2]))
 if command=='flush':sys.exit(perform(command,''))
 if command=='restore':
  for line in sys.stdin:
   fields=line.split()
   if fields and fields[0]=='add':
    status=perform('add',fields[2])
    if status:sys.exit(status)
  sys.exit(0)
 if command in ['list','save']:
  live=(root/'live').read_text().splitlines()
  if command=='list':print('Name: high_volume_bans\nType: hash:ip\nHeader: family inet hashsize 1024 maxelem 250000\nMembers:');print('\n'.join(live))
  else:print('create high_volume_bans hash:ip');print('\n'.join('add high_volume_bans '+x for x in live))
  sys.exit(0)
 if command in ['create','destroy','swap']:sys.exit(0)
 print('UNSUPPORTED FAKE IPSET',args,file=sys.stderr);sys.exit(96)
if name=='csf':
 sys.exit(run_fixture(['/bin/bash',str(root/'cli.sh'),'--rebuild-live-set'],env={'PATH':str(root/'bin')+':/usr/bin:/bin','LANG':'C','TMPDIR':str(root/'tmp')},timeout=8).returncode)
if name=='geoiplookup':print('GeoIP Country Edition: ZZ, Fixture');sys.exit(0)
if name=='ip':print('2: eth0 inet 10.20.30.40/24 brd 10.20.30.255 scope global eth0');sys.exit(0)
if name in ['conntrack','ss','iptables']:sys.exit(0)
print('FORBIDDEN native service/cleanup call',name,file=sys.stderr);sys.exit(95)
'''
  for name in ['ipset','csf','geoiplookup','ip','conntrack','ss','iptables','systemctl','service','killall','pkill']:
   f=self.bin/name;f.write_text(fake);f.chmod(0o700)
  syntax=run_fixture(['bash','-n',str(self.cli)],timeout=5,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);self.assertEqual(syntax.returncode,0,syntax.stderr)
  self.env={'PATH':str(self.bin)+':/usr/bin:/bin','LANG':'C','TMPDIR':str(self.root/'tmp')}
 def launch(self,args,env=None,tty=False):
  if tty:
   import pty
   master,slave=pty.openpty()
  else:slave=subprocess.PIPE
  trace=self.root/('trace-'+str(time.monotonic_ns())+'.log');trace.touch(mode=0o600)
  proc=spawn_fixture(['strace','-f','-e','trace=file,process','-o',str(trace),'bash',str(self.cli),*args],cwd=self.root,env={**self.env,**(env or {})},stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  proc._fixture_trace=trace
  self.addCleanup(self.cleanup_unfinished,proc)
  if tty:os.close(slave);os.write(master,b'YES\n');proc._fixture_master=master
  return proc
 def cleanup_unfinished(self,proc):
  if getattr(proc,'_fixture_finished',False):return
  result=capture_fixture(proc,0,force_stop='test teardown after an early failure')
  proc._fixture_finished=True
  (self.root/('teardown-'+str(proc.pid)+'.json')).write_text(json.dumps(result,indent=2))
  if hasattr(proc,'_fixture_master'):os.close(proc._fixture_master)
  self.assertTrue(result['cleanup']['directChildReaped'],'private direct child not reaped; inspect teardown receipt')
  self.assertFalse(result['cleanup']['pipeWritersUnknown'],'unknown pipe writers; inspect teardown receipt')
  self.assertEqual(result['cleanup']['errors'],[],'guarded teardown errors; inspect receipt')
  self.fail('unfinished private fixture required teardown; receipt preserved')
 def finish(self,proc,name,force_stop=None):
  result=capture_fixture(proc,15,force_stop=force_stop)
  proc._fixture_finished=True
  out,err=result['stdout'],result['stderr']
  if hasattr(proc,'_fixture_master'):os.close(proc._fixture_master)
  (self.root/(name+'.json')).write_text(json.dumps(result,indent=2))
  if result['error']:self.fail('private fixture capture failed; preserved receipt: '+name+' '+result['error'])
  lines=proc._fixture_trace.read_text().splitlines()
  writes=[];execs=[]
  for line in lines:
   if 'execve(' in line:
    found=re.search(r'execve\("([^\"]+)"',line)
    if found:execs.append(found.group(1))
   self.assertNotRegex(line,r'(?:open|openat)\([^\n]*"/etc/csf(?:/|\")')
   mutation=(re.search(r'\b(?:open|openat)\(',line) and re.search(r'O_WRONLY|O_RDWR|O_CREAT',line)) or re.search(r'\b(?:rename|renameat|renameat2|unlink|unlinkat|mkdir|rmdir|chmod|chown|lchown|truncate)\(',line)
   if mutation:
    for path in re.findall(r'"([^\"]+)"',line):
     if path.startswith('/') and path not in ['/dev/null','/dev/tty','/dev/stderr','/dev/stdout'] and not path.startswith('/dev/pts/'):self.assertTrue(path.startswith(str(self.root)+'/'),line)
    writes.append(line)
  self.assertTrue(execs)
  for path in execs:
   self.assertNotIn(path,['/usr/sbin/csf','/sbin/ipset','/usr/sbin/ipset','/usr/sbin/conntrack','/sbin/conntrack','/usr/sbin/ss','/sbin/iptables'],path)
  (self.root/(name+'-syscalls.json')).write_text(json.dumps({'traceFile':str(proc._fixture_trace),'execPaths':sorted(set(execs)),'checkedMutationCalls':len(writes),'productionCSFOpens':0,'outsideFixtureWrites':0},indent=2))
  return proc.returncode,out,err
 def race(self,args,wait_command,wait_ip,tty=False):
  a=self.launch(args,{'WAIT_COMMAND':wait_command,'WAIT_IP':wait_ip},tty=tty);deadline=time.monotonic()+8
  while not (self.root/'ready').exists():
   if a.poll() is not None:self.fail('first private CLI exited before barrier: '+str(self.finish(a,'early')))
   if time.monotonic()>deadline:self.finish(a,'barrier-timeout',force_stop='private CLI barrier deadline');self.fail('private CLI barrier timed out')
   time.sleep(.01)
  b=self.launch(['--blacklist','203.0.113.3','winner']);result=self.finish(b,'winner');self.assertEqual(result[0],0,result[2]);winner=self.tracker.read_bytes();(self.root/'go').touch();result=self.finish(a,'stale');self.assertNotEqual(result[0],0,result[2]);self.assertIn('beforeimage',result[2]);self.assertEqual(self.tracker.read_bytes(),winner);self.assertIn(b'203.0.113.3',winner)
 def test_two_single_cli_processes_preserve_winner(self):self.race(['--blacklist','203.0.113.1','stale'],'add','203.0.113.1')
 def test_batch_and_single_cli_processes_preserve_winner_and_itemize(self):
  source=self.root/'input';source.write_text('203.0.113.1\n203.0.113.2\n');self.race(['--blacklist-file',str(source),'stale batch'],'add','203.0.113.1');r=json.loads((self.root/'stale.json').read_text());self.assertIn('BATCH_INPUT 1 ',r['stdout']);self.assertIn('BATCH_INPUT 2 ',r['stdout']);self.assertIn('live_verified_tracking_not_qualified',r['stdout'])
 def test_recursive_csf_hook_runs_without_tracker_lock(self):
  self.tracker.write_text(self.tracker.read_text()+'127.0.0.1 # old conflict\n');p=self.launch(['--whitelist','127.0.0.1','private hook fixture']);r=self.finish(p,'recursive');self.assertEqual(r[0],0,r[2]);self.assertNotIn('FORBIDDEN',r[2]);calls=[json.loads(x) for x in (self.root/'calls.jsonl').read_text().splitlines()];self.assertTrue(any(x['name']=='csf' for x in calls));self.assertNotIn('127.0.0.1',self.tracker.read_text())
 def test_unblacklist_stale_writer_preserves_concurrent_tracker(self):self.race(['--unblacklist','203.0.113.9','stale removal'],'del','203.0.113.9')
 def test_reconcile_stale_writer_preserves_concurrent_tracker(self):
  self.tracker.write_text(self.tracker.read_text()+'127.0.0.1 # conflict\n');(self.root/'live').write_text('203.0.113.9\n127.0.0.1\n');self.race(['--reconcile-allowlist'],'del','127.0.0.1')
 def test_local_whitelist_stale_writer_preserves_concurrent_tracker(self):
  self.tracker.write_text(self.tracker.read_text()+'10.20.30.40 # conflict\n');(self.root/'live').write_text('203.0.113.9\n10.20.30.40\n');self.race(['--whitelist-local-addresses'],'del','10.20.30.40')
 def test_lfd_stale_writer_preserves_concurrent_tracker(self):
  (self.root/'lfd.log').write_text('Oct 23 host lfd: 203.0.113.1 *Blocked in csf* [LF_DISTATTACK]\n');self.race(['--migrate-lfd-distributed'],'add','203.0.113.1')
 def test_default_scan_stale_writer_preserves_concurrent_tracker(self):
  (self.root/'logs'/'access').write_text('203.0.113.55 - - [23/Oct/2026:12:00:00 -0700] "GET /probe?x=php://filter HTTP/1.1" 404 0\n');self.race([],'add','203.0.113.55');receipts=list(self.root.glob('tracker.txn.*/failure.tsv'));self.assertTrue(receipts);self.assertTrue(any('203.0.113.9' in x.read_text() and '203.0.113.55' in x.read_text() for x in receipts))
 def test_initialization_and_recursive_reload_preserve_existing_tracker(self):
  before=self.tracker.read_bytes();r=self.finish(self.launch(['--init']),'initialize');self.assertEqual(r[0],0,r[2]);self.assertEqual(self.tracker.read_bytes(),before);self.assertEqual(self.tracker.stat().st_mode&0o777,0o600)
 def test_clear_stale_writer_preserves_concurrent_tracker(self):self.race(['--clear'],'flush','',tty=True)
 def test_clear_success_only_on_private_tty_fixture(self):
  r=self.finish(self.launch(['--clear'],tty=True),'clear');self.assertEqual(r[0],0,r[2]);self.assertEqual(self.tracker.read_bytes(),b'');self.assertEqual((self.root/'live').read_bytes(),b'');self.assertEqual(self.tracker.stat().st_mode&0o777,0o600)
if __name__=='__main__':unittest.main(verbosity=2)

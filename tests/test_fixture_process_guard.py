"""Fake Popen only: no process, signal or filesystem access in these regressions."""
import json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
try:
 from fixture_process_guard import capture_fixture,own_fixture,spawn_fixture
except ImportError:
 capture_fixture=own_fixture=None
class Clock:
 def __init__(self):self.now=0
 def __call__(self):return self.now
class Stream:
 def __init__(self):self.closed=False
 def close(self):self.closed=True
class Fake:
 pid=12345
 def __init__(self,clock,outcomes,poll=None):
  self.clock=clock;self.outcomes=list(outcomes);self.returncode=poll;self.stdout=Stream();self.stderr=Stream();self.stdin=None;self.calls=[];self.args=['fixture','--synthetic']
 def poll(self):return self.returncode
 def communicate(self,timeout=None):
  if timeout is None:raise AssertionError('unbounded communicate forbidden')
  self.calls.append(timeout);self.clock.now+=timeout
  result=self.outcomes.pop(0) if self.outcomes else subprocess.TimeoutExpired(self.args,timeout)
  if isinstance(result,BaseException):raise result
  self.returncode=0;return result
 def wait(self,timeout=None):
  if timeout is None:raise AssertionError('unbounded wait forbidden')
  self.clock.now+=timeout
  if self.returncode is None:raise subprocess.TimeoutExpired(self.args,timeout)
  return self.returncode
class GuardTests(unittest.TestCase):
 def setup_case(self,outcomes,poll=None):
  self.assertIsNotNone(capture_fixture,'guarded finite fixture supervisor missing')
  clock=Clock();proc=Fake(clock,outcomes,poll);identity={'pid':proc.pid,'ppid':77,'pgrp':proc.pid,'session':proc.pid,'start':'100','argv':proc.args};signals=[]
  own_fixture(proc,proc.args,identity_reader=lambda pid:identity,parent_pid=77)
  return clock,proc,identity,signals
 def capture(self,clock,proc,identity,signals,**kw):
  return capture_fixture(proc,timeout=1,cleanup_budget=3,clock=clock,identity_reader=lambda pid:identity,signal_group=lambda pid,sig:signals.append((pid,sig)),parent_pid=77,**kw)
 def test_reaped_parent_pipe_writer_never_signaled_and_capture_bounded(self):
  clock,p,i,s=self.setup_case([subprocess.TimeoutExpired('fixture',1,output=b'partial')]);p.returncode=0
  r=self.capture(clock,p,i,s);self.assertEqual(s,[]);self.assertLessEqual(clock.now,4);self.assertTrue(r['cleanup']['pipeWritersUnknown']);self.assertTrue(p.stdout.closed);self.assertIn('partial',r['stdout'])
 def test_changed_start_or_argv_or_group_or_parent_never_signaled(self):
  for field,value in [('start','999'),('argv',['different']),('pgrp',55),('session',55),('ppid',88)]:
   with self.subTest(field=field):
    c,p,i,s=self.setup_case([subprocess.TimeoutExpired('fixture',1)]);i[field]=value;r=self.capture(c,p,i,s);self.assertEqual(s,[]);self.assertTrue(r['error']);self.assertLessEqual(c.now,4)
 def test_live_unreaped_exact_direct_child_can_be_signaled(self):
  c,p,i,s=self.setup_case([subprocess.TimeoutExpired('fixture',1,output=b'first'),('done','err')]);r=self.capture(c,p,i,s);self.assertEqual(len(s),1);self.assertEqual(s[0][0],p.pid);self.assertEqual(r['stdout'],'done');self.assertTrue(r['cleanup']['captureComplete'])
 def test_exhausted_capture_preserves_partial_and_all_errors(self):
  c,p,i,s=self.setup_case([subprocess.TimeoutExpired('fixture',1,output=b'first',stderr=b'problem'),subprocess.TimeoutExpired('fixture',1),OSError('capture failure')]);r=self.capture(c,p,i,s);self.assertEqual(r['stdout'],'first');self.assertEqual(r['stderr'],'problem');self.assertLessEqual(c.now,4);self.assertTrue(any('capture failure' in x for x in r['cleanup']['errors']));self.assertTrue(p.stderr.closed)
 def test_barrier_forced_stop_shares_one_finite_cleanup_budget(self):
  c,p,i,s=self.setup_case([]);r=self.capture(c,p,i,s,force_stop='barrier deadline');self.assertLessEqual(c.now,3);self.assertTrue(r['error']);self.assertEqual(len(s),2)
 def test_nonfinite_deadlines_refused_without_capture_or_signal(self):
  for timeout,budget in [(float('inf'),3),(float('nan'),3),(1,float('inf')),(1,float('nan'))]:
   with self.subTest(timeout=timeout,budget=budget):
    c,p,i,s=self.setup_case([])
    with self.assertRaises(ValueError):capture_fixture(p,timeout,cleanup_budget=budget,clock=c,identity_reader=lambda pid:i,signal_group=lambda pid,sig:s.append((pid,sig)),parent_pid=77)
    self.assertEqual(p.calls,[]);self.assertEqual(s,[])
 def test_group_not_signaled_after_direct_child_reaped_between_attempts(self):
  c,p,i,s=self.setup_case([subprocess.TimeoutExpired('fixture',1)])
  def signal_and_reap(pid,sig):s.append((pid,sig));p.returncode=0
  r=capture_fixture(p,1,cleanup_budget=3,clock=c,identity_reader=lambda pid:i,signal_group=signal_and_reap,parent_pid=77);self.assertEqual(len(s),1);self.assertLessEqual(c.now,4)
class PrivateOwnedProcess(unittest.TestCase):
 def test_actual_owned_group_timeout_is_bounded_and_partial_output_retained(self):
  root=Path(tempfile.mkdtemp(prefix='fixture-owner-proof-',dir=os.environ['TMPDIR']))
  argv=[sys.executable,'-B','-S','-c','import time; print("synthetic-owned-marker",flush=True); time.sleep(20)']
  started=time.monotonic();proc=spawn_fixture(argv,cwd=root,env={'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':str(root)},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  result=capture_fixture(proc,.15,cleanup_budget=1)
  (root/'receipt.json').write_text(json.dumps({'argv':argv,'elapsed':time.monotonic()-started,'result':result},indent=2))
  self.assertIsNotNone(result['error']);self.assertIn('synthetic-owned-marker',result['stdout']);self.assertLess(time.monotonic()-started,2)
  self.assertTrue(result['cleanup']['captureComplete']);self.assertTrue(result['cleanup']['directChildReaped']);self.assertFalse(result['cleanup']['pipeWritersUnknown']);self.assertEqual(result['cleanup']['errors'],[]);self.assertEqual(len(result['cleanup']['signals']),1)
if __name__=='__main__':unittest.main(verbosity=2)

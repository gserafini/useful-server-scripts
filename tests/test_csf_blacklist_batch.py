"""Full batch execution through the same isolated native-command fixtures."""
import unittest
import test_csf_blacklist_persistence as fixtures
class BatchContract(fixtures.BatchTests):
 def test_two_constant_tracker_reads_and_one_policy_build(self):
  r,e,reads,live,t=self.run_case('203.0.113.1\n203.0.113.2\n203.0.113.3\n');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(reads,2,'one snapshot load plus one exact pre-publish hash read');self.assertEqual(e.count('policy'),1);self.assertEqual(e.count('setup'),1);self.assertEqual(sum(x.startswith('ipset restore') for x in e),1);self.assertFalse(any(x.startswith('ipset add') for x in e))
 def test_every_input_duplicate_protected_and_invalid_disposition(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n203.0.113.1\n203.0.113.13\n999.0.0.1\n');self.assertNotEqual(r.returncode,0);self.assertEqual(l,[])
  for line in [1,2,3,4]:self.assertRegex(r.stdout+r.stderr,r'BATCH_INPUT '+str(line)+r' ')
 def test_protected_and_duplicate_inputs_itemized(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n203.0.113.1\n203.0.113.13\n');self.assertNotEqual(r.returncode,0);self.assertEqual(l,['203.0.113.1']);self.assertIn('protected',r.stdout);self.assertIn('duplicate-of=1',r.stdout)
 def test_normalization_keeps_permanent_reason_and_unrelated_comment(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n','# retain comment\n203.0.113.9 # ordinary\n203.0.113.9 # do not delete retained\n');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(t.count('203.0.113.9'),1);self.assertIn('do not delete retained',t);self.assertIn('# retain comment',t)
 def test_unknown_tracker_record_stops_before_any_live_add(self):
  for original in ['unknown native record must be reviewed\n','203.0.113.0/24 # CIDR unsupported\n','2001:db8::1 # IPv6 unsupported\n']:
   with self.subTest(original=original):
    r,e,n,l,t=self.run_case('203.0.113.1\n',tracker=original);self.assertNotEqual(r.returncode,0);self.assertEqual(l,[]);self.assertEqual(t,original)
 def test_bulk_error_not_replayed_and_all_outcomes_itemized(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n203.0.113.2\n203.0.113.3\n',fail_ip='203.0.113.2');self.assertNotEqual(r.returncode,0);self.assertEqual(l,['203.0.113.1']);self.assertIn('203.0.113.1',t);self.assertNotIn('203.0.113.2',t);self.assertNotIn('203.0.113.3',t);self.assertEqual(sum(x.startswith('ipset restore') for x in e),1)
  for line in [1,2,3]:self.assertIn('BATCH_INPUT '+str(line)+' ',r.stdout)
 def test_no_verified_native_members_preserves_original_tracker(self):
  original='203.0.113.9 # first\n203.0.113.9 # do not delete duplicate\n'
  r,e,n,l,t=self.run_case('203.0.113.1\n',tracker=original,fail_ip='203.0.113.1');self.assertNotEqual(r.returncode,0);self.assertEqual(l,[]);self.assertEqual(t,original)
 def test_cleanup_budget_reports_unattempted_tail(self):
  r,e,n,l,t=self.run_case('203.0.113.1\n203.0.113.2\n203.0.113.3\n',cleanup_advance=11);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(sum(x.startswith('bounded-teardown ') for x in e),1);self.assertEqual(r.stdout.count('cleanup=deferred_budget'),2)
 def test_cleanup_exit_statuses_are_exact_and_unknown_is_error(self):
  for code in [124,137,7]:
   with self.subTest(code=code):
    r,e,n,l,t=self.run_case('203.0.113.1\n',cleanup_exit=code);self.assertEqual('203.0.113.1' in t,True);self.assertIn('cleanup=exit_'+str(code),r.stdout);self.assertEqual(r.returncode==0,code in [124,137]);self.assertNotIn('connections closed',r.stdout+r.stderr)
 def test_literal_escaped_newline_has_exact_remedy_and_no_mutation(self):
  r,e,n,l,t=self.run_case('203.0.113.1\\n203.0.113.2\n');self.assertNotEqual(r.returncode,0);self.assertEqual(l,[]);self.assertIn('real newline',r.stderr);self.assertIn('quoted heredoc',r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)

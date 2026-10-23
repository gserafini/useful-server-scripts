"""Fail closed if a historical writer bypasses the common publication boundary."""
import re, unittest
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'scripts/csf_ban_wp_login_attackers'
class WriterRoutes(unittest.TestCase):
 def test_all_eight_writer_families_use_shared_io(self):
  source=P.read_text()
  for name in ['reconcile_protected_bans','perform_migrate_lfd_distributed','perform_blacklist','perform_unblacklist','perform_whitelist_local_addresses','perform_clear']:
   block=re.search(r'^'+name+r'\(\) \{.*?^\}',source,re.S|re.M).group(0)
   self.assertIn('tracking_snapshot',block,name);self.assertIn('tracking_publish',block,name)
  init=re.search(r'^perform_init\(\) \{.*?^\}',source,re.S|re.M).group(0);self.assertIn('tracking_initialize',init)
  main=source[source.index('# --- EXECUTION START ---'):];self.assertIn('TRACKING_SCAN_CONTEXT=$(tracking_snapshot)',main);self.assertIn('tracking_publish "$TRACKING_SCAN_CONTEXT"',main)
 def test_old_direct_writer_spellings_removed(self):
  source=P.read_text();forbidden=['>> "$IP_TRACKING_FILE"','mv -f "$cleaned_tracking_file" "$IP_TRACKING_FILE"','mv "$TEMP_TRACKING_FILE" "$IP_TRACKING_FILE"','touch "$IP_TRACKING_FILE"','truncate -s 0 "$IP_TRACKING_FILE"']
  for spelling in forbidden:self.assertNotIn(spelling,source,spelling)
if __name__=='__main__':unittest.main(verbosity=2)

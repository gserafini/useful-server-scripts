"""The launcher preserves explicit PHP, argv and the real updater target."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'wp-cpanel'

class LauncherTest(unittest.TestCase):
    def test_native_cwd_selection_and_explicit_php(self):
        with tempfile.TemporaryDirectory(prefix='wp-launcher-', dir=SCRIPT.parent.parent / 'tests') as directory:
            # cPanel securetmp is noexec; keep the executable fixture in this repo.
            root = Path(directory)
            phar = root / 'fixture.php'
            phar.write_text('<?php echo json_encode([PHP_VERSION_ID, $_SERVER["argv"]]);')
            launcher = root / 'wp'
            launcher.write_text(SCRIPT.read_text().replace('/usr/local/lib/wp-cli/wp-cli.phar', str(phar)))
            launcher.chmod(0o755)
            args = ['--path=/tmp/a b', '--url=example.test', 'quoted\'value']
            for cmd, version in [([str(launcher)], 805), (['/opt/cpanel/ea-php82/root/usr/bin/php', str(launcher)], 802)]:
                result = subprocess.run(cmd + args, cwd='/home/share/public_html', check=True, text=True, capture_output=True)
                php, argv = json.loads(result.stdout)
                self.assertEqual(php // 100, version)
                self.assertEqual(argv, [str(phar)] + args)

if __name__ == '__main__':
    unittest.main()

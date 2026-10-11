"""Installer platform choices and archived APT isolation, without host changes."""
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
HELPER=ROOT/'donino_link/resources/platform.sh'


class PlatformTests(unittest.TestCase):
    def shell(self,system,version,body,architecture='amd64'):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);release=root/'os-release';release.write_text(f'ID={system}\nVERSION_ID={version}\n')
            # Replace mutations/package access with probes. Archived files
            # belong to this disposable directory, never the host filesystem.
            helper=root/'platform.sh';helper.write_text(HELPER.read_text().replace('/var/cache/donino-link/apt',str(root)))
            script=f'''set -Eeuo pipefail
source "{helper}"
dpkg() {{ echo "{architecture}"; }}
install() {{ :; }}
chmod() {{ :; }}
donino_platform "{release}"
{body}
'''
            return subprocess.run(['bash','-c',script],capture_output=True,text=True)

    def test_all_released_ubuntu_versions_and_preview(self):
        for version in ['22.04','22.10','23.04','23.10','24.04','24.10','25.04','25.10','26.04','26.10']:
            for arch in ['amd64','arm64']:
                with self.subTest(version=version,arch=arch):
                    result=self.shell('ubuntu',version,'printf "%s" "$DONINO_CODENAME"',arch)
                    self.assertEqual(result.returncode,0,result.stderr)

    def test_supported_debian_and_unsupported_hosts(self):
        for version in ['12','13']:
            self.assertEqual(self.shell('debian',version,':').returncode,0)
        for system,version,arch in [('ubuntu','20.04','amd64'),('ubuntu','28.04','amd64'),('fedora','44','amd64'),('ubuntu','24.04','i386')]:
            self.assertNotEqual(self.shell(system,version,':',arch).returncode,0)

    def test_archived_apt_is_isolated_and_signed(self):
        body='apt-get() { printf "%s\\n" "$@"; }; donino_apt update -q; cat "${DONINO_APT_OPTIONS[1]#*=}"'
        result=self.shell('ubuntu','23.10',body)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Dir::Etc::sourceparts=-',result.stdout)
        self.assertIn('http://old-releases.ubuntu.com/ubuntu/ mantic-security',result.stdout)
        self.assertNotIn('trusted=yes',result.stdout)
        self.assertNotIn('AllowUnauthenticated',result.stdout)

    def test_lts_keeps_host_apt_sources(self):
        result=self.shell('ubuntu','24.04','echo "options=${#DONINO_APT_OPTIONS[@]}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('options=0',result.stdout)

    def test_archive_migration_falls_back_to_live_host_sources(self):
        body='apt-get() { if [[ "$*" == *Dir::Etc::sourcelist* ]]; then return 100; fi; echo live-host-sources; }; donino_apt update -q; echo "options=${#DONINO_APT_OPTIONS[@]}"'
        result=self.shell('ubuntu','25.10',body)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('live-host-sources',result.stdout)
        self.assertIn('options=0',result.stdout)

    def test_time64_candidate_and_fallback(self):
        for expected in ['libasound2t64','libasound2']:
            body='apt-cache() { if [[ "$2" == '+expected+' ]]; then echo "Candidate: 1.0"; else echo "Candidate: (none)"; fi; }; donino_package libasound2t64 libasound2'
            result=self.shell('ubuntu','24.04',body)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.splitlines()[-1],expected)

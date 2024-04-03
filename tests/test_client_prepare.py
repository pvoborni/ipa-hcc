import os
import shutil
import tempfile
from unittest import mock

from dns.rdtypes.ANY.URI import URI
from ipaplatform.tasks import tasks

import conftest
from ipahcc.client import client_prepare

CONFIG = {
    "domain": conftest.DOMAIN,
    "idmsvc_api_url": "https://api.test/api/idmsvc/v1",
    "dev_username": "user",
    "dev_password": "test",
}


class TestAutoEnrollment(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)

        self.mock_hccplatform()
        p = mock.patch.multiple(
            client_prepare,
            SYSCONFIG=os.path.join(self.tmpdir, "ipa-hcc-auto-enrollment"),
        )
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(client_prepare, "get_ipa_resolver")
        resolver = p.start()
        resolver.return_value.resolve.return_value = [
            URI(1, 256, 0, 100, "https://server.test/service"),
        ]
        self.addCleanup(p.stop)

        p = mock.patch.object(client_prepare, "urlopen")
        self.m_urlopen = p.start()
        # hcc_host_conf, hcc_register
        self.m_urlopen.side_effect = [
            conftest.jsonio(CONFIG),
        ]
        self.addCleanup(p.stop)

        p = mock.patch.object(tasks, "set_hostname")
        self.m_sethostname = p.start()
        self.addCleanup(p.stop)

    def parse_args(self, *args):
        return client_prepare.parser.parse_args(args=args)

    def assert_args_error(self, args, expected=None):
        with self.assertRaises(SystemExit):
            with conftest.capture_output() as out:
                client_prepare.main(args)
        if expected is not None:
            self.assertIn(expected, out.read())
        return out

    def test_args(self):
        args = self.parse_args()
        self.assertEqual(args.timeout, 10)

    def test_prepare(self):
        args = self.parse_args()
        prepare = client_prepare.ClientPrepare(args)
        prepare.configure()

        with open(client_prepare.SYSCONFIG, encoding="utf-8") as f:
            sysconfig = f.read().strip()

        self.assertEqual(
            sysconfig,
            (
                'AUTO_ENROLLMENT_ARGS="--verbose --insecure '
                f'--idmsvc-api-url {CONFIG["idmsvc_api_url"]} '
                f'--dev-username {CONFIG["dev_username"]} '
                f'--dev-password {CONFIG["dev_password"]}"'
            ),
        )

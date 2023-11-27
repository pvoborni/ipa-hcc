#
# very basic tests to ensure code is at least importable.
#

import conftest
from ipahcc.server.util import parse_rhsm_cert

# pylint: disable=import-outside-toplevel


class IPAClientTests(conftest.IPABaseTests):
    def test_auto_enrollment_help(self):
        import ipahcc_auto_enrollment

        self.assert_cli_run(ipahcc_auto_enrollment.main, "--help")


@conftest.requires_ipaserver
class IPAServerTests(conftest.IPABaseTests):
    def test_server_plugin_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.install.plugins import update_hcc  # noqa: F401
        from ipaserver.plugins import (
            hccconfig,  # noqa: F401
            hcchost,  # noqa: F401
            hccidp,  # noqa: F401
            hccjwk,  # noqa: F401
            hccserverroles,  # noqa: F401
        )

    def test_registration_service_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.install.plugins import (  # noqa: F401
            update_hcc_enrollment_service,
        )

    def test_mockapi_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.install.plugins import (  # noqa: F401
            update_hcc_mockapi,
        )


class IPAHCCServerTests(conftest.IPABaseTests):
    def test_ipa_hcc_cli_help(self):
        from ipahcc.server import cli

        self.assert_cli_run(cli.main, "--help")


class TestUtil(IPAClientTests):
    def test_parse_cert(self):
        with open(conftest.RHSM_CERT, "rb") as f:
            org_id, rhsm_id = parse_rhsm_cert(f.read())
        self.assertEqual(org_id, conftest.ORG_ID)
        self.assertEqual(rhsm_id, conftest.CLIENT_RHSM_ID)

        with self.assertRaises(ValueError):
            parse_rhsm_cert("data")
        with self.assertRaises(ValueError):
            parse_rhsm_cert(b"data")

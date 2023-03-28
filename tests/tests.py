#
# very basic tests to ensure code is at least importable.
#

import conftest
from ipahcc import hccplatform
from ipahcc.server import schema

# pylint: disable=import-outside-toplevel


class IPAClientTests(conftest.IPABaseTests):
    def test_auto_enrollment_help(self):
        from ipahcc.client import auto_enrollment

        self.assert_cli_run(auto_enrollment.main, "--help")


class WSGITests(conftest.IPABaseTests):
    def test_wsgi_imports(self):
        from ipahcc.registration import wsgi as hcc_registration_service
        from ipahcc.mockapi import wsgi as hcc_mockapi

        assert callable(hcc_registration_service.application)
        assert callable(hcc_mockapi.application)


@conftest.requires_ipaserver
class IPAServerTests(conftest.IPABaseTests):
    def test_server_plugin_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.plugins import hccconfig  # noqa: F401
        from ipaserver.plugins import hcchost  # noqa: F401
        from ipaserver.plugins import hccserverroles  # noqa: F401
        from ipaserver.install.plugins import update_hcc  # noqa: F401

    def test_registration_service_imports(self):
        # pylint: disable=unused-import,unused-variable,import-error
        from ipaserver.install.plugins import (  # noqa: F401
            update_hcc_enrollment_service,
        )


@conftest.requires_ipa_install
class IPAHCCServerTests(conftest.IPABaseTests):
    def test_ipa_hcc_cli_help(self):
        from ipahcc.server.cli import IPAHCCCli

        # admintool's main() needs argv0
        self.assert_cli_run(IPAHCCCli.main, "argv0", "--help")

    def test_ipa_hcc_dbus_help(self):
        from ipahcc.server import dbus_service
        from ipahcc.server import dbus_cli

        self.assert_cli_run(dbus_service.main, "--help")
        self.assert_cli_run(dbus_cli.main, "--help")


@conftest.requires_jsonschema
class TestJSONSchema(conftest.IPABaseTests):
    def test_hcc_request(self):
        instance = {
            "domain_name": "domain.example",
            "domain_type": "rhel-idm",
            "domain_id": "71c0bf27-37e7-41ae-b51b-1a8599025e1a",
            "inventory_id": "91e3fa59-4de2-4a28-90b2-01965b201ade",
        }
        schema.validate_schema(instance, "/schemas/hcc-host-register/request")

        instance["extra"] = True

        with self.assertRaises(schema.ValidationError):
            schema.validate_schema(
                instance, "/schemas/hcc-host-register/request"
            )

    def test_domain_request(self):
        instance = {
            "domain_name": conftest.DOMAIN,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": conftest.REALM,
                "servers": [
                    {
                        "fqdn": conftest.SERVER_FQDN,
                        "subscription_manager_id": conftest.SERVER_RHSM_ID,
                        "location": "sigma",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": True,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica1.ipahcc.test",
                        "subscription_manager_id": "fdebb5ad-f8d7-4234-a1ff-2b9ef074089b",
                        "location": "tau",
                        "ca_server": True,
                        "hcc_enrollment_server": True,
                        "hcc_update_server": False,
                        "pkinit_server": True,
                    },
                    {
                        "fqdn": "ipareplica2.ipahcc.test",
                        "subscription_manager_id": None,
                        "location": None,
                        "ca_server": False,
                        "hcc_enrollment_server": False,
                        "hcc_update_server": False,
                        "pkinit_server": True,
                    },
                ],
                "cacerts": [
                    {
                        "nickname": "IPAHCC.TEST IPA CA",
                        "pem": conftest.IPA_CA_DATA,
                    }
                ],
                "realm_domains": [conftest.DOMAIN],
                "locations": [
                    {"name": "kappa", "description": None},
                    {"name": "sigma", "description": None},
                    {"name": "tau", "description": "location tau"},
                ],
            },
        }
        schema.validate_schema(instance, "/schemas/domain/request")
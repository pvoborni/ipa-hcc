import json

from requests import Response
from ipapython import admintool
from ipapython.dnsutil import DNSName
from ipalib import x509

import conftest
from conftest import mock

from ipahcc import hccplatform
from ipahcc.server import hccapi
from ipahcc.server.dbus_service import IPAHCCDbus

CACERT = x509.load_certificate_from_file(conftest.IPA_CA_CRT)


@conftest.requires_mock
class TestHCCAPICommon(conftest.IPABaseTests):
    def setUp(self):
        super(TestHCCAPICommon, self).setUp()

        self.mock_hccplatform()

        self.m_api = mock.Mock()
        self.m_api.isdone.return_value = True
        self.m_api.env = self.get_mock_env()
        self.m_api.Command.ca_is_enabled.return_value = {"result": True}
        # note: stripped down config_show() output
        self.m_api.Command.config_show.return_value = {
            "result": {
                "ca_server_server": (conftest.SERVER_FQDN,),
                "dns_server_server": (conftest.SERVER_FQDN,),
                "hcc_enrollment_server_server": (conftest.SERVER_FQDN,),
                "hcc_update_server_server": conftest.SERVER_FQDN,
                "hccdomainid": (conftest.DOMAIN_ID,),
                "hccorgid": (conftest.ORG_ID,),
                "ipa_master_server": (conftest.SERVER_FQDN,),
                "kra_server_server": (conftest.SERVER_FQDN,),
                "pkinit_server_server": (conftest.SERVER_FQDN,),
            },
            "summary": None,
            "value": None,
        }
        self.m_api.Command.server_find.return_value = {
            "count": 1,
            "result": (
                {
                    "cn": (conftest.SERVER_FQDN,),
                    "ipalocation_location": (DNSName("sigma"),),
                },
            ),
            "summary": "1 host matched",
            "truncated": False,
        }
        self.m_api.Command.host_find.return_value = {
            "count": 1,
            "result": (
                {
                    "fqdn": (conftest.SERVER_FQDN,),
                    "hccsubscriptionid": (conftest.SERVER_RHSM_ID,),
                },
            ),
            "summary": "1 host matched",
            "truncated": False,
        }
        self.m_api.Command.realmdomains_show.return_value = {
            "result": {
                "associateddomain": (conftest.DOMAIN,),
            }
        }
        self.m_api.Command.location_find.return_value = {
            "result": (
                {"idnsname": (DNSName("kappa"),)},
                {"idnsname": (DNSName("sigma"),)},
                {
                    "idnsname": (DNSName("tau"),),
                    "description": ("location tau",),
                },
            ),
        }

        p = mock.patch.object(hccapi, "get_ca_certs")
        self.m_get_ca_certs = p.start()
        self.m_get_ca_certs.return_value = [
            (CACERT, "IPA-HCC.TEST IPA CA", True, None)
        ]
        self.addCleanup(p.stop)

        self.m_session = mock.Mock()
        self.m_hccapi = hccapi.HCCAPI(self.m_api)
        self.m_hccapi.session = self.m_session


@conftest.requires_mock
class TestHCCAPI(TestHCCAPICommon):
    def test_check_host(self):
        body = {"inventory_id": conftest.CLIENT_INVENTORY_ID}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.m_hccapi.check_host(
            conftest.DOMAIN_ID,
            conftest.CLIENT_INVENTORY_ID,
            conftest.CLIENT_RHSM_ID,
            conftest.CLIENT_FQDN,
        )
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, Response)

    def test_register_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.m_hccapi.register_domain(
            conftest.DOMAIN_ID, "mockapi"
        )
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, Response)

    def test_update_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        info, resp = self.m_hccapi.update_domain()
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, Response)


@conftest.requires_mock
class TestIPAHCCDbus(TestHCCAPICommon):
    def setUp(self):
        super(TestIPAHCCDbus, self).setUp()
        bus = mock.Mock()
        bus_name = mock.Mock()
        self.m_mainloop = mock.Mock()
        self.dbus = IPAHCCDbus(
            bus,
            hccplatform.HCC_DBUS_OBJ_PATH,
            bus_name=bus_name,
            loop=self.m_mainloop,
            hccapi=self.m_hccapi,
        )
        self.addCleanup(self.dbus.stop)

    def dbus_call(self, method, *args):
        # pylint: disable=protected-access
        self.assertTrue(self.dbus._lq_thread.is_alive())
        ok_cb = mock.Mock()
        err_cb = mock.Mock()
        args += (ok_cb, err_cb)
        method(*args)
        # wait for queue to process task
        self.dbus._lq._queue.join()
        return ok_cb, err_cb

    def test_dbus_livecycle(self):
        # pylint: disable=protected-access
        self.assertTrue(self.dbus._lq_thread.is_alive())
        self.dbus.stop()
        self.assertFalse(self.dbus._lq_thread.is_alive())
        self.assert_log_entry("Stopping lookup queue")
        self.m_mainloop.quit.assert_called_once()

    def test_check_host(self):
        body = {"inventory_id": conftest.CLIENT_INVENTORY_ID}
        self.m_session.request.return_value = self.mkresponse(200, body)
        ok_cb, err_cb = self.dbus_call(
            self.dbus.check_host,
            conftest.DOMAIN_ID,
            conftest.CLIENT_INVENTORY_ID,
            conftest.CLIENT_RHSM_ID,
            conftest.CLIENT_FQDN,
        )

        err_cb.assert_not_called()
        ok_cb.assert_called_once_with(
            200,
            "OK",
            None,
            {"content-type": "application/json", "content-length": 56},
            json.dumps(body),
            0,
            "OK",
        )

    def test_register_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        ok_cb, err_cb = self.dbus_call(
            self.dbus.register_domain, conftest.DOMAIN_ID, "mockapi"
        )

        err_cb.assert_not_called()
        ok_cb.assert_called_once_with(
            200,
            "OK",
            None,
            {"content-type": "application/json", "content-length": 16},
            json.dumps(body),
            0,
            "OK",
        )

    def test_update_domain(self):
        body = {"status": "ok"}
        self.m_session.request.return_value = self.mkresponse(200, body)
        ok_cb, err_cb = self.dbus_call(
            self.dbus.update_domain,
            False,
        )

        err_cb.assert_not_called()
        ok_cb.assert_called_once_with(
            200,
            "OK",
            None,
            {"content-type": "application/json", "content-length": 16},
            json.dumps(body),
            0,
            "OK",
        )


@conftest.requires_mock
class TestDBUSCli(conftest.IPABaseTests):
    def setUp(self):
        super(TestDBUSCli, self).setUp()
        p = mock.patch("ipahcc.hccplatform.is_ipa_configured")
        self.m_is_ipa_configured = p.start()
        self.addCleanup(p.stop)
        self.m_is_ipa_configured.return_value = False

        p = mock.patch.multiple(
            "ipahcc.server.dbus_client",
            check_host=mock.Mock(),
            register_domain=mock.Mock(),
            update_domain=mock.Mock(),
        )
        self.m_dbus_client = p.start()
        self.addCleanup(p.stop)

    def test_cli(self):
        # pylint: disable=import-outside-toplevel
        from ipahcc.server.dbus_cli import main

        out = self.assert_cli_run(main, exitcode=2)
        self.assertIn("usage:", out)

        out = self.assert_cli_run(
            main,
            "register",
            conftest.DOMAIN_ID,
            "mockapi",
            exitcode=admintool.SERVER_NOT_CONFIGURED,
        )
        self.assertEqual(out.strip(), "IPA is not configured on this system.")

        self.m_is_ipa_configured.return_value = True

        with mock.patch("ipahcc.server.dbus_client.register_domain") as m:
            m.return_value = {"status": "ok"}
            out = self.assert_cli_run(
                main, "register", conftest.DOMAIN_ID, "mockapi"
            )
        self.assertIn("ok", out)

        with mock.patch("ipahcc.server.dbus_client.update_domain") as m:
            m.return_value = {"status": "ok"}
            out = self.assert_cli_run(main, "update")
        self.assertIn("ok", out)

        with mock.patch("ipahcc.server.dbus_client.check_host") as m:
            m.return_value = {"status": "ok"}
            out = self.assert_cli_run(
                main,
                "check-host",
                conftest.DOMAIN_ID,
                conftest.CLIENT_INVENTORY_ID,
                conftest.CLIENT_RHSM_ID,
                conftest.CLIENT_FQDN,
            )
        self.assertIn("ok", out)

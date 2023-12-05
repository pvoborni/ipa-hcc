import copy
import textwrap
import typing
import unittest
from unittest import mock

from ipalib import x509
from ipapython import admintool
from ipapython.dnsutil import DNSName

import conftest
from ipahcc import hccplatform, sign
from ipahcc.mockapi import domain_token
from ipahcc.server import hccapi

CACERT = x509.load_pem_x509_certificate(conftest.IPA_CA_DATA.encode("ascii"))

COMMON_RESULT: typing.Dict[str, typing.Any] = {
    "domain_name": conftest.DOMAIN,
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    hccplatform.HCC_DOMAIN_TYPE: {
        "realm_name": conftest.REALM,
        "servers": [
            {
                "fqdn": conftest.SERVER_FQDN,
                "ca_server": True,
                "hcc_enrollment_server": True,
                "hcc_update_server": True,
                "pkinit_server": True,
                "subscription_manager_id": conftest.SERVER_RHSM_ID,
                "location": "sigma",
            }
        ],
        "locations": [
            {"name": "kappa"},
            {"name": "sigma"},
            {"name": "tau", "description": "location tau"},
        ],
        "automount_locations": ["default"],
        "realm_domains": [conftest.DOMAIN],
    },
}

DOMAIN_REGISTER_RESULT = copy.deepcopy(COMMON_RESULT)
DOMAIN_REGISTER_RESULT.update(
    {
        "auto_enrollment_enabled": True,
        "domain_id": conftest.DOMAIN_ID,
    }
)
DOMAIN_REGISTER_RESULT[hccplatform.HCC_DOMAIN_TYPE].update(
    {
        "ca_certs": [conftest.IPA_CA_CERTINFO],
    }
)

DOMAIN_UPDATE_RESULT = DOMAIN_REGISTER_RESULT
DOMAIN_GET_RESULT = DOMAIN_REGISTER_RESULT

STATUS_CHECK_RESULT = copy.deepcopy(COMMON_RESULT)
STATUS_CHECK_RESULT.update(
    {
        "domain_id": conftest.DOMAIN_ID,
        "org_id": conftest.ORG_ID,
    }
)

DOMAIN_REG_TOKEN_RESULT = {
    "domain_token": "F3n-iOZn1VI.wbzIH7v-kRrdvfIvia4nBKAvEpIKGdv6MSIFXeUtqVY",
    "domain_id": "7b160558-8273-5a24-b559-6de3ff053c63",
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "expiration": 1691662998,
}

JWK_PRIV = sign.generate_private_key()
JWK_PUBSTR = JWK_PRIV.export_public()
REVOKED_KID = "w7ES12OK"
EXPIRED_KID = "i9sjItkt"

SIGNING_KEYS_RESPONSE = {
    "keys": [JWK_PUBSTR],
    "revoked_kids": [REVOKED_KID],
}


class TestHCCAPICommon(conftest.IPABaseTests):
    def setUp(self):
        super().setUp()

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
        self.m_api.Command.automountlocation_find.return_value = {
            "result": ({"cn": ("default",)},),
        }
        self.m_api.Command.hccjwk_find.return_value = {
            "result": [
                {
                    "cn": (JWK_PRIV["kid"],),
                    "hccpublicjwk": (JWK_PUBSTR,),
                    "state": (sign.KeyState.VALID,),
                },
                {
                    "cn": (REVOKED_KID,),
                    "hccpublicjwk": (),
                    "state": (sign.KeyState.REVOKED,),
                },
                {
                    "cn": (EXPIRED_KID,),
                    "hccpublicjwk": (),
                    "state": (sign.KeyState.EXPIRED,),
                },
            ]
        }

        p = mock.patch.object(hccapi, "get_ca_certs")
        self.m_get_ca_certs = p.start()
        self.m_get_ca_certs.return_value = [
            (CACERT, conftest.IPA_CA_NICKNAME, True, None)
        ]
        self.addCleanup(p.stop)

        self.m_session = mock.Mock()
        self.m_hccapi = hccapi.HCCAPI(self.m_api)
        self.m_hccapi.session = self.m_session

        p = mock.patch.object(hccapi.APIResult, "genrid")
        self.m_genrid = p.start()
        self.m_genrid.return_value = "rid"
        self.addCleanup(p.stop)

    def gen_domain_reg_token(self):
        token, expires_ns = domain_token.generate_token(
            hccplatform.TEST_DOMREG_KEY,
            hccplatform.HCC_DOMAIN_TYPE,
            conftest.ORG_ID,
        )
        domain_id = domain_token.token_domain_id(token)
        return {
            "domain_id": str(domain_id),
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_token": token,
            "expiration": int(expires_ns / 1_000_000_000),
        }


class TestHCCAPI(TestHCCAPICommon):
    def test_register_domain(self):
        tok = self.gen_domain_reg_token()
        self.m_session.request.return_value = self.mkresponse(
            200, DOMAIN_REGISTER_RESULT
        )
        info, resp = self.m_hccapi.register_domain(tok["domain_token"])
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, hccapi.APIResult)

    def test_update_domain(self):
        self.m_session.request.return_value = self.mkresponse(
            200, DOMAIN_UPDATE_RESULT
        )
        info, resp = self.m_hccapi.update_domain()
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, hccapi.APIResult)

    def test_signing_keys(self):
        self.m_session.request.return_value = self.mkresponse(
            200, SIGNING_KEYS_RESPONSE
        )
        keys, revoked_kids = self.m_hccapi.get_signing_keys()
        self.assertEqual(set(keys), {JWK_PRIV["kid"]})
        self.assertEqual(revoked_kids, [REVOKED_KID])

    def test_status_check(self):
        self.m_session.request.return_value = self.mkresponse(
            200, DOMAIN_GET_RESULT
        )
        info, resp = self.m_hccapi.status_check()
        self.assertIsInstance(info, dict)
        self.assertIsInstance(resp, hccapi.APIResult)

    def test_get_ipa_jwkset(self):
        jwkset = self.m_hccapi.get_ipa_jwkset()
        expected = sign.JWKSet()
        expected.add(sign.get_public_key(JWK_PRIV))
        self.assertEqual(jwkset, expected)

    def test_update_jwk_do_update(self):
        self.m_session.request.return_value = self.mkresponse(
            200, SIGNING_KEYS_RESPONSE
        )
        # IPA lists revoked key as valid, update_jwk changes it to invalid
        self.m_api.Command.hccjwk_find.return_value = {
            "result": [
                {
                    "cn": (REVOKED_KID,),
                    "hccpublicjwk": (JWK_PUBSTR,),  # need a random JWK
                    "state": (sign.KeyState.VALID,),
                }
            ]
        }
        self.m_api.Command.batch.return_value = {"results": [{}, {}]}

        info, resp = self.m_hccapi.update_jwk()
        self.assertIsInstance(resp, hccapi.APIResult)
        self.assertEqual(info, {})
        updates = [
            {
                "method": "hccjwk_add",
                "params": [[JWK_PRIV["kid"]], {"hccpublicjwk": JWK_PUBSTR}],
            },
            {
                "method": "hccjwk_revoke",
                "params": [[REVOKED_KID], {}],
            },
        ]
        self.m_api.Command.batch.assert_called_once_with(updates)

    def test_update_jwk_noop(self):
        # IPA API has all keys, nothing to do
        self.m_session.request.return_value = self.mkresponse(
            200, SIGNING_KEYS_RESPONSE
        )
        info, resp = self.m_hccapi.update_jwk()
        self.assertIsInstance(resp, hccapi.APIResult)
        self.assertEqual(info, {})
        self.m_api.Command.batch.assert_not_called()


class TestCLI(TestHCCAPICommon):
    def setUp(self):
        super().setUp()
        p: typing.Any
        p = mock.patch("ipahcc.hccplatform.is_ipa_configured")
        self.m_is_ipa_configured = p.start()
        self.addCleanup(p.stop)
        self.m_is_ipa_configured.return_value = True

        # patch ipalib.api for cli.main()
        p = mock.patch("ipalib.api", self.m_api)
        p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(
            hccapi.HCCAPI, "_submit_idmsvc_api", autospec=True
        )
        self.m_submit_idmsvc_api = p.start()
        self.addCleanup(p.stop)

        p = mock.patch("os.geteuid")
        self.m_geteuid = p.start()
        self.m_geteuid.return_value = 0
        self.addCleanup(p.stop)

    def assert_cli_run(self, *args, **kwargs):
        # pylint: disable=import-outside-toplevel
        from ipahcc.server.cli import main

        return super().assert_cli_run(main, *args, **kwargs)

    def test_cli_noaction(self):
        out = self.assert_cli_run(exitcode=2)
        self.assertIn("usage:", out)

    def test_cli_not_configured(self):
        self.m_is_ipa_configured.return_value = False

        out = self.assert_cli_run(
            "register",
            conftest.DOMAIN_ID,
            exitcode=admintool.SERVER_NOT_CONFIGURED,
        )
        self.assertEqual(out.strip(), "IPA is not configured on this system.")

    def test_cli_register(self):
        # register calls "register_domain" followed by "update_jwk"
        self.m_submit_idmsvc_api.side_effect = [
            self.mkresponse(200, DOMAIN_REGISTER_RESULT),
            self.mkresponse(200, SIGNING_KEYS_RESPONSE),
        ]
        tok = self.gen_domain_reg_token()
        out = self.assert_cli_run(
            "register", "--unattended", tok["domain_token"]
        )
        self.assertIn("Successfully registered domain", out)

    def test_cli_update(self):
        # update calls "update_domain" followed by "update_jwk"
        self.m_submit_idmsvc_api.side_effect = [
            self.mkresponse(200, DOMAIN_UPDATE_RESULT),
            self.mkresponse(200, SIGNING_KEYS_RESPONSE),
        ]
        out = self.assert_cli_run("update")
        self.assertIn("Successfully updated domain", out)

    def test_cli_status(self):
        self.m_submit_idmsvc_api.side_effect = [
            self.mkresponse(200, DOMAIN_GET_RESULT),
            self.mkresponse(200, STATUS_CHECK_RESULT),
        ]
        out = self.assert_cli_run("status")

        self.assertEqual(
            out,
            textwrap.dedent(
                f"""\
            domain name: {conftest.DOMAIN}
            domain id: {conftest.DOMAIN_ID}
            org id: {conftest.ORG_ID}
            auto enrollment: True
            servers:
            \t{conftest.SERVER_FQDN} (HCC plugin: yes)
            """
            ),
        )

    @unittest.skipUnless(
        hccplatform.DEVELOPMENT_MODE, "token API is only enabled in dev mode"
    )
    def test_domain_reg_token(self):
        self.m_submit_idmsvc_api.return_value = self.mkresponse(
            200, DOMAIN_REG_TOKEN_RESULT
        )
        out = self.assert_cli_run("token")
        token = DOMAIN_REG_TOKEN_RESULT["domain_token"]
        self.assertEqual(out, f"{token}\n")

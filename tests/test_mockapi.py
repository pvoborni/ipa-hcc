import copy
import typing
import unittest
import uuid
from unittest import mock

from test_hccapi import DOMAIN_RESULT

import conftest
from ipahcc import hccplatform, sign
from ipahcc.mockapi import domain_token, wsgi

domain_request = {
    "title": "Some title",
    "description": "Some description",
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
        ],
        "ca_certs": [conftest.IPA_CA_CERTINFO],
        "locations": [
            {"name": "kappa"},
            {"name": "sigma"},
            {"name": "tau", "description": "location tau"},
        ],
        "realm_domains": [conftest.DOMAIN],
    },
}

host_conf_response = {
    "domain_name": conftest.DOMAIN,
    "domain_type": hccplatform.HCC_DOMAIN_TYPE,
    "domain_id": conftest.DOMAIN_ID,
    "auto_enrollment_enabled": True,
    # "token": ...,
    hccplatform.HCC_DOMAIN_TYPE: {
        "realm_name": conftest.REALM,
        "cabundle": conftest.IPA_CA_DATA,
        "enrollment_servers": [{"fqdn": conftest.SERVER_FQDN}],
    },
}

PRIV_KEY = sign.generate_private_key()
PUB_KEY = sign.get_public_key(PRIV_KEY)


class TestMockAPIWSGI(conftest.IPAWSGIBaseTests):
    wsgi_class = wsgi.Application

    def setUp(self):
        p = mock.patch.object(wsgi.Application, "_load_jwk")
        self.m_load_jwk = p.start()
        self.m_load_jwk.return_value = (PRIV_KEY, PUB_KEY.export_public())
        self.addCleanup(p.stop)

        super().setUp()

        p = mock.patch.object(self.app, "session")
        self.m_session = p.start()
        self.addCleanup(p.stop)

        # lookup inventory result
        self.m_session.get.return_value = self.mkresponse(
            200,
            {
                "results": [
                    {
                        "fqdn": conftest.CLIENT_FQDN,
                        "id": conftest.CLIENT_INVENTORY_ID,
                        "subscription_manager_id": conftest.CLIENT_RHSM_ID,
                    }
                ],
                "total": 1,
            },
        )

        p = mock.patch.object(self.app, "get_access_token")
        self.m_access_token = p.start()
        self.addCleanup(p.stop)
        self.m_access_token.return_value = "access token"

    def test_root(self):
        status_code, status_msg, headers, response = self.call_wsgi(
            "/", {}, method="GET"
        )
        self.assert_response(200, status_code, status_msg, headers, response)

    def test_host_conf(self):
        path = "/".join(
            (
                "",
                "host-conf",
                conftest.CLIENT_INVENTORY_ID,
                conftest.CLIENT_FQDN,
            )
        )
        body: typing.Dict[str, typing.Any] = {}
        status_code, status_msg, headers, response = self.call_wsgi(
            path, body, method="POST"
        )
        self.assert_response(200, status_code, status_msg, headers, response)
        raw_token = response.pop("token")
        self.assertEqual(response, host_conf_response)
        header, claims = sign.validate_host_token(
            raw_token,
            PUB_KEY,
            cert_o=conftest.ORG_ID,
            cert_cn=conftest.CLIENT_RHSM_ID,
            inventory_id=conftest.CLIENT_INVENTORY_ID,
            fqdn=conftest.CLIENT_FQDN,
            domain_id=conftest.DOMAIN_ID,
        )
        self.assertEqual(header["kid"], PUB_KEY["kid"])
        self.assertIn("jti", claims)

    def test_register_domain(self):
        headers = {"HTTP_X_RH_IDM_REGISTRATION_TOKEN": "mockapi"}
        path = "/".join(("", "domains", conftest.DOMAIN_ID, "register"))
        status_code, status_msg, headers, response = self.call_wsgi(
            path,
            domain_request,
            method="PUT",
            extra_headers={
                "X-RH-IDM-Registration-Token": "mockapi",
            },
        )
        self.assert_response(200, status_code, status_msg, headers, response)
        expected = copy.deepcopy(DOMAIN_RESULT)
        expected["signing_keys"] = {
            "keys": [self.app.raw_pub_key],
            "revoked_kids": ["bad key id"],
        }
        self.assertEqual(response, expected)

    def test_update_domain(self):
        path = "/".join(("", "domains", conftest.DOMAIN_ID, "update"))
        status_code, status_msg, headers, response = self.call_wsgi(
            path, domain_request, method="PUT"
        )

        self.assert_response(200, status_code, status_msg, headers, response)
        expected = copy.deepcopy(DOMAIN_RESULT)
        expected["signing_keys"] = {
            "keys": [self.app.raw_pub_key],
            "revoked_kids": ["bad key id"],
        }
        self.assertEqual(response, expected)

    def test_domain_reg_token(self) -> None:
        path = "/domains/token"
        body = {"domain_type": hccplatform.HCC_DOMAIN_TYPE}
        headers = {}
        status_code, status_msg, headers, response = self.call_wsgi(
            path,
            body,
            method="POST",
        )
        self.assert_response(200, status_code, status_msg, headers, response)
        token: str = response["domain_token"]
        expires: int = response["expiration"]
        # pylint: disable=protected-access
        tok_expires_ns = domain_token._validate_token_sig(
            hccplatform.TEST_DOMREG_KEY,
            hccplatform.HCC_DOMAIN_TYPE,
            conftest.ORG_ID,
            token,
        )
        tok_expires = int(tok_expires_ns / 1_000_000_000)
        self.assertEqual(expires, tok_expires)


class TestDomRegToken(unittest.TestCase):
    token = "F3n-iOZn1VI.wbzIH7v-kRrdvfIvia4nBKAvEpIKGdv6MSIFXeUtqVY"  # noqa: S105
    domain_id = uuid.UUID("7b160558-8273-5a24-b559-6de3ff053c63")
    expires = 1691662998988903762
    org_id = "123456"
    key = b"secretkey"

    def test_domain_id(self):
        self.assertEqual(
            domain_token.token_domain_id(self.token), self.domain_id
        )

    def test_generate_token(self):
        # pylint: disable=protected-access
        token = domain_token._generate_token_ns(
            self.key, hccplatform.HCC_DOMAIN_TYPE, self.org_id, self.expires
        )
        self.assertEqual(token, self.token)
        token, expires = domain_token.generate_token(
            self.key, hccplatform.HCC_DOMAIN_TYPE, self.org_id
        )
        self.assertEqual(
            domain_token._validate_token_sig(
                self.key, hccplatform.HCC_DOMAIN_TYPE, self.org_id, token
            ),
            expires,
        )

    def test_validate_token(self):
        # pylint: disable=protected-access
        expires = domain_token._validate_token_sig(
            self.key, hccplatform.HCC_DOMAIN_TYPE, self.org_id, self.token
        )
        self.assertEqual(expires, self.expires)
        with self.assertRaisesRegex(ValueError, "Invalid signature"):
            domain_token.validate_token(
                self.key, hccplatform.HCC_DOMAIN_TYPE, "789789", self.token
            )
        with self.assertRaisesRegex(ValueError, "token expired"):
            domain_token.validate_token(
                self.key, hccplatform.HCC_DOMAIN_TYPE, self.org_id, self.token
            )

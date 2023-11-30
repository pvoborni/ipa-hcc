import json
from unittest import mock

import conftest
from ipahcc import hccplatform, sign
from ipahcc.registration import wsgi

PRIV_KEY = sign.generate_private_key()
PUB_KEY = sign.get_public_key(PRIV_KEY)


class TestRegistrationWSGI(conftest.IPAWSGIBaseTests):
    wsgi_class = wsgi.Application

    def setUp(self):
        super().setUp()

        p = mock.patch.object(self.app, "_get_ipa_jwkset")
        self.m_get_jwkset = p.start()
        self.m_get_jwkset.return_value = PUB_KEY
        self.addCleanup(p.stop)

    def test_ipaapi(self):
        app = self.app
        api = self.m_api

        api.isdone.return_value = False
        api.Backend.rpcclient.isconnected.return_value = False
        app.before_call()
        self.m_gss_credentials.assert_called_once()
        api.finalize.assert_called()
        api.Backend.rpcclient.connect.assert_called_once()

        api.isdone.return_value = True
        api.Backend.rpcclient.isconnected.return_value = True
        app.after_call()
        api.Backend.rpcclient.disconnect.assert_called_once()

    def test_register(self):
        self.m_api.return_value = mock.Mock(
            return_value=(
                "rid",
                200,
                "OK",
                "url",
                {"content-type": "application/json"},
                json.dumps({"inventory_id": conftest.CLIENT_INVENTORY_ID}),
                0,
                "",
            )
        )
        tok = sign.generate_host_token(
            PRIV_KEY,
            cert_o=conftest.ORG_ID,
            cert_cn=conftest.CLIENT_RHSM_ID,
            inventory_id=conftest.CLIENT_INVENTORY_ID,
            fqdn=conftest.CLIENT_FQDN,
            domain_id=conftest.DOMAIN_ID,
        )
        body = {
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_name": conftest.DOMAIN,
            "domain_id": conftest.DOMAIN_ID,
            "token": tok.serialize(compact=False),
        }
        path = "/".join(
            ("", conftest.CLIENT_INVENTORY_ID, conftest.CLIENT_FQDN)
        )
        status_code, status_msg, headers, response = self.call_wsgi(
            path=path, body=body
        )

        self.assert_response(200, status_code, status_msg, headers, response)
        self.assertEqual(
            response,
            {
                "status": "ok",
                "kdc_cabundle": conftest.KDC_CA_DATA,
            },
        )

        app = self.app
        self.assertEqual(app.org_id, conftest.ORG_ID)
        self.assertEqual(app.domain_id, conftest.DOMAIN_ID)

        host_add = self.m_api.Command.host_add
        host_add.assert_called_once()
        args, kwargs = host_add.call_args
        self.assertEqual(
            args,
            (conftest.CLIENT_FQDN,),
        )
        self.assertEqual(
            kwargs,
            {
                "force": True,
                "hccinventoryid": conftest.CLIENT_INVENTORY_ID,
                "hccsubscriptionid": conftest.CLIENT_RHSM_ID,
            },
        )

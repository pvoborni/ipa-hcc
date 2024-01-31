"""Integration tests for ipaserver plugins

Tests must be executed on an IPA server with ipahcc plugins. Current user must
be root or enrollment agent user.

Run::
    # python3 -m unittest -v tests/test_ipaserver_integration.py
"""

import datetime
import os
import unittest

from ipalib import api, errors
from ipalib.facts import is_ipa_configured

from ipahcc import hccplatform, sign


@unittest.skipUnless(is_ipa_configured(), "host is not an IPA server")
class TestIPAServerIntegration(unittest.TestCase):  # pragma: no cover
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        # Let gssproxy handle Kerberos/GSSAPI auth for us
        os.environ["GSS_USE_PROXY"] = "1"
        # in-memory ccache
        os.environ["KRB5CCNAME"] = "MEMORY:"
        if os.geteuid() == 0:
            # set euid so gssproxy authentication works
            user = hccplatform.HCC_ENROLLMENT_AGENT_USER
            os.setegid(user.pgid)
            os.seteuid(user.uid)
        # bootstrap and finalize API
        if not api.isdone("bootstrap"):
            api.bootstrap(
                force_schema_check=True,
                in_server=False,
                log=None,
                context="hcc",
            )
        if not api.isdone("finalize"):
            api.finalize()
        api.Backend.rpcclient.connect()

    @classmethod
    def tearDownClass(cls):
        if api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.disconnect()

    def test_00service_whoami(self):
        result = api.Command.whoami()
        svc = hccplatform.HCC_ENROLLMENT_AGENT
        expected = f"{svc}/{api.env.host}@{api.env.realm}"
        self.assertEqual(result["arguments"][0], expected)

    def test_config_show(self):
        result = api.Command.config_show()["result"]
        self.assertIn(api.env.host, result["hcc_enrollment_server_server"])
        self.assertIn(api.env.host, result["hcc_enrollment_agent_server"])
        self.assertIn("hcc_update_server_server", result)
        self.assertTrue(result["hccdomainid"])
        self.assertTrue(result["hccorgid"])

    def hccjwk_del(self, kid):
        try:
            api.Command.hccjwk_del(kid)
        except errors.NotFound:
            return False
        else:
            return True

    def test_hccjwk(self):
        start_result = api.Command.hccjwk_find()

        pkey = sign.generate_private_key()
        jwk = sign.get_public_key(pkey)
        kid: str = jwk["kid"]
        notafter = datetime.datetime.fromtimestamp(jwk["exp"])
        jwkstr: str = jwk.export_public()
        jwkrecord = {
            "cn": (kid,),
            "algorithmid": ("ES256",),
            "ipatokennotafter": (notafter,),
            "ipaenabledflag": (True,),
            "ipakeyusage": ("sig",),
            "hccpublicjwk": (jwkstr,),
            "state": ("valid",),
            "dn": f"cn={kid},cn=jwk,cn=hcc,cn=etc,{api.env.basedn}",
        }

        # remove key after tests
        self.addCleanup(self.hccjwk_del, kid)
        # add key
        result = api.Command.hccjwk_add(hccpublicjwk=jwkstr)
        r = result["result"]
        r.pop("objectclass")
        self.assertEqual(r, jwkrecord)
        # find key
        result = api.Command.hccjwk_find()
        for r in result["result"]:
            if r["cn"] == (kid,):
                self.assertEqual(r, jwkrecord)
            break
        else:
            self.fail(f"{kid} not found in {result}")

        # show one record
        result = api.Command.hccjwk_show(kid)
        self.assertEqual(result["result"], jwkrecord)

        # revoke
        revoked = jwkrecord.copy()
        revoked.update(
            {
                "hccpublicjwk": ("<revoked>",),
                "ipaenabledflag": (False,),
                "state": ("revoked",),
            }
        )
        result = api.Command.hccjwk_revoke(kid)
        self.assertEqual(result["result"], revoked)
        result = api.Command.hccjwk_show(kid)
        self.assertEqual(result["result"], revoked)

        # valid skips revoked JWKs
        result = api.Command.hccjwk_find(valid=True)
        self.assertEqual(result, start_result)

import time
import unittest
from unittest import mock

import jwcrypto.jwk
import jwcrypto.jws
import jwcrypto.jwt

import conftest
from ipahcc import sign


class TestJWK(unittest.TestCase):
    def test_jwk(self):
        priv = sign.generate_private_key()
        self.assertTrue(priv.has_private)
        self.assertIsInstance(priv, sign.JWKDict)
        self.assertEqual(
            sorted(priv),
            ["alg", "crv", "d", "exp", "kid", "kty", "use", "x", "y"],
        )

        pub = sign.get_public_key(priv)
        self.assertFalse(pub.has_private)
        self.assertIsInstance(pub, sign.JWKDict)
        self.assertEqual(
            sorted(pub), ["alg", "crv", "exp", "kid", "kty", "use", "x", "y"]
        )

        self.assertRaises(NotImplementedError, pub.export)
        self.assertEqual(pub.get("crv"), pub["crv"])
        self.assertEqual(pub.get("missing"), None)
        self.assertEqual(pub.get("missing", False), False)

        raw_priv = priv.export_private()
        self.assertIsInstance(raw_priv, str)
        raw_pub = pub.export_public()
        self.assertIsInstance(raw_pub, str)

        priv2 = sign.load_key(raw_priv)
        pub2 = sign.load_key(raw_pub)

        exp = priv["exp"]
        self.assertIsInstance(exp, int)
        kid = priv["kid"]
        self.assertIsInstance(kid, str)

        for key in (priv, pub, priv2, pub2):
            self.assertIsInstance(key, jwcrypto.jwk.JWK)
            self.assertTrue(priv.has_public)
            self.assertEqual(key["kid"], kid)
            self.assertEqual(key["exp"], exp)
            self.assertEqual(key["crv"], "P-256")
            self.assertEqual(key["alg"], "ES256")
            if key.has_private:
                self.assertIn("d", key)
            else:
                self.assertNotIn("d", key)

    def assert_load_key(self, key: sign.JWKDict, msg: str):
        raw_key = key.export_public()
        with self.assertRaisesRegex(sign.InvalidKey, msg):
            sign.load_key(raw_key)

    def test_jwk_validate(self):
        priv = sign.generate_private_key()
        pub = sign.get_public_key(priv)

        pub["exp"] = time.time() - 60
        with self.assertRaises(sign.ExpiredKey):
            self.assert_load_key(pub, "key has expired")

        del pub["exp"]
        self.assert_load_key(pub, "'exp' is missing")

        pub["use"] = "invalid"
        self.assert_load_key(pub, "Invalid key usage")
        del pub["use"]
        self.assert_load_key(pub, "'use' is missing")

        del pub["kid"]
        self.assert_load_key(pub, "Missing key identifier")


class TestJWST(unittest.TestCase):
    def generate_token(
        self,
        key,
        cert_o=conftest.ORG_ID,
        cert_cn=conftest.CLIENT_RHSM_ID,
        inventory_id=conftest.CLIENT_INVENTORY_ID,
        fqdn=conftest.CLIENT_FQDN,
        domain_id=conftest.DOMAIN_ID,
        **kwargs,
    ):
        return sign.generate_host_token(
            key, cert_o, cert_cn, inventory_id, fqdn, domain_id, **kwargs
        )

    def validate_token(
        self,
        tok,
        key,
        cert_o=conftest.ORG_ID,
        cert_cn=conftest.CLIENT_RHSM_ID,
        inventory_id=conftest.CLIENT_INVENTORY_ID,
        fqdn=conftest.CLIENT_FQDN,
        domain_id=conftest.DOMAIN_ID,
        **kwargs,
    ):
        return sign.validate_host_token(
            tok,
            key,
            cert_o=cert_o,
            cert_cn=cert_cn,
            inventory_id=inventory_id,
            fqdn=fqdn,
            domain_id=domain_id,
            **kwargs,
        )

    def test_jwt_single_sig(self):
        priv1 = sign.generate_private_key()
        pub1 = sign.get_public_key(priv1)

        tok = self.generate_token(priv1)
        self.assertIsInstance(tok, jwcrypto.jwt.JWT)
        self.assertIsInstance(tok, sign.MultiJWST)

        with self.assertRaises(ValueError):
            tok.serialize(compact=True)

        j = tok.serialize(compact=False)
        self.assertIsInstance(j, str)
        self.assertIsInstance(sign.json_decode(j), dict)

        self.validate_token(j, pub1)

        pub_set = sign.JWKSet()
        pub_set.add(pub1)
        self.validate_token(j, pub_set)

        priv2 = sign.generate_private_key()
        pub2 = sign.get_public_key(priv2)
        other_set = sign.JWKSet()
        other_set.add(pub2)

        with self.assertRaises(jwcrypto.jwt.JWTMissingKey):
            self.validate_token(j, other_set)

    def test_jwt_multi_sig_serialize(self):
        priv1 = sign.generate_private_key()
        pub1 = sign.get_public_key(priv1)
        priv2 = sign.generate_private_key()
        pub2 = sign.get_public_key(priv2)
        priv3 = sign.generate_private_key()
        pub3 = sign.get_public_key(priv3)

        priv_set = sign.JWKSet()
        priv_set.add(priv1)
        priv_set.add(priv2)

        pub_set = sign.JWKSet()
        pub_set.add(pub1)
        pub_set.add(pub2)

        other_set = sign.JWKSet()
        other_set.add(pub3)

        tok = self.generate_token(priv_set)

        i = tok.serialize(compact=False)
        tok.deserialize(i, pub_set)

    def test_jwt_multi_sig_validate(self):
        priv1 = sign.generate_private_key()
        pub1 = sign.get_public_key(priv1)
        priv2 = sign.generate_private_key()
        pub2 = sign.get_public_key(priv2)
        priv3 = sign.generate_private_key()
        pub3 = sign.get_public_key(priv3)

        priv_set = sign.JWKSet()
        priv_set.add(priv1)
        priv_set.add(priv2)

        pub_set = sign.JWKSet()
        pub_set.add(pub1)
        pub_set.add(pub2)

        other_set = sign.JWKSet()
        other_set.add(pub3)

        tok = self.generate_token(priv_set)

        j = tok.serialize(compact=False)
        self.validate_token(j, pub1)
        self.validate_token(j, pub2)
        self.validate_token(j, pub_set)

        with self.assertRaises(jwcrypto.jws.InvalidJWSSignature):
            self.validate_token(j, pub3)
        with self.assertRaises(jwcrypto.jwt.JWTMissingKey):
            self.validate_token(j, other_set)

    def test_jwt_multi_compact_disallowed(self):
        priv = sign.generate_private_key()
        pub = sign.get_public_key(priv)

        tok = sign.MultiJWST()
        with self.assertRaises(ValueError):
            tok.deserialize("compact.not.supported", pub)

    def test_jwt_claim_mismatch(self):
        # compact JWT with single signature
        priv = sign.generate_private_key()
        pub = sign.get_public_key(priv)
        tok = self.generate_token(priv, fqdn="client.other.test")

        with self.assertRaises(jwcrypto.jwt.JWTInvalidClaimValue):
            self.validate_token(tok.serialize(), pub)
        with self.assertRaises(jwcrypto.jwt.JWTInvalidClaimValue):
            self.validate_token(tok.serialize(compact=False), pub)

    def test_jwt_time(self):
        # compact JWT with single signature
        priv = sign.generate_private_key()
        pub = sign.get_public_key(priv)
        tok = self.generate_token(priv, fqdn="client.other.test")

        now = time.time()

        with mock.patch("time.time") as m_time:
            m_time.return_value = now - 70
            with self.assertRaises(jwcrypto.jwt.JWTNotYetValid):
                self.validate_token(tok.serialize(), pub)

            m_time.return_value = now + 900
            with self.assertRaises(jwcrypto.jwt.JWTExpired):
                self.validate_token(tok.serialize(), pub)

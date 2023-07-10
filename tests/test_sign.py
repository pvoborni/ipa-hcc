import time
import unittest

import jwcrypto.jwk

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
        self.assert_load_key(pub, "key has expired")
        del pub["exp"]
        self.assert_load_key(pub, "'exp' is missing")

        pub["use"] = "invalid"
        self.assert_load_key(pub, "Invalid key usage")
        del pub["use"]
        self.assert_load_key(pub, "'use' is missing")

        del pub["kid"]
        self.assert_load_key(pub, "Missing key identifier")

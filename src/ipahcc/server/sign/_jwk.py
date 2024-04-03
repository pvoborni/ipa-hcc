"""JSON Web Key (JWK)

- only key type (kty) "EC"
- 'crv' must be "P-256" (fast, FIPS approved curve)
- key identifier (kid) is set to truncated thumbprint
- 'use' is set to 'sig' (signing)
- additional key 'exp' with key expiration time
"""

import enum
import time
import typing

from jwcrypto import jwk
from jwcrypto.common import (
    JWException,
    json_decode,
    json_encode,
)

__all__ = (
    "JWKDict",
    "JWKSet",
    "InvalidKey",
    "get_public_key",
    "load_key",
)


class KeyState(str, enum.Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


# EC key curve to algorithm mapping
KTY = "EC"
CRV = "P-256"
CRV_TO_ALG = {
    "P-256": "ES256",
    # "P-384": "ES384",
}
SUPPORTED_ALGS = list(CRV_TO_ALG.values())

JWKSet = jwk.JWKSet

JWKBase: jwk.JWK

if hasattr(jwk.JWK, "get"):
    # modern JWK implementation with dict interface
    JWKBase = jwk.JWK
else:

    class JWKBase(jwk.JWK):  # type: ignore
        """A forward-compatible JWK subclass with dict interface

        The JWK implementation of jwcrypto <= 0.8 (RHEL 8, 9) does not have
        a dict-like interface and its export functions do not support
        `as_dict` argument.
        """

        if typing.TYPE_CHECKING:
            _params: typing.Dict[str, typing.Any]
            _key: typing.Dict[str, typing.Any]
            _unknown: typing.Dict[str, typing.Any]

        def _get_dict(self, key: str) -> dict:
            if key in jwk.JWKParamsRegistry:
                return self._params
            elif key in jwk.JWKValuesRegistry[self._params["kty"]]:
                return self._key
            else:
                return self._unknown

        def __setitem__(self, key: str, value: typing.Any) -> None:
            dct = self._get_dict(key)
            dct[key] = value

        def __getitem__(self, key: str) -> typing.Any:
            dct = self._get_dict(key)
            return dct[key]

        def __delitem__(self, key: str):
            dct = self._get_dict(key)
            del dct[key]

        def __eq__(self, other):
            if not isinstance(other, JWKBase):
                return NotImplemented

            return self.thumbprint() == other.thumbprint() and self.get(
                "kid"
            ) == other.get("kid")

        def __hash__(self):
            return hash((self.thumbprint(), self.get("kid")))

        def get(self, key, default=None):
            try:
                return self[key]
            except KeyError:
                return default

        def __contains__(self, key: str) -> bool:
            try:
                self[key]
            except KeyError:
                return False
            else:
                return True

        def __iter__(self):
            yield from self._params
            yield from self._key
            yield from self._unknown

        def export_public(self, as_dict=False):
            """Exports the public key in the standard JSON format."""
            if not self.has_public:
                raise jwk.InvalidJWKType("No public key available")
            pub = self._public_params()
            if as_dict:
                return pub
            return json_encode(pub)

        def export_private(self, as_dict=False):
            """Export the private key in the standard JSON format."""
            if not self.has_private:
                raise jwk.InvalidJWKType("No private key available")
            return self._export_all(as_dict)

        def _export_all(self, as_dict=False):
            d = {}
            d.update(self._params)
            d.update(self._key)
            d.update(self._unknown)
            if as_dict:
                return d
            return json_encode(d)


# modern JWK implementation with dict interface
class JWKDict(JWKBase):  # type: ignore
    def _public_params(self):
        """Export all parameters except private key values

        The original implementation only exports known public attributes.
        """
        d = self._export_all(as_dict=True)
        # pop private key members (if set)
        reg = jwk.JWKValuesRegistry[d["kty"]]
        for name, param in reg.items():
            if not param.public:
                d.pop(name, None)
        return d

    def export(self, private_key=True, as_dict=False):
        # use export_public() or export_private()
        raise NotImplementedError


class InvalidKey(JWException):
    def __init__(
        self,
        key: JWKDict,
        name: str,
        msg: str,
    ):
        super().__init__(msg)
        self.key = key
        self.name = name
        self.msg = msg


class ExpiredKey(JWException):
    def __init__(self, key: JWKDict):
        msg = f"key {key['kid']} has expired"
        super().__init__(msg)
        self.key = key
        self.name = "exp"
        self.msg = msg


def get_public_key(priv_key: JWKDict) -> JWKDict:
    """Convert a private JWK to a public JWK"""
    pub_key = priv_key.export_public(as_dict=True)
    return JWKDict(**pub_key)


def load_key(raw_key: str) -> JWKDict:
    """Load JWK from serialized JSON string

    Supports both public and private keys.
    """
    dct = json_decode(raw_key)  # type: dict
    key = JWKDict(**dct)
    validate_key(key)
    return key


def validate_key(key: JWKDict) -> None:
    """Validate properties of a JWKDict

    Properties: kid, kty, crv, use, exp
    """
    kid = key.get("kid")
    if not kid:
        raise InvalidKey(key, "kid", "Missing key identifier (kid)")

    if key["kty"] != KTY:
        raise InvalidKey(key, "kty", "Unsupported key type.")
    alg = CRV_TO_ALG.get(key["crv"])
    if not alg:
        raise InvalidKey(key, "crv", "Unsupported EC curve.")
    if key.get("alg") != alg:
        raise InvalidKey(key, "alg", "Unsupported or missing algorithm.")

    # jwcrypto ensure consistency between use and key_ops
    if "use" not in key:
        raise InvalidKey(key, "use", "Key usage 'use' is missing.")
    if key["use"] != "sig":
        raise InvalidKey(key, "use", "Invalid key usage, expected 'sig'.")
    # exp is not standardized in RFC 7517, but commonly used
    if "exp" not in key:
        raise InvalidKey(key, "exp", "Key expiration 'exp' is missing.")
    if time.time() > key["exp"]:
        raise ExpiredKey(key)


def generate_private_key(*, crv=CRV, validity: int = 90 * 86400) -> JWKDict:
    """Generate private JWK (for testing purposes only)"""
    priv = JWKDict(
        generate="EC",
        crv=crv,
        use="sig",
        alg=CRV_TO_ALG[crv],
        exp=int(time.time() + validity),
    )
    # truncated thumbprint of public key
    # RFC 7517, 8.1.1, recommends up to 8 chars
    priv["kid"] = priv.thumbprint()[:8]
    return priv

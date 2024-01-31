"""Signed JSON Web Token

JWT must be signed (JWS):
  - headers "kid" and "alg" must be set
  - alg is always "ES256" (ECDSA signature with SHA-256)

Registered claims:
  - issuer (iss) must be "idmsvc/v1"
  - subject (sub) is RHSM cert subject "CN"
  - aud (audience) must be "register host"
  - expiration (exp), not before (nbf), and issued at (iat) must be set
  - JWT ID (jti) must be set (6 random bytes, URL-safe base64)

Additional private claims:
  - "rhorg" (string) is set to RHSM cert subject "O"
  - "rhinvid" (string) is host-based inventory uuid
  - "rhdomid" (string) HMSIDM domain id
  - "rhfqdn" (string) hosts' fully qualified domain name
"""

import base64
import os
import typing

from jwcrypto import jws, jwt
from jwcrypto.common import (
    JWException,
    json_decode,
)

from ._jwk import CRV_TO_ALG, SUPPORTED_ALGS, JWKDict, JWKSet

ISSUER = "idmsvc/v1"
AUD_JOIN_HOST = "join host"
CLAIM_ORG_ID = "rhorg"
CLAIM_DOMAIN_ID = "rhdomid"
CLAIM_FQDN = "rhfqdn"
CLAIM_INVENTORY_ID = "rhinvid"

CHECKED_HOST_CLAIMS = {
    ## JWT registered claims
    # issuer (StringOrURI)
    "iss": ISSUER,
    # subject StringOrURI, will be set to cert subject CN
    "sub": None,
    # audience (array of StringOrURI), our value must match one entry
    "aud": AUD_JOIN_HOST,
    # date: expires, not before, issued at (automatically set)
    "exp": None,
    "nbf": None,
    "iat": None,
    # claim identifier (uuid string), automatically set
    "jti": None,
    ## private claims
    # cert subject org (O) (string)
    CLAIM_ORG_ID: None,
    # host-based inventory id (uuid string)
    CLAIM_INVENTORY_ID: None,
    # client's fqdn (str)
    CLAIM_FQDN: None,
    # domain_id (uuid string)
    CLAIM_DOMAIN_ID: None,
}  # type: typing.Dict[str, typing.Union[str, int, typing.List[str], None]]


class MultiJWST(jwt.JWT):
    """Extended JWT that supports multiple signatures

    Technically RFC 7519 conform JWTs must be in compact notation and can
    only have a signature. This implementation can create non-standard
    signed token (JWS token) with multiple signatures. Verification
    ensures that at least one key from a JWKSet can be verified.
    """

    if typing.TYPE_CHECKING:
        claims: typing.Dict[str, typing.Any]
        header: typing.Dict[str, typing.Any]

    def make_signed_token(self, key: typing.Union[JWKDict, JWKSet]) -> None:
        """Signs the payload."""
        t = jws.JWS(self.claims)
        if self._algs:
            t.allowed_algs = self._algs

        if isinstance(key, JWKDict):
            t.add_signature(key, protected=self.header)
        elif isinstance(key, JWKSet):
            for k in key:
                try:
                    header = self.header.copy()
                except (KeyError, ValueError):
                    header = {}
                header["alg"] = k["alg"]
                header["kid"] = k["kid"]
                t.add_signature(k, protected=header)
        else:
            raise TypeError(key)

        self.token = t

    def make_encrypted_token(self, key):  # pragma: no cover
        raise NotImplementedError

    def serialize(self, compact=False):
        """Serializes the object into a JWS token.

        Generates a standard JSON format. `compact` must be False as jwcrpyto
        doesn't support the compact form with multiple signatures.
        """

        if compact:
            raise ValueError(
                "Can't use compact encoding with multiple signatures"
            )

        return self.token.serialize(compact)

    # Parameter 'jwt' has been renamed to 'tok' in overriding
    # 'MultiJWST.deserialize' method
    def deserialize(
        self,
        # pylint: disable=arguments-renamed
        tok: str,
        key=typing.Union[JWKDict, JWKSet],
    ) -> None:
        """Deserialize a JWT JSON token.

        If a key is provided a verification step will be attempted after
        the object is successfully deserialized.

        The deserialization of the compact form is not supported using multiple
        signatures in jwcrypto.
        """
        if isinstance(tok, str) and tok.startswith("{"):
            tok_dict = json_decode(tok)
            tok_str = tok
        else:
            # Compact notation is not supported.
            raise ValueError("'tok' must be a serialized JSON object.")

        # see RFC 7516, section 9
        if "payload" in tok_dict:
            self.token = jws.JWS()
        elif "ciphertext" in tok_dict:  # pragma: no cover
            # ipahcc does not use JWE
            raise NotImplementedError("JWE support is not implemented")
        else:  # pragma: no cover
            raise ValueError(f"Token format unrecognized: {tok}")

        # Apply algs restrictions if any, before performing any operation
        if self._algs:
            self.token.allowed_algs = self._algs

        self.deserializelog = []
        # now deserialize and also decrypt/verify (or raise) if we
        # have a key
        success_key = None
        if key is None:  # pragma: no cover
            self.token.deserialize(tok_str, None)
        elif isinstance(key, JWKDict):
            self.token.deserialize(tok_str, key)
            success_key = key
            self.deserializelog.append("Success")
        elif isinstance(key, JWKSet):
            self.token.deserialize(tok, None)
            if "kid" in self.token.jose_header:
                # single-signature / compact JWT
                keyid = self.token.jose_header["kid"]
                kid_key = key.get_key(keyid)
                if not kid_key:
                    raise jwt.JWTMissingKey(f"Key ID {keyid} not in key set")
                self.token.deserialize(tok, kid_key)
                success_key = kid_key
            else:
                for k in key:
                    try:
                        self.token.deserialize(tok, k)
                        self.deserializelog.append("Success")
                        success_key = k
                        break
                    except Exception as e:  # pylint: disable=broad-except
                        self.deserializelog.append(
                            "Key [%s] failed: [%s]" % (k["kid"], repr(e))
                        )
                        continue
                if "Success" not in self.deserializelog:
                    raise jwt.JWTMissingKey("No working key found in key set")
        else:
            raise ValueError("Unrecognized Key Type")

        if success_key is not None:
            kid = success_key.get("kid")
            if isinstance(self.token.jose_header, list):
                # multi-signature JWTs have a list of header
                # pick header that matches our key
                for hdr in self.token.jose_header:
                    if hdr["kid"] == kid:
                        self.header = hdr
                        break
                else:
                    raise ValueError(
                        f"jose_header is missing entry for {kid}."
                    )
            else:
                self.header = self.token.jose_header
            self.claims = self.token.payload.decode("utf-8")
            self._check_provided_claims()


class InvalidToken(JWException):
    pass


def validate_host_token(
    raw_token: str,
    pub_key: typing.Union[JWKDict, JWKSet],
    cert_o: str,
    cert_cn: str,
    inventory_id: str,
    fqdn: str,
    domain_id: str,
    validity: int = 10 * 60,
    leeway: int = 60,
) -> typing.Tuple[dict, dict]:
    if isinstance(pub_key, JWKDict):
        assert not pub_key.has_private
    else:
        assert all(not k.has_private for k in pub_key)
    # str values must be equal, "aud" must match one element
    # "exp" and "nbf" are validated using current time, validity and leeway
    # other None values are checked for presence (e.g. "idm_inventory_id")
    check_claims = CHECKED_HOST_CLAIMS.copy()
    check_claims.update(
        {
            "sub": cert_cn,
            CLAIM_ORG_ID: cert_o,
            CLAIM_INVENTORY_ID: inventory_id,
            CLAIM_FQDN: fqdn,
            CLAIM_DOMAIN_ID: domain_id,
        }
    )

    t = MultiJWST(check_claims=check_claims, algs=SUPPORTED_ALGS)
    t.validity = validity
    t.leeway = leeway
    t.deserialize(raw_token, pub_key)
    return json_decode(t.header), json_decode(t.claims)


def generate_host_token(
    key: typing.Union[JWKDict, JWKSet],
    cert_o: str,
    cert_cn: str,
    inventory_id: str,
    fqdn: str,
    domain_id: str,
    validity: int = 10 * 60,
) -> jwt.JWT:
    """Generate a signed token (for testing purposes only)"""
    if isinstance(key, JWKDict):
        assert key.has_private
        assert key["kty"] == "EC"
        header = {"kid": key["kid"], "alg": CRV_TO_ALG[key["crv"]]}
    else:
        assert all(k.has_private for k in key)
        assert all(k["kty"] == "EC" for k in key)
        header = {}
    default_claims = CHECKED_HOST_CLAIMS.copy()
    # aud should be an array
    default_claims["aud"] = [AUD_JOIN_HOST]

    t = MultiJWST(
        header=header, default_claims=default_claims, algs=SUPPORTED_ALGS
    )
    t.validity = validity
    t.claims = {
        "sub": cert_cn,
        CLAIM_ORG_ID: cert_o,
        CLAIM_INVENTORY_ID: inventory_id,
        CLAIM_FQDN: fqdn,
        CLAIM_DOMAIN_ID: domain_id,
        # use 6 random bytes -> 8 characters as random id
        # Our tokens are valid for mere hours, 48 random bits are sufficient.
        "jti": base64.urlsafe_b64encode(os.urandom(6)).decode("ascii"),
    }
    t.make_signed_token(key)
    return t

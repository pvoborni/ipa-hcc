"""Mock API endpoints

The WSGI service provides a minimalistic implementation of /host-conf/ API
endpoints. It has to be installed on an IPA server with
ipa-hcc-registration-service. The mockapi performs minimal checks.

NOTE: The WSGI app does not use any frameworks such as FastAPI or Flask
to reduce dependencies on RHEL. This makes the code is unnecessary
complicated and someward fragile, too. Works well enough for local
testing, though.
"""

import logging
import typing
from time import monotonic as monotonic_time

import requests
from ipalib import errors
from ipaplatform.paths import paths

from ipahcc import hccplatform, sign
from ipahcc.server.framework import UUID_RE, HTTPException, JSONWSGIApp, route

from . import domain_token

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-mockapi")
logger.setLevel(logging.DEBUG)


class Application(JSONWSGIApp):
    def __init__(self, api=None) -> None:
        super().__init__(api=api)
        # inventory bearer token + validity timestamp
        self.access_token: typing.Optional[str] = None
        self.valid_until: int = 0
        # requests session for persistent HTTP connection
        self.session = requests.Session()
        self.session.headers.update(hccplatform.HTTP_HEADERS)

    # _connect_ipa is called on demand
    # def before_call(self) -> None:
    #     self._connect_ipa()

    def _load_priv_jwk(self) -> typing.Optional[sign.JWKDict]:
        logger.info(
            "Loading mockapi JWK from %s", hccplatform.MOCKAPI_PRIV_JWK
        )
        try:
            with open(hccplatform.MOCKAPI_PRIV_JWK, "r", encoding="utf-8") as f:
                return sign.load_key(f.read())
        except OSError:
            logger.exception("Unable to load %s", hccplatform.MOCKAPI_PRIV_JWK)
            return None

    def get_access_token(self) -> str:  # pragma: no cover
        """Get a bearer access token from an offline token

        TODO: Poor man's OAuth2 workflow. Replace with
        requests-oauthlib.

        https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#refreshing-tokens
        """
        # use cached access token
        if self.access_token and monotonic_time() < self.valid_until:
            return self.access_token

        refresh_token_file = hccplatform.REFRESH_TOKEN_FILE
        try:
            with open(refresh_token_file, encoding="utf-8") as f:
                refresh_token = f.read().strip()
        except OSError as e:
            logger.error(
                "Unable to read refresh token from '%s': %s",
                refresh_token_file,
                e,
            )
            raise

        data = {
            "grant_type": "refresh_token",
            "client_id": hccplatform.TOKEN_CLIENT_ID,
            "refresh_token": refresh_token,
        }
        url = hccplatform.CONFIG.token_url
        start = monotonic_time()
        resp = self.session.post(url, data)
        dur = monotonic_time() - start
        if resp.status_code >= 400:
            raise HTTPException(
                resp.status_code,
                f"get_access_token() failed: {resp} {resp.content!r} ({url})",
            )
        logger.debug(
            "Got access token from refresh token in %0.3fs.",
            dur,
        )
        j = resp.json()
        self.access_token = j["access_token"]
        # 10 seconds slack
        self.valid_until = monotonic_time() + j["expires_in"] - 10
        if typing.TYPE_CHECKING:
            assert self.access_token
        return self.access_token

    def lookup_inventory(
        self, inventory_id: str, rhsm_id: str, access_token: str
    ) -> typing.Tuple[str, str, str]:
        """Lookup host by its inventory_id

        Returns fqdn, inventory_id, rhsm_id
        """
        # cannot lookup from .../hosts/{inventory_id}, RHEL 7 does not include
        # subscription_manager_id in return value.
        url = "/".join((hccplatform.CONFIG.inventory_api_url.rstrip("/"), "hosts"))
        logger.debug(
            "Looking up inventory id %s / rhsm %s in console inventory %s",
            inventory_id,
            rhsm_id,
            url,
        )
        headers = {"Authorization": f"Bearer {access_token}"}
        params = {"filter[system_profile][owner_id]": rhsm_id}
        start = monotonic_time()
        resp = self.session.get(url, params=params, headers=headers)
        dur = monotonic_time() - start
        if resp.status_code >= 400:
            # reset access token
            self.access_token = None
            raise HTTPException(
                resp.status_code,
                f"lookup_inventory() failed: {resp.reason}",
            )

        j = resp.json()
        if j["total"] != 1:
            raise HTTPException(
                404,
                f"Unknown host {inventory_id}.",
            )
        result = j["results"][0]
        fqdn = result["fqdn"]
        rhsm_id = result["subscription_manager_id"]
        inventory_id = result["id"]
        logger.debug(
            "Got result for %s (%s, %s) in %0.3fs",
            fqdn,
            inventory_id,
            rhsm_id,
            dur,
        )
        return fqdn, inventory_id, rhsm_id

    def check_inventory(
        self, inventory_id: str, fqdn: str, rhsm_id: str
    ) -> None:
        if not fqdn.endswith(self.api.env.domain):
            raise HTTPException(404, "hostname not recognized")

        access_token = self.get_access_token()
        exp_fqdn, exp_id, exp_rhsm_id = self.lookup_inventory(
            inventory_id, rhsm_id, access_token=access_token
        )
        if fqdn != exp_fqdn:
            raise HTTPException(
                400,
                f"unexpected fqdn: {fqdn} != {exp_fqdn}",
            )
        if inventory_id != exp_id:
            raise HTTPException(
                400,
                f"unexpected inventory_id: {inventory_id} != {exp_id}",
            )
        # RHEL 7.9 clients have subscription_manager_id == None
        if exp_rhsm_id is not None and rhsm_id != exp_rhsm_id:
            raise HTTPException(
                400,
                f"unexpected RHSM id: {rhsm_id} != {exp_rhsm_id}",
            )

    def get_ca_certs(self) -> str:
        with open(paths.IPA_CA_CRT, encoding="utf-8") as f:
            ipa_ca_pem = f.read()
        return ipa_ca_pem

    @route("GET", "^/$")
    def handle_root(  # pylint: disable=unused-argument
        self, env: dict, body: dict
    ) -> dict:
        return {}

    @route("GET", "^/signing_keys$")
    def handle_keys(  # pylint: disable=unused-argument
        self, env: dict, body: dict
    ) -> dict:
        if not self._is_connected():
            self._connect_ipa()
        jwkset = self._get_ipa_jwkset()
        keys = [jwk.export_public() for jwk in jwkset]
        return {"keys": keys, "revoked_kids": ["bad key id"]}

    @route(
        "POST",
        f"^/host-conf/(?P<inventory_id>{UUID_RE})/(?P<fqdn>[^/]+)$",
        schema="HostConf",
    )
    def handle_host_conf(  # pylint: disable=unused-argument
        self, env: dict, body: dict, inventory_id: str, fqdn: str
    ) -> dict:
        org_id, rhsm_id = self.parse_cert(env)

        if not self._is_connected():
            self._connect_ipa()
        if self.domain_id is None:
            raise HTTPException(
                400, "domain is not registered (no domain_id in LDAP)"
            )
        if self.org_id is not None and org_id != self.org_id:
            raise HTTPException(
                400, f"Invalid org_id: {org_id} != {self.org_id}"
            )
        priv_key = self._load_priv_jwk()
        if priv_key is None:
            raise HTTPException(
                500, "unable to load MockAPI private JWK from disk"
            )
        logger.warning(
            "Received host configuration request for "
            "org O=%s, CN=%s, FQDN %s, inventory %s",
            org_id,
            rhsm_id,
            fqdn,
            inventory_id,
        )

        self.check_inventory(inventory_id, fqdn, rhsm_id)

        ca = self.get_ca_certs()
        logger.info(
            "host-conf for %s (%s, %s) is domain %s.",
            fqdn,
            inventory_id,
            rhsm_id,
            self.api.env.domain,
        )
        tok = sign.generate_host_token(
            priv_key,
            cert_o=str(org_id),
            cert_cn=rhsm_id,
            inventory_id=inventory_id,
            fqdn=fqdn,
            domain_id=self.domain_id,
        )
        response = {
            "domain_name": self.api.env.domain,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_id": self.domain_id,
            "auto_enrollment_enabled": True,
            "token": tok.serialize(compact=False),
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": self.api.env.realm,
                "cabundle": ca,
                "enrollment_servers": [
                    {"fqdn": self.api.env.host},
                ],
            },
        }
        return response

    @route("POST", "^/domains/token$", schema="DomainRegToken")
    def handle_domain_reg_token(self, env: dict, body: dict) -> dict:
        """Generate a new domain registration token

        The mockapi implementation has different assumptions than
        idmscv-backend. It uses the org_id from mTLS auth for the token.
        idmscv-backend does not use mTLS auth.
        """
        domain_type: str = body["domain_type"]
        if domain_type != hccplatform.HCC_DOMAIN_TYPE:
            raise HTTPException(400, "unsupported domain type")
        org_id, _ = self.parse_cert(env)
        token, expires_ns = domain_token.generate_token(
            hccplatform.TEST_DOMREG_KEY, domain_type, org_id
        )
        domain_id = domain_token.token_domain_id(token)
        response = {
            "domain_id": str(domain_id),
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "domain_token": token,
            "expiration": int(expires_ns / 1_000_000_000),
        }
        return response

    @route("POST", "^/domains$", schema="IPADomainRegister")
    def handle_register_domain(self, env: dict, body: dict) -> dict:
        regtok = env.get("HTTP_X_RH_IDM_REGISTRATION_TOKEN")
        if regtok is None:
            raise HTTPException(403, "missing X-RH-IDM-Registration-Token")
        org_id, _ = self.parse_cert(env)
        try:
            domain_id = domain_token.validate_token(
                hccplatform.TEST_DOMREG_KEY,
                hccplatform.HCC_DOMAIN_TYPE,
                org_id,
                regtok,
            )
        except ValueError as e:
            raise HTTPException(
                404, f"invalid X-RH-IDM-Registration-Token: {e}"
            ) from None

        response = self._handle_domain(str(domain_id), body)

        # set hccorgid in global IPA configuration
        if not self._is_connected():
            self._connect_ipa()
        try:
            self.api.Command.config_mod(
                hccorgid=str(org_id),
            )
        except errors.EmptyModlist:
            logger.debug("hccorgid=%s already configured", org_id)
        else:
            logger.debug("hccorgid=%s set", org_id)

        return response

    @route(
        "PUT",
        f"^/domains/(?P<domain_id>{UUID_RE})$",
        schema="IPADomainUpdate",
    )
    def handle_update_domain(
        self,
        env: dict,  # pylint: disable=unused-argument
        body: dict,
        domain_id: str,
    ) -> dict:
        logger.info("Update domain %s", domain_id)
        return self._handle_domain(domain_id, body)

    def _handle_domain(self, domain_id: str, body: dict) -> dict:
        domain_name = body["domain_name"]
        domain_type = body["domain_type"]
        if domain_name != self.api.env.domain:
            raise HTTPException(400, "unsupported domain name")
        if domain_type != hccplatform.HCC_DOMAIN_TYPE:
            raise HTTPException(400, "unsupported domain type")
        if domain_id != body.get("domain_id", domain_id):
            raise HTTPException(400, "domain id mismatch")
        body.setdefault("auto_enrollment_enabled", True)
        body["domain_id"] = domain_id
        return body

    @route(
        "GET",
        "^/internal/hccconf$",
    )
    def handle_internal_hccconf(  # pylint: disable=unused-argument
        self, env: dict, body: dict
    ) -> dict:
        """Internal hcc.conf provider for ephemeral and stage setup

        Used by ipahcc-client-prepare to provision a stage or ephemeral
        test system with /etc/ipa/hcc.conf and fix non-FQDN hostnames.
        Clients discover this endpoint with a DNS URI lookup:

        ipa dnszone-add podengo-project.internal.
        ipa dnsrecord-add podengo-project.internal. _hccconf \
            --uri-priority=0 --uri-weight=100 \
            --uri-target=https://$(hostname)/api/idmsvc/v1/internal/hccconf
        """
        result = {
            "domain": self.api.env.domain,
            "idmsvc_api_url": hccplatform.CONFIG.idmsvc_api_url,
        }
        if hccplatform.CONFIG.dev_username:
            result["dev_username"] = hccplatform.CONFIG.dev_username
            result["dev_password"] = hccplatform.CONFIG.dev_password
        return result

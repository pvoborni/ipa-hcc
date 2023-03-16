"""Interface to register or update domains with Hybrid Cloud Console
"""
import logging
import json

from cryptography.hazmat.primitives.serialization import Encoding
import requests
import requests.exceptions

from ipalib import errors
from ipalib.install import certstore

from ipahcc import hccplatform
from . import schema

if hccplatform.PY2:
    from httplib import responses as http_responses
else:
    from http.client import responses as http_responses

hccconfig = hccplatform.HCCConfig()
logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 10
_missing = object()


def _get_one(dct, key, default=_missing):
    try:
        return dct[key][0]
    except (KeyError, IndexError):
        if default is _missing:
            raise
        return default


class APIError(Exception):
    dbus_format = "qssa{ss}sqs"

    def __init__(
        self,
        status_code,
        reason,
        url,
        headers,
        body,
        exit_code=2,
        error_message=None,
    ):
        super(Exception, self).__init__(status_code, reason, error_message)
        # HTTP status code or IPA errno (>= 900)
        self.status_code = status_code
        # HTTP reason or IPA exception name
        self.reason = reason
        # remote URL or None
        self.url = url
        # response header dict or None
        self.headers = headers
        # response body (JSON or object)
        self.body = body
        # exit code for CLI
        self.exit_code = exit_code
        # human readable error message for CLI
        self.error_message = error_message

    def __repr__(self):
        # remove newline in JSON
        content = self.json.replace("\n", "")
        clsname = self.__class__.__name__
        return "{clsname}: {content}".format(clsname=clsname, content=content)

    def to_dbus(self):
        """Convert to D-Bus format"""
        headers = self.headers or {}
        url = self.url or ""
        body = self.body
        if isinstance(body, dict):
            body = json.dumps(body)
        return (
            self.status_code,
            self.reason,
            url,
            headers,
            body,
            self.exit_code,
            self.error_message,
        )

    @classmethod
    def from_response(
        cls, response, exit_code=2, error_message="Request failed"
    ):
        """Construct exception for failed request response"""
        return cls(
            response.status_code,
            response.reason,
            response.url,
            response.headers,
            response.text,
            exit_code,
            error_message,
        )

    @classmethod
    def not_found(
        cls, rhsm_id, response, exit_code=2, error_message=http_responses[404]
    ):
        """RHSM_ID not found (404)"""
        status_code = 404
        reason = http_responses[status_code]
        content = dict(
            status=status_code,
            title=reason,
            details="Host with owner id '{rhsm_id}' not found in inventory.".format(
                rhsm_id=rhsm_id
            ),
        )
        return cls(
            status_code,
            reason,
            response.url,
            response.headers,
            content,
            exit_code,
            error_message,
        )

    @classmethod
    def from_ipaerror(cls, e, exit_code, error_message):
        """From public IPA, expected exception"""
        # does not handle errors.PrivateError
        assert isinstance(e, errors.PublicError)
        exc_name = type(e).__name__
        exc_msg = str(e)
        status_code = e.errno
        reason = "{exc_name}: {exc_msg}".format(
            exc_name=exc_name, exc_msg=exc_msg
        )
        content = dict(
            status_code=status_code,
            title=exc_name,
            details=exc_msg,
        )
        return cls(
            status_code,
            reason,
            None,
            {},
            content,
            exit_code,
            error_message,
        )

    @classmethod
    def from_other(cls, status_code, exit_code, error_message):
        """From generic error"""
        reason = http_responses[status_code]
        content = dict(
            status_code=status_code,
            title=reason,
            details=error_message,
        )
        return cls(
            status_code, reason, None, {}, content, exit_code, error_message
        )


class HCCAPI(object):
    """Register or update domain information in HCC"""

    def __init__(self, api, dry_run=False):
        if not api.isdone("finalize") or not api.env.in_server:
            raise ValueError(
                "api must be an in_server, finalized, and connected API object"
            )

        self.api = api
        self.dry_run = dry_run
        self._session = requests.Session()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def check_host(
        self, domain_id, inventory_id, rhsm_id, fqdn, timeout=DEFAULT_TIMEOUT
    ):
        if not domain_id:
            config = self._get_ipa_config(all=False)
            domain_id = self._get_domain_id(config)
        info = {
            "domain_name": self.api.env.domain,
            "domain_id": domain_id,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            "inventory_id": inventory_id,
            "subscription_manager_id": rhsm_id,
            "fqdn": fqdn,
        }
        schema.validate_schema(info, "/schemas/check-host/request")
        resp = self._submit_idm_api(
            method="POST",
            subpath=("check-host", rhsm_id, fqdn),
            payload=info,
            timeout=timeout,
            extra_headers=None,
        )
        schema.validate_schema(resp.json(), "/schemas/check-host/response")
        return info, resp

    def register_domain(self, domain_id, token, timeout=DEFAULT_TIMEOUT):
        config = self._get_ipa_config(all=True)
        info = self._get_ipa_info(config)
        schema.validate_schema(info, "/schemas/domain/request")
        extra_headers = {
            "X-RH-IDM-Registration-Token": token,
        }
        resp = self._submit_idm_api(
            method="PUT",
            subpath=("domains", domain_id, "register"),
            payload=info,
            timeout=timeout,
            extra_headers=extra_headers,
        )
        schema.validate_schema(resp.json(), "/schemas/domain/response")
        # update after successful registration
        try:
            self.api.Command.config_mod(hccdomainid=domain_id)
        except errors.EmptyModlist:
            logger.debug("hccdomainid=%s already configured", domain_id)
        else:
            logger.debug("hccdomainid=%s set", domain_id)
        return info, resp

    def update_domain(
        self, update_server_only=False, timeout=DEFAULT_TIMEOUT
    ):
        config = self._get_ipa_config(all=True)
        # hcc_update_server_server is a single attribute
        update_server = config.get("hcc_update_server_server")
        if update_server_only and update_server != self.api.env.host:
            # stop with success
            logger.info(
                "Current host is not an HCC update server (update server: %s)",
                update_server,
            )
            return False

        domain_id = self._get_domain_id(config)

        info = self._get_ipa_info(config)
        schema.validate_schema(info, "/schemas/domain/request")
        resp = self._submit_idm_api(
            method="PUT",
            subpath=("domains", domain_id, "update"),
            payload=info,
            timeout=timeout,
            extra_headers=None,
        )
        schema.validate_schema(resp.json(), "/schemas/domain/response")
        return info, resp

    def _get_domain_id(self, config):
        domain_id = _get_one(config, "hccdomainid", None)
        if domain_id is None:
            raise APIError.from_other(
                500, 3, "Global setting 'hccDomainId' is missing."
            )
        return domain_id

    def _get_servers(self, config):
        """Get list of IPA server info objects"""
        # Include location information from
        ca_servers = set(config.get("ca_server_server", ()))
        hcc_enrollment = set(config.get("hcc_enrollment_server_server", ()))
        hcc_update = config.get("hcc_update_server_server", None)
        pkinit_servers = set(config.get("pkinit_server_server", ()))

        result = self.api.Command.host_find(in_hostgroup="ipaservers")

        servers = []
        for server in result["result"]:
            fqdn = _get_one(server, "fqdn")

            server_info = {
                "fqdn": fqdn,
                "subscription_manager_id": _get_one(
                    server, "hccsubscriptionid", default=None
                ),
                "ca_server": (fqdn in ca_servers),
                "hcc_enrollment_server": (fqdn in hcc_enrollment),
                "hcc_update_server": (fqdn == hcc_update),
                "pkinit_server": (fqdn in pkinit_servers),
            }
            servers.append(server_info)

        return servers

    def _get_cacerts(self):
        """Get list of trusted CA cert info objects"""
        try:
            result = self.api.Command.ca_is_enabled(version="2.107")
            ca_enabled = result["result"]
        except (errors.CommandError, errors.NetworkError):
            result = self.api.Command.env(server=True, version="2.0")
            ca_enabled = result["result"]["enable_ra"]

        certs = certstore.get_ca_certs(
            self.api.Backend.ldap2,
            self.api.env.basedn,
            self.api.env.realm,
            ca_enabled,
        )

        cacerts = []
        for cert, nickname, trusted, _eku in certs:
            if not trusted:
                continue
            certinfo = {
                "nickname": nickname,
                "pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
            }
            cacerts.append(certinfo)

        return cacerts

    def _get_realm_domains(self):
        """Get list of realm domain names"""
        result = self.api.Command.realmdomains_show()
        return list(result["result"]["associateddomain"])

    def _get_ipa_config(self, all):
        try:
            return self.api.Command.config_show(all=all)["result"]
        except Exception as e:
            msg = "Unable to get global configuration from IPA"
            logger.exception(msg)
            raise APIError.from_ipaerror(e, 5, msg)

    def _get_ipa_info(self, config):
        return {
            "domain_name": self.api.env.domain,
            "domain_type": hccplatform.HCC_DOMAIN_TYPE,
            hccplatform.HCC_DOMAIN_TYPE: {
                "realm_name": self.api.env.realm,
                "servers": self._get_servers(config),
                "cacerts": self._get_cacerts(),
                "realm_domains": self._get_realm_domains(),
            },
        }

    def _submit_idm_api(
        self, method, subpath, payload, timeout, extra_headers=None
    ):
        api_url = hccconfig.idm_cert_api_url.rstrip("/")
        url = "/".join((api_url,) + subpath)
        headers = {}
        if extra_headers:
            headers.update(extra_headers)
        logger.debug(
            "Sending %s request to %s with headers %s", method, url, headers
        )
        body = json.dumps(payload, indent=2)
        logger.debug("body: %s", body)
        if self.dry_run:
            logger.warning("Skip %s request %s, body:\n%s", method, url, body)
            return
        try:
            resp = self._session.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                cert=(hccplatform.RHSM_CERT, hccplatform.RHSM_KEY),
                json=payload,
            )
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            logger.error(
                "Request to %s failed: %s: %s", url, type(e).__name__, e
            )
            raise APIError.from_response(
                resp, 4, "{method} request failed".format(method=method)
            )

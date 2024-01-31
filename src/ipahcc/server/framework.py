#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Simple WSGI framework
"""
import collections
import inspect
import json
import logging
import os
import re
import traceback
import typing
from http.client import responses as http_responses
from urllib.parse import parse_qs

import gssapi
import ipalib

from ipahcc import hccplatform, sign
from ipahcc.server.hccapi import HCCAPI, APIResult
from ipahcc.server.schema import ValidationError, validate_schema
from ipahcc.server.util import parse_rhsm_cert

logger = logging.getLogger(__name__)


class HTTPException(Exception):
    def __init__(self, code, msg):
        super().__init__(code, msg)
        self.code = code
        self.message = msg


_Route = collections.namedtuple("_Route", "method path schema")


def route(method, path, schema=None):
    """Decorator to mark a method as HTTP request handler"""
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        raise ValueError(method)
    if not path.startswith("^") or not path.endswith("$"):
        raise ValueError(path)

    def inner(func):
        func.wsgi_route = _Route(method, path, schema)
        return func

    return inner


def patch_user_cache(api, cachepath):
    """FreeIPA does not have an API option to set cache path

    Cache path can be set with "XDG_CACHE_HOME" env *before* the first
    IPA module is imported. The patch function allows us to override the
    settings at a later point.
    """
    if not api.isdone("bootstrap"):
        # ipaclient.plugins.rpcclient defines rpcclient after IPA API is
        # bootstrapped and has RPC schema set.
        raise ValueError("Patching requires bootstrapped API")

    # pylint: disable=import-outside-toplevel, protected-access
    from ipaclient.remote_plugins import ServerInfo, schema
    from ipalib import constants

    constants.USER_CACHE_PATH = cachepath
    ServerInfo._DIR = os.path.join(cachepath, "ipa", "servers")
    schema.Schema._DIR = os.path.join(
        cachepath, "ipa", "schema", schema.FORMAT
    )
    # _KraConfigCache is not used by ipa-hcc


UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


class JSONWSGIApp:
    """Trivial, opinionated WSGI framework for REST-like JSON API

    - supports request methods GET, POST, PUT, PATCH.
    - POST, PUT, PATCH requests must be "application/json".
    - responses are always "application/json", even for errors.
    - handlers support optional schema validation for request and response
      payload.

    Example::

       @route("POST", "^/example/(?P<id>[^/]+)$", schema=None)
       def example(self, env, body, id):
           return {"id": id}
    """

    max_content_length = 10240

    def __init__(self, api=None):
        if api is None:  # pragma: no cover
            self.api = ipalib.api
        else:
            self.api = api
        if not self.api.isdone("bootstrap"):
            self.api.bootstrap(
                in_server=False,
                context="hcc",
            )

        if not self.api.env.in_server:
            patch_user_cache(
                api=self.api,
                cachepath=hccplatform.HCC_ENROLLMENT_AGENT_CACHE_DIR,
            )

        self.hccapi = HCCAPI(self.api)
        self.routes = self._get_routes()
        self._cache: typing.Dict[str, typing.Any] = {}

    def _get_routes(self) -> typing.List[typing.Tuple["re.Pattern", dict]]:
        """Inspect class and get a list of routes"""
        routes: typing.Dict[str, dict] = {}
        for name, meth in inspect.getmembers(self, inspect.ismethod):
            if name.startswith("_"):
                continue
            wr = getattr(meth, "wsgi_route", None)
            if wr:
                methmap = routes.setdefault(wr.path, {})
                methmap[wr.method] = (meth, wr.schema)

        return [
            (re.compile(path), methmap)
            for path, methmap in sorted(routes.items())
        ]

    def _route_lookup(self, env: dict) -> typing.Tuple[
        typing.Callable,
        typing.Optional[str],
        typing.Dict[str, typing.Any],
        typing.Dict[str, str],
    ]:
        """Lookup route by path info

        Returns callable, schema, body, kwargs

        Raises:
          - 411 length required
          - 413 request too large
          - 405 method not allowed
          - 406 unsupported content type
          - 404 not found
        """
        method = env["REQUEST_METHOD"]
        pathinfo = env["PATH_INFO"]

        if method in {"POST", "PUT", "PATCH"}:
            # limit content-length to prevent DoS
            try:
                length = int(env["CONTENT_LENGTH"])
            except (KeyError, ValueError):
                length = -1
            if length < 0:
                raise HTTPException(411, "Length required.")
            if length > self.max_content_length:
                raise HTTPException(413, "Request entity too large.")
            # POST/PUT/PATCH must be content-type application/json
            content_type = env["CONTENT_TYPE"]
            if content_type != "application/json":
                raise HTTPException(
                    406,
                    f"Unsupported content type {content_type}.",
                )
            body = json.loads(env["wsgi.input"].read(length))
        else:
            qs = env.get("QUERY_STRING")
            body = parse_qs(qs) if qs else {}

        for pathre, methmap in self.routes:
            mo = pathre.match(pathinfo)
            if mo is None:
                continue
            meth, schema = methmap.get(method, (None, None))
            if meth is None:
                raise HTTPException(
                    405,
                    f"Method {method} not allowed.",
                )
            return meth, schema, body, mo.groupdict()

        raise HTTPException(404, f"{pathinfo} not found")

    def _validate_schema(
        self,
        instance: dict,
        schema_name: str,
        suffix: str = "",
    ) -> None:
        """Validate JSON schema"""
        schema_id = f"{schema_name}{suffix}"
        try:
            validate_schema(instance, schema_id)
        except ValidationError:
            logger.exception("schema violation")
            raise HTTPException(
                400,
                f"schema violation: invalid JSON for {schema_id}",
            ) from None

    def _get_cache(self, key: str, default: typing.Any = None) -> typing.Any:
        """Get a key from local cache"""
        # Future versions may invalidate the cache after X minutes.
        return self._cache.get(key, default)

    def _set_cache(self, key: str, value: typing.Any) -> None:
        """Set or update a cache entry"""
        self._cache[key] = value

    def _clear_cache(self) -> None:
        self._cache.clear()

    def before_call(self) -> None:
        """Before handle method call hook"""
        # check for modified hcc.conf in development mode
        if hccplatform.DEVELOPMENT_MODE:
            hccplatform.CONFIG.refresh_config()

    def after_call(self) -> None:
        """After handle method call hook"""
        self._disconnect_ipa()
        # invalidate cache and force refresh in development mode
        if hccplatform.DEVELOPMENT_MODE:
            self._clear_cache()

    def parse_cert(self, env: dict) -> typing.Tuple[str, str]:
        """Parse XRHID certificate"""

        cert_pem = env.get("SSL_CLIENT_CERT")
        if not cert_pem:
            raise HTTPException(412, "SSL_CLIENT_CERT is missing or empty.")
        try:
            return parse_rhsm_cert(cert_pem)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None

    def _kinit_gssproxy(self) -> gssapi.Credentials:
        """Perform Kerberos authentication / refresh with gssproxy

        The environ variable `GSS_USE_PROXY` instructs GSSAPI to use gssproxy
        interposer module to perform heavily lifting for us. gssproxy is
        configured to map the effective uid of the process to a service
        with a client keytab.

        The `gssapi.Credentials` call is optional. It's there to check early
        whether everything is set up correctly.
        """
        os.environ["GSS_USE_PROXY"] = "1"
        # IPA's httpd.conf sets ccache name to a path which is not accessible
        # by the ipahcc user. NOTE: gssproxy has its own private ccache.
        os.environ["KRB5CCNAME"] = "MEMORY:"
        return gssapi.Credentials(usage="initiate")

    def _is_connected(self) -> bool:
        """Check whether IPA API is connected"""
        return (
            self.api.isdone("finalize")
            and self.api.Backend.rpcclient.isconnected()
        )

    def _connect_ipa(self) -> None:
        logger.debug("Connecting to IPA")
        self._kinit_gssproxy()
        if not self.api.isdone("finalize"):
            self.api.finalize()
        if not self._is_connected():
            self.api.Backend.rpcclient.connect()
            logger.debug("Connected")
        else:
            logger.debug("IPA rpcclient is already connected.")

    def _disconnect_ipa(self) -> None:
        if self._is_connected():
            self.api.Backend.rpcclient.disconnect()

    def _get_ipa_config(self) -> typing.Tuple[str, str]:
        """Get org_id and domain_id from IPA config"""
        # automatically connect
        connected = self._is_connected()
        if not connected:
            self._connect_ipa()
        try:
            # no need to fetch additional values
            result = self.api.Command.config_show(raw=True)["result"]
            org_ids = result.get("hccorgid")
            if not org_ids or len(org_ids) != 1:
                raise ValueError(
                    "Invalid IPA configuration, 'hccorgid' is not set."
                )
            domain_ids = result.get("hccdomainid")
            if not domain_ids or len(domain_ids) != 1:
                raise ValueError(
                    "Invalid IPA configuration, 'hccdomainid' is not set."
                )
            return org_ids[0], domain_ids[0]
        finally:
            if not connected:
                self._disconnect_ipa()

    @property
    def org_id(self) -> str:
        """Get organization id from LDAP (cached)"""
        org_id = self._get_cache("org_id")
        if org_id is None:
            org_id, domain_id = self._get_ipa_config()
            self._set_cache("org_id", org_id)
            self._set_cache("domain_id", domain_id)
        if typing.TYPE_CHECKING:
            assert isinstance(org_id, str)
        return org_id

    @property
    def domain_id(self) -> str:
        """Get domain uuid from LDAP (cached)"""
        domain_id = self._get_cache("domain_id")
        if domain_id is None:
            org_id, domain_id = self._get_ipa_config()
            self._set_cache("org_id", org_id)
            self._set_cache("domain_id", domain_id)
        if typing.TYPE_CHECKING:
            assert isinstance(domain_id, str)
        return domain_id

    def _get_ipa_jwkset(self) -> sign.JWKSet:
        """Get JWKs from LDAP"""
        jwkset = self._get_cache("jwkset")
        if jwkset is None:
            jwkset = self.hccapi.get_ipa_jwkset()
            self._set_cache("jwkset", jwkset)
        if typing.TYPE_CHECKING:
            assert isinstance(jwkset, sign.JWKSet)
        return jwkset

    def __call__(
        self, env: dict, start_response: typing.Callable
    ) -> typing.Iterable[typing.ByteString]:
        try:
            meth, schema_name, body, kwargs = self._route_lookup(env)
            if schema_name is not None:
                self._validate_schema(body, schema_name, "Request")

            self.before_call()
            try:
                result = meth(env, body, **kwargs)
            finally:
                self.after_call()

            if schema_name is not None:
                self._validate_schema(result, schema_name, "Response")

            response = json.dumps(result)
            status = 200
        except BaseException as e:  # pylint: disable=broad-except
            error_id = APIResult.genrid()
            if isinstance(e, HTTPException):
                status = e.code
                title = http_responses[status]
                details = e.message
                logger.info("%i: %s", status, details)
            else:
                logger.exception("Request failed")
                status = 500
                title = f"server error: {e}"
                details = traceback.format_exc()
            logger.error("[%s] %i %s", error_id, status, title)
            errors = {
                "errors": [
                    {
                        "id": error_id,
                        "status": str(status),
                        "title": title,
                        "detail": details,
                    }
                ]
            }
            self._validate_schema(errors, "Errors")
            response = json.dumps(errors)

        status_line = f"{status} {http_responses[status]}"
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(response)),
        }
        headers.update(hccplatform.HTTP_HEADERS)

        start_response(status_line, list(headers.items()))
        return [response.encode("utf-8")]

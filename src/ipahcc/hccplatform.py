#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2022  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
__all__ = ("is_ipa_configured",)

import configparser
import json
import logging
import os
import typing

from ipalib.facts import is_ipa_configured
from ipaplatform.constants import User, constants
from ipaplatform.osinfo import osinfo
from ipapython.version import VENDOR_VERSION as IPA_VERSION

from ._version import __version__ as VERSION

get_rhsm_config: typing.Optional[typing.Callable]
try:
    # pylint: disable=ungrouped-imports
    from rhsm.config import get_config_parser as get_rhsm_config
except ImportError:
    get_rhsm_config = None

logger = logging.getLogger(__name__)

# common HTTP request headers
HTTP_HEADERS = {
    "User-Agent": f"IPA HCC auto-enrollment {VERSION} (IPA: {IPA_VERSION})",
    "X-RH-IDM-Version": json.dumps(
        {
            "ipa-hcc": VERSION,
            "ipa": IPA_VERSION,
            "os-release-id": osinfo["ID"],
            "os-release-version-id": osinfo["VERSION_ID"],
        }
    ),
}  # type: dict[str, str]

# HCC enrollment agent (part pf ipa-hcc-server-plugin)
HCC_ENROLLMENT_AGENT = "hcc-enrollment"
HCC_ENROLLMENT_AGENT_USER = User("ipahcc")
HCC_ENROLLMENT_AGENT_GROUP = constants.IPAAPI_GROUP
HCC_ENROLLMENT_AGENT_CACHE_DIR = "/var/cache/ipa-hcc"
# Note: gssproxy directory comes with correct SELinux roles.
HCC_ENROLLMENT_AGENT_KEYTAB = "/var/lib/gssproxy/hcc-enrollment.keytab"

HCC_ENROLLMENT_JWK_PRIVILEGE = "HCC JWK Administrators"
HCC_ENROLLMENT_ROLE = "HCC Enrollment Administrators"

HCC_CACERTS_DIR = "/usr/share/ipa-hcc/cacerts"

RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"
INSIGHTS_HOST_DETAILS = "/var/lib/insights/host-details.json"
INSIGHTS_MACHINE_ID = "/etc/insights-client/machine-id"

# Hybrid Cloud Console and Host Based Inventory API
# see https://access.redhat.com/articles/3626371
TOKEN_CLIENT_ID = "rhsm-api"  # noqa: S105
REFRESH_TOKEN_FILE = "/etc/ipa/hcc/refresh_token"  # noqa: S105

# configuration
HCC_CONFIG = "/etc/ipa/hcc.conf"

# stage proxy
HCC_STAGE_PROXY = "http://squid.corp.redhat.com:3128"

HCC_DOMAIN_TYPE = "rhel-idm"  # noqa: S105

# for testing
DEVELOPMENT_MODE = True
MOCKAPI_PRIV_JWK = os.path.join(
    HCC_ENROLLMENT_AGENT_CACHE_DIR, "mockapi-priv-jwk.json"
)
TEST_DOMREG_KEY = b"secretkey"


# NOTE: cert-api.access.redhat.com uses internal CA chain
# /etc/rhsm/ca/redhat-uep.pem. The hosts cert.console.redhat.com and
# cert.console.stage.redhat.com use public CAs.
# NOTE: Code duplication with ipahcc_auto_enrollment

ProxyUrl = typing.Optional[str]


class ConsoleConfig(typing.NamedTuple):
    env: str
    rhsm_server: str
    # base url for inventory v1 (cert and token auth)
    inventory_cert_url: str
    inventory_api_url: str
    # base url for idmsvc v1 (cert auth)
    idmsvc_cert_url: str
    # SSO token refresh url
    sso_token_url: str


PROD_CONSOLE = ConsoleConfig(
    env="prod",
    rhsm_server="subscription.rhsm.redhat.com",
    inventory_cert_url="https://cert.console.redhat.com/api/inventory/v1",
    inventory_api_url="https://console.redhat.com/api/inventory/v1",
    idmsvc_cert_url="https://cert.console.redhat.com/api/idmsvc/v1",
    sso_token_url=(  # noqa: S106
        "https://sso.redhat.com/auth/realms/redhat-external"
        "/protocol/openid-connect/token"
    ),
)

STAGE_CONSOLE = ConsoleConfig(
    env="stage",
    rhsm_server="subscription.rhsm.stage.redhat.com",
    inventory_cert_url="https://cert.console.stage.redhat.com/api/inventory/v1",
    inventory_api_url="https://console.stage.redhat.com/api/inventory/v1",
    idmsvc_cert_url="https://cert.console.stage.redhat.com/api/idmsvc/v1",
    sso_token_url=(  # noqa: S106
        "https://sso.stage.redhat.com/auth/realms/redhat-external"
        "/protocol/openid-connect/token"
    ),
)


def detect_rhsm_config() -> typing.Tuple[ConsoleConfig, ProxyUrl]:
    """Detect configuration from RHSM config"""
    rhsm_server: typing.Optional[str]
    proxy_url: ProxyUrl = None
    proxy_url_noauth: ProxyUrl = None
    if get_rhsm_config is not None:
        logger.debug("Using RHSM config")
        rc = get_rhsm_config()
        rhsm_server = rc.get("server", "hostname").strip()
        phost = rc.get("server", "proxy_hostname").strip()
        if phost:
            pscheme = rc.get("server", "proxy_scheme").strip() or "http"
            pport = rc.get("server", "proxy_port").strip() or "3128"
            puser = rc.get("server", "proxy_user").strip()
            ppassword = rc.get("server", "proxy_password").strip()
            proxy_auth = f"{puser}:{ppassword}@" if puser else ""
            proxy_url = f"{pscheme}://{proxy_auth}{phost}:{pport}"
            # for logging
            proxy_url_noauth = f"{pscheme}://{phost}:{pport}"
        logger.debug("Detected RHSM server: %s", rhsm_server)
    else:
        logger.debug("RHSM is not available, default to prod")
        rhsm_server = None

    if rhsm_server == STAGE_CONSOLE.rhsm_server:
        cfg = STAGE_CONSOLE
    elif rhsm_server == PROD_CONSOLE.rhsm_server:
        cfg = PROD_CONSOLE
    else:
        # fallback is prod
        cfg = PROD_CONSOLE
    logger.info(
        "Detected RHSM server: '%s', RHSM proxy '%s', configuration: %r",
        rhsm_server,
        proxy_url_noauth or "",
        cfg,
    )
    return cfg, proxy_url


class HCCConfig:
    _section = "hcc"

    def __init__(self):
        self._ccfg, proxy_url = detect_rhsm_config()
        defaults = {
            "inventory_api_url": self._ccfg.inventory_api_url,  # token auth
            "idmsvc_api_url": self._ccfg.idmsvc_cert_url,  # cert auth
            "token_url": self._ccfg.sso_token_url,
        }
        if proxy_url:
            defaults["console_proxy"] = proxy_url
        self._cp = configparser.ConfigParser(
            defaults=defaults,
            interpolation=configparser.ExtendedInterpolation(),
        )
        self._cp.add_section(self._section)
        self._mtime: int = 0
        self.refresh_config()

    def refresh_config(self) -> typing.Optional[bool]:
        """Read or refresh config from config file"""
        try:
            mtime = int(os.stat(HCC_CONFIG).st_mode)
            if mtime > self._mtime:
                logger.info("Reading config file %s", HCC_CONFIG)
                with open(HCC_CONFIG, encoding="utf-8") as f:
                    self._cp.read_file(f)
                self._mtime = mtime
                return True
            else:
                return False
        except FileNotFoundError:
            return None

    def _get(self, key):
        value = self._cp.get(self._section, key, fallback=None)
        if not value:
            return None
        return value

    @property
    def idmsvc_api_url(self) -> str:
        """IDM API url with cert authentication"""
        return self._get("idmsvc_api_url")

    @property
    def token_url(self) -> str:
        """SSO token url"""
        return self._get("token_url")

    @property
    def inventory_api_url(self) -> str:
        """host based inventory API url with token auth"""
        return self._get("inventory_api_url")

    @property
    def console_proxy(self) -> ProxyUrl:
        """Proxy server for Console APIs"""
        return self._get("console_proxy")

    @property
    def proxy_map(self) -> typing.Optional[typing.Dict[str, str]]:
        """Proxy mapping for requests"""
        proxy = self.console_proxy
        if proxy is None:
            return None
        # special case for testing, only proxy requests to stage console.
        elif proxy == HCC_STAGE_PROXY:
            return {
                "https://subscription.rhsm.stage.redhat.com": HCC_STAGE_PROXY,
                "https://cert.console.stage.redhat.com": HCC_STAGE_PROXY,
                "https://console.stage.redhat.com": HCC_STAGE_PROXY,
                "https://sso.stage.redhat.com": HCC_STAGE_PROXY,
            }
        # use proxy for https and http
        else:
            return {
                "https": proxy,
                "http": proxy,
            }

    @property
    def dev_org_id(self) -> typing.Optional[str]:
        """Ephemeral dev/test org id (for fake header)"""
        return self._get("dev_org_id")

    @property
    def dev_cert_cn(self) -> typing.Optional[str]:
        """Ephemeral dev/test cert CN (for fake header)"""
        return self._get("dev_cert_cn")

    @property
    def dev_username(self) -> typing.Optional[str]:
        """Ephemeral dev/test username for API auth"""
        return self._get("dev_username")

    @property
    def dev_password(self) -> typing.Optional[str]:
        """Ephemeral dev/test password for API auth"""
        return self._get("dev_password")

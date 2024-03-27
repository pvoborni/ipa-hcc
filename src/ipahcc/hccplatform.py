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
from typing import Optional

from ipalib.facts import is_ipa_configured
from ipaplatform.constants import User, constants
from ipaplatform.osinfo import osinfo
from ipapython.version import VENDOR_VERSION as IPA_VERSION

logger = logging.getLogger(__name__)

# version is updated by Makefile
VERSION = "0.16"

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

# Hybrid Cloud Console and Host Based Inventory API
# see https://access.redhat.com/articles/3626371
TOKEN_CLIENT_ID = "rhsm-api"  # noqa: S105
REFRESH_TOKEN_FILE = "/etc/ipa/hcc/refresh_token"  # noqa: S105

# configuration
HCC_CONFIG = "/etc/ipa/hcc.conf"

HCC_DOMAIN_TYPE = "rhel-idm"  # noqa: S105

# for testing
DEVELOPMENT_MODE = True
MOCKAPI_PRIV_JWK = os.path.join(
    HCC_ENROLLMENT_AGENT_CACHE_DIR, "mockapi-priv-jwk.json"
)
TEST_DOMREG_KEY = b"secretkey"


class _HCCConfig:
    _defaults = {
        "token_url": (
            "https://sso.redhat.com/auth/realms/redhat-external"
            "/protocol/openid-connect/token"
        ),
        "inventory_api_url": "https://console.redhat.com/api/inventory/v1",
        "idmsvc_api_url": "https://console.redhat.com/api/idmsvc/v1",
    }

    _section = "hcc"

    def __init__(self):
        self._cp = configparser.ConfigParser(
            defaults=self._defaults,
            interpolation=configparser.ExtendedInterpolation(),
        )
        self._cp.add_section(self._section)
        self._mtime: int = 0
        self.refresh_config()

    def refresh_config(self) -> Optional[bool]:
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

    @property
    def idmsvc_api_url(self) -> str:
        """IDM API url with cert authentication"""
        return self._cp.get(self._section, "idmsvc_api_url")

    @property
    def token_url(self) -> str:
        """SSO token url"""
        return self._cp.get(self._section, "token_url")

    @property
    def inventory_api_url(self) -> str:
        """host based inventory API url with token auth"""
        return self._cp.get(self._section, "inventory_api_url")

    @property
    def dev_org_id(self) -> Optional[str]:
        """Ephemeral dev/test org id (for fake header)"""
        return self._cp.get(self._section, "dev_org_id", fallback=None)

    @property
    def dev_cert_cn(self) -> Optional[str]:
        """Ephemeral dev/test cert CN (for fake header)"""
        return self._cp.get(self._section, "dev_cert_cn", fallback=None)

    @property
    def dev_username(self) -> Optional[str]:
        """Ephemeral dev/test username for API auth"""
        return self._cp.get(self._section, "dev_username", fallback=None)

    @property
    def dev_password(self) -> Optional[str]:
        """Ephemeral dev/test password for API auth"""
        return self._cp.get(self._section, "dev_password", fallback=None)


CONFIG = _HCCConfig()

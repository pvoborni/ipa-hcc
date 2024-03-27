#!/usr/bin/env python3
"""IPA client auto-enrollment for Hybrid Cloud Console

Installation with older clients that lack PKINIT:

- get configuration from remote api /host-conf
- write a temporary krb5.conf for kinit and ipa-getkeytab commands
- with kinit using PKINIT identity and host principal 'host/$FQDN'
- ipa-getkeytab for host principal 'host/$FQDN' using the first
  IPA server from remote configuration
"""

import argparse
import base64
import json
import logging
import os
import random
import shlex
import shutil
import socket
import ssl
import sys
import tempfile
import time
import typing
import urllib.request
import uuid

from dns.exception import DNSException
from ipalib import constants, util, x509
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython import ipautil
from ipapython.dnsutil import query_srv
from ipapython.version import VENDOR_VERSION as IPA_VERSION

try:
    # pylint: disable=ungrouped-imports
    from ipalib.install.dnsforwarders import detect_resolve1_resolv_conf
except ModuleNotFoundError:

    def detect_resolve1_resolv_conf() -> bool:
        return False


get_rhsm_config: typing.Optional[typing.Callable]
try:
    # pylint: disable=ungrouped-imports
    from rhsm.config import get_config_parser as get_rhsm_config
except ImportError:
    get_rhsm_config = None

FQDN = socket.gethostname()

# version is updated by Makefile
VERSION = "0.16"

# copied from ipahcc.hccplatform
DEVELOPMENT_MODE = True
RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"
RHSM_CONF = "/etc/rhsm/rhsm.conf"
INSIGHTS_MACHINE_ID = "/etc/insights-client/machine-id"
INSIGHTS_HOST_DETAILS = "/var/lib/insights/host-details.json"
# Prod cert-api uses internal CA while stage uses a public CA
IPA_DEFAULT_CONF = paths.IPA_DEFAULT_CONF
HCC_DOMAIN_TYPE = "rhel-idm"
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
}

logger = logging.getLogger(__name__)


class ConsoleConfig(typing.NamedTuple):
    env: str
    rhsm_server: str
    # base url for inventory v1
    inventory_cert_url: str
    # base url for idmsvc v1
    idmsvc_cert_url: str
    # Prod cert-api uses internal CA while stage uses a public CA
    cert_api_cafile: typing.Optional[str]


PROD_CONSOLE = ConsoleConfig(
    env="prod",
    rhsm_server="subscription.rhsm.redhat.com",
    inventory_cert_url="https://cert.console.redhat.com/api/inventory/v1",
    idmsvc_cert_url="https://cert.console.redhat.com/api/idmsvc/v1",
    cert_api_cafile="/etc/rhsm/ca/redhat-uep.pem",
)

STAGE_CONSOLE = ConsoleConfig(
    env="stage",
    rhsm_server="subscription.rhsm.stage.redhat.com",
    inventory_cert_url="https://cert.console.stage.redhat.com/api/inventory/v1",
    idmsvc_cert_url="https://cert.console.stage.redhat.com/api/idmsvc/v1",
    cert_api_cafile=None,
)

ProxyUrl = typing.Optional[str]


def detect_rhsm_config() -> typing.Tuple[ConsoleConfig, ProxyUrl]:
    """Detect configuration from RHSM config"""
    rhsm_server: str
    proxy_url: ProxyUrl = None
    if get_rhsm_config is not None:
        logger.debug("Using RHSM config")
        rhsm_config = get_rhsm_config()
        rhsm_server = rhsm_config.get("server", "hostname").strip()
        proxy_hostname = rhsm_config.get("server", "proxy_hostname").strip()
        if proxy_hostname:
            proxy_scheme = (
                rhsm_config.get("server", "proxy_scheme").strip() or "http"
            )
            proxy_port = (
                rhsm_config.get("server", "proxy_port").strip() or "3128"
            )
            proxy_user = rhsm_config.get("server", "proxy_user").strip()
            proxy_password = rhsm_config.get(
                "server", "proxy_password"
            ).strip()
            proxy_auth = (
                f"{proxy_user}:{proxy_password}@" if proxy_user else ""
            )
            proxy_url = (
                f"{proxy_scheme}://{proxy_auth}{proxy_hostname}:{proxy_port}"
            )
        logger.debug(
            "Detected RHSM server: %s, proxy: %s", rhsm_server, proxy_url
        )
    else:
        logger.debug("RHSM is not available, default to prod")
        rhsm_server = "subscription.rhsm.redhat.com"

    if rhsm_server == STAGE_CONSOLE.rhsm_server:
        cfg = STAGE_CONSOLE
    else:
        cfg = PROD_CONSOLE
    logger.info("Detected configuration %s, RHSM proxy '%s'", cfg, proxy_url)
    return cfg, proxy_url


def check_arg_hostname(arg: str) -> str:
    hostname = arg.lower()
    if hostname in {"localhost", "localhost.localdomain"}:
        raise argparse.ArgumentError(
            None,
            f"Invalid hostname {arg}, host's FQDN is not configured.",
        )
    # TODO: fixme and look into support for 253 characters.
    # Linux Kernel limits the node name (hostname) to 64 characters.
    # A bug in Cyrus SASL causes LDAP bind with SASL to fail when a hostname
    # is exactly 64 characters. The off-by-one bug causes ipa-join to fail.
    # SASL auth works with 63 characters. The bug is fixed by
    # https://github.com/cyrusimap/cyrus-sasl/pull/599 but not available on
    # older RHEL versions.
    maxlen = constants.MAXHOSTNAMELEN - 1
    try:
        util.validate_hostname(hostname, maxlen=maxlen)
    except ValueError as e:
        raise argparse.ArgumentError(
            None, f"Invalid hostname {arg}: {e}"
        ) from None
    return hostname


def check_arg_domain_name(arg: str) -> str:
    try:
        util.validate_domain_name(arg)
    except ValueError as e:
        raise argparse.ArgumentError(
            None, f"Invalid domain name {arg}: {e}"
        ) from None
    return arg.lower()


def check_arg_location(arg: str) -> str:
    try:
        util.validate_dns_label(arg)
    except ValueError as e:
        raise argparse.ArgumentError(
            None, f"Invalid location {arg}: {e}"
        ) from None
    return arg.lower()


def check_arg_uuid(arg: str) -> str:
    try:
        uuid.UUID(arg)
    except ValueError as e:
        raise argparse.ArgumentError(
            None, f"Invalid UUID value {arg}: {e}"
        ) from None
    return arg.lower()


parser = argparse.ArgumentParser(
    prog="ipa-hcc-auto-enrollment",
    description="Auto-enrollment of IPA clients with Hybrid Cloud Console",
)

parser.add_argument(
    "--verbose",
    "-v",
    help="Enable verbose logging",
    dest="verbose",
    default=0,
    action="count",
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version=f"ipa-hcc {VERSION} (IPA {IPA_VERSION})",
)
parser.add_argument(
    "--insecure",
    action="store_true",
    help="Use insecure connection to Console API",
)
parser.add_argument(
    "--hostname",
    metavar="HOST_NAME",
    help="The hostname of this machine (FQDN)",
    default=FQDN,
    type=check_arg_hostname,
)
parser.add_argument(
    "--force",
    help="force setting of Kerberos conf",
    action="store_true",
)
parser.add_argument(
    "--timeout",
    help="timeout for HTTP request",
    type=int,
    default=10,
)
parser.add_argument(
    "--idmsvc-api-url",
    help=(
        "URL of Hybrid Cloud Console API with cert auth "
        "(default: detect from RHSM config)"
    ),
    default=None,
)

g_filter = parser.add_argument_group("domain filter")
# location, domain_name, domain_id
g_filter.add_argument(
    "--domain-name",
    metavar="NAME",
    help="Request enrollment into domain",
    type=check_arg_domain_name,
)
g_filter.add_argument(
    "--domain-id",
    metavar="UUID",
    help="Request enrollment into domain by HCC domain id",
    type=check_arg_uuid,
)
g_filter.add_argument(
    "--location",
    help="Prefer servers from location",
    type=check_arg_location,
    default=None,
)

# ephemeral testing
parser.set_defaults(
    dev_username=None,
    dev_password=None,
    dev_org_id=None,
    dev_cert_cn=None,
    upto=None,
    override_ipa_server=None,
    console_proxy=None,
    nameservers=None,
)
if DEVELOPMENT_MODE:
    g_ephemeral = parser.add_argument_group("Ephemeral environment")
    # presence of --dev-username enables Ephemeral login and fake identity
    g_ephemeral.add_argument(
        "--dev-username",
        metavar="USERNAME",
        help="Ephemeral basic auth user",
        type=str,
    )
    g_ephemeral.add_argument(
        "--dev-password",
        metavar="PASSWORD",
        help="Ephemeral basic auth password",
        type=str,
    )
    # If --dev-cert-cn is given, the RHSM cert is ignored. Otherwise the org id
    # and system CN are read from the certificate.
    g_ephemeral.add_argument(
        "--dev-org-id",
        metavar="ORG_ID",
        help="Override org id for systems without RHSM cert",
        type=str,
    )
    g_ephemeral.add_argument(
        "--dev-cert-cn",
        metavar="CERT_CN",
        help="Override RHSM CN for systems without RHSM cert",
        type=str,
    )

    g_testing = parser.add_argument_group("Development & Testing")
    g_testing.add_argument(
        "--upto",
        metavar="PHASE",
        choices=("host-conf", "resolveconf", "register"),
    )
    g_testing.add_argument(
        "--override-ipa-server",
        metavar="SERVER",
        help="Override IPA server name",
        type=check_arg_hostname,
    )
    # --console-proxy sets HTTPS proxy for requests to Console endpoints.
    # Requests to IPA endpoints use system settings (usually no proxy).
    g_testing.add_argument(
        "--console-proxy",
        help="HTTP proxy for Console API (default: detect from RHSM config)",
        default=None,
    )
    # Reconfigure system with custom DNS server(s)
    g_testing.add_argument(
        "--nameserver",
        metavar="IP",
        help=(
            "Override /etc/resolve.conf nameserver. The option can be "
            "repeated up to three times."
        ),
        action="append",
        dest="nameservers",
        default=None,
    )


class SystemStateError(Exception):
    def __init__(
        self, msg: str, remediation: typing.Optional[str], filename: str
    ):
        super().__init__(msg, remediation, filename)
        self.msg = msg
        self.remediation = remediation
        self.filename = filename


class AutoEnrollment:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        # initialized later
        self.enrollment_servers: typing.Optional[
            typing.List[typing.Dict[typing.Any, typing.Any]]
        ] = None
        self.servers: typing.Optional[typing.List[str]] = None
        self.server: typing.Optional[str] = None
        self.domain: typing.Optional[str] = None
        self.realm: typing.Optional[str] = None
        self.domain_id: typing.Optional[str] = None
        self.insights_machine_id: typing.Optional[str] = None
        self.inventory_id: typing.Optional[str] = None
        self.token: typing.Optional[str] = None
        self.install_args: typing.Iterable[str] = ()
        self.automount_location: typing.Optional[str] = None
        self.console_config: ConsoleConfig = PROD_CONSOLE
        # internals
        self.tmpdir: typing.Optional[str] = None

    def __enter__(self) -> "AutoEnrollment":
        self.tmpdir = tempfile.mkdtemp()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.args.verbose >= 2:
            logger.info("Keeping temporary directory %s", self.tmpdir)
        elif self.tmpdir is not None:
            shutil.rmtree(self.tmpdir)
            self.tmpdir = None

    def _ephemeral_config(self, req: urllib.request.Request) -> None:
        """Configure for Ephemeral environment"""
        logger.info("Configure urlopen for ephemeral basic auth")
        # HTTPBasicAuthHandler is a mess, manually create auth header
        creds = f"{self.args.dev_username}:{self.args.dev_password}"
        basic_auth = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        req.add_unredirected_header("Authorization", f"Basic {basic_auth}")

        org_id = self.args.dev_org_id
        cn = self.args.dev_cert_cn
        if cn is None or org_id is None:
            cert = x509.load_certificate_from_file(RHSM_CERT)
            nas = list(cert.subject)
            org_id = nas[0].value
            cn = nas[1].value
            logger.debug(
                "Using cert info from %s: org_id: %s, cn: %s",
                RHSM_CERT,
                org_id,
                cn,
            )
        else:
            logger.debug(
                "Using cert info from CLI: org_id: %s, cn: %s", org_id, cn
            )

        fake_identity = {
            "identity": {
                "account_number": "11111",
                "org_id": org_id,
                "type": "System",
                "auth_type": "cert-auth",
                "system": {
                    "cert_type": "system",
                    "cn": cn,
                },
                "internal": {
                    "auth_time": 900,
                    "cross_access": False,
                    "org_id": org_id,
                },
            }
        }
        req.add_header(
            "X-Rh-Fake-Identity",
            base64.b64encode(
                json.dumps(fake_identity).encode("utf-8")
            ).decode("ascii"),
        )
        req.add_header("X-Rh-Insights-Request-Id", str(uuid.uuid4()))

    def _do_json_request(
        self,
        url: str,
        body: typing.Optional[dict] = None,
        verify: bool = True,
        cafile: typing.Optional[str] = None,
        proxy: typing.Optional[str] = None,
    ) -> dict:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        headers.update(HTTP_HEADERS)
        if body is None:
            logger.debug("GET request %s: %s", url, body)
            req = urllib.request.Request(url, headers=headers)
            assert req.get_method() == "GET"
        else:
            logger.debug("POST request %s: %s", url, body)
            data = json.dumps(body).encode("utf-8")
            # Requests with data are always POST requests.
            req = urllib.request.Request(url, data=data, headers=headers)
            assert req.get_method() == "POST"

        context = ssl.create_default_context(cafile=cafile)
        context.load_cert_chain(RHSM_CERT, RHSM_KEY)
        if getattr(context, "post_handshake_auth", None) is not None:
            context.post_handshake_auth = True
        if verify:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if DEVELOPMENT_MODE and self.args.dev_username:
            self._ephemeral_config(req)

        # build URL opener with custom handlers
        handlers: typing.List[urllib.request.BaseHandler]
        handlers = [urllib.request.HTTPSHandler(context=context)]
        if proxy:
            logger.info("Using proxy %s for request to %s", proxy, url)
            handlers.append(urllib.request.ProxyHandler({"https": proxy}))
        opener = urllib.request.build_opener(*handlers)

        try:
            with opener.open(  # noqa: S310
                req,
                timeout=self.args.timeout,
            ) as resp:  # nosec
                j = json.load(resp)
        except urllib.request.HTTPError as e:
            logger.error(
                "HTTPError %s: %s (%s %s)",
                e.code,
                e.reason,
                req.get_method(),
                req.get_full_url(),
            )
            if e.headers.get("content-type") == "application/json":
                j = json.load(e.fp)
                for error in j.get("errors", ()):
                    logger.error(
                        "Error status=%s, title=%r, detail=%r, code=%r",
                        error.get("status"),
                        error.get("title"),
                        error.get("detail"),
                        error.get("code"),
                    )
            else:
                # not a JSON error response, may be HTML
                logger.debug("Error response: %s", e.read(4096))
            raise e from None

        logger.debug("Server response: %s", j)
        return j

    def _run(
        self,
        cmd: typing.List[str],
        stdin: typing.Optional[str] = None,
        setenv: bool = False,
    ) -> None:
        if setenv:
            # pass KRB5 and OpenSSL env vars
            env = {
                k: v
                for k, v in os.environ.items()
                if k.startswith(("KRB5", "GSS", "OPENSSL"))
            }
            env["LC_ALL"] = "C.UTF-8"
            env["KRB5_CONFIG"] = self.krb_name
            if typing.TYPE_CHECKING:
                assert self.tmpdir
            env["KRB5CCNAME"] = os.path.join(self.tmpdir, "ccache")
            if self.args.verbose >= 2:
                env["KRB5_TRACE"] = "/dev/stderr"
        else:
            env = None
        ipautil.run(cmd, stdin=stdin, env=env, raiseonerr=True)

    @property
    def ipa_cacert(self) -> str:
        if typing.TYPE_CHECKING:
            assert self.tmpdir
        return os.path.join(self.tmpdir, "ipa_ca.crt")

    @property
    def kdc_cacert(self) -> str:
        if typing.TYPE_CHECKING:
            assert self.tmpdir
        return os.path.join(self.tmpdir, "kdc_ca.crt")

    @property
    def pkinit_anchors(self) -> typing.List[str]:
        return [
            # Candlepin CA chain signs RHSM client cert
            f"FILE:{self.kdc_cacert}",
            # IPA CA signs KDC cert
            f"FILE:{self.ipa_cacert}",
        ]

    @property
    def pkinit_identity(self) -> str:
        return f"FILE:{RHSM_CERT},{RHSM_KEY}"

    @property
    def krb_name(self) -> str:
        if typing.TYPE_CHECKING:
            assert self.tmpdir
        return os.path.join(self.tmpdir, "krb5.conf")

    def check_system_state(self) -> None:
        for fname in (RHSM_CERT, RHSM_KEY):
            if not os.path.isfile(fname):
                raise SystemStateError(
                    "Host is not registered with subscription-manager.",
                    "subscription-manager register",
                    fname,
                )
        if not os.path.isfile(INSIGHTS_MACHINE_ID):
            raise SystemStateError(
                "Host is not registered with Insights.",
                "insights-client --register",
                INSIGHTS_MACHINE_ID,
            )
        # if INSIGHTS_HOST_DETAILS is missing, fall back to HTTP API call
        if os.path.isfile(IPA_DEFAULT_CONF) and not self.args.upto:
            raise SystemStateError(
                "Host is already an IPA client.", None, IPA_DEFAULT_CONF
            )

    def enroll_host(self) -> None:
        self.console_config, proxy_url = detect_rhsm_config()
        if self.args.console_proxy is None and proxy_url is not None:
            logger.debug("Using console proxy from RHSM: %s", proxy_url)
            self.args.console_proxy = proxy_url
        if self.args.idmsvc_api_url is None:
            logger.debug("Using default idmsvc url")
            self.args.idmsvc_api_url = self.console_config.idmsvc_cert_url

        logger.info("Enrolling with settings: %r", self.args)
        try:
            self.check_system_state()
        except SystemStateError as e:
            print(
                f"ERROR: {e.msg} (file: {e.filename})",
                file=sys.stderr,
            )
            if e.remediation:
                print(
                    f"Remediation: run '{e.remediation}'",
                    file=sys.stderr,
                )
            sys.exit(2)

        self.get_host_details()

        # set local_cacert, servers, domain name, domain_id, realm
        self.hcc_host_conf()
        self.check_upto("host-conf")

        self.set_dnsresolver()
        self.update_serverlist()
        self.check_upto("resolveconf")

        # self-register host with IPA
        # TODO: check other servers if server returns 400
        self.hcc_register()
        self.check_upto("register")

        self.ipa_client_install()
        if self.automount_location is not None:
            if typing.TYPE_CHECKING:
                assert isinstance(self.server, str)
            self.ipa_client_automount(self.automount_location, self.server)

    def check_upto(self, phase) -> None:
        if self.args.upto is not None and self.args.upto == phase:
            logger.info("Stopping at phase %s", phase)
            parser.exit(0)

    def get_host_details(self) -> dict:
        """Get inventory id from Insights' host details file or API call.

        insights-client stores the result of Insights API query in a local file
        once the host is registered.
        """
        with open(INSIGHTS_MACHINE_ID, encoding="utf-8") as f:
            self.insights_machine_id = f.read().strip()
        result = self._read_host_details_file()
        if result is None:
            result = self._get_host_details_api()
        self.inventory_id = result["results"][0]["id"]
        logger.info(
            "Host '%s' has inventory id '%s', insights id '%s'.",
            self.args.hostname,
            self.inventory_id,
            self.insights_machine_id,
        )
        return result

    def _read_host_details_file(self) -> typing.Optional[dict]:
        """Attempt to read host-details.json file

        The file is created and updated by insights-clients. On some older
        versions, the file is not created during the initial
        'insights-client --register' execution.
        """
        try:
            with open(INSIGHTS_HOST_DETAILS, encoding="utf-8") as f:
                j = json.load(f)
        except (OSError, ValueError) as e:
            logger.debug(
                "Failed to read JSON file %s: %s", INSIGHTS_HOST_DETAILS, e
            )
            return None
        else:
            if j["total"] != 1:
                return None
            return j

    def _get_host_details_api(self) -> dict:
        """Fetch host details from Insights API"""
        mid = self.insights_machine_id
        if typing.TYPE_CHECKING:
            assert isinstance(mid, str)
        base = self.console_config.inventory_cert_url
        url = f"{base}/hosts?insights_id={mid}"
        time.sleep(3)  # short initial sleep
        sleep_dur = 10  # sleep for 10, 20, 40, ...
        for _i in range(5):
            try:
                j = self._do_json_request(
                    url,
                    verify=True,
                    cafile=self.console_config.cert_api_cafile,
                    proxy=self.args.console_proxy,
                )
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "Failed to request host details from %s", url
                )
                break
            else:
                if j["total"] == 1 and j["results"][0]["insights_id"] == mid:
                    return j
                else:
                    logger.error("%s not in result", mid)
                logger.info("Waiting for %i seconds", sleep_dur)
                time.sleep(sleep_dur)
                sleep_dur *= 2
        # TODO: error message
        raise RuntimeError("Unable to find machine in host inventory")

    def _lookup_dns_srv(self) -> typing.List[str]:
        """Lookup IPA servers via LDAP SRV records

        Returns a list of hostnames sorted by priority (takes locations
        into account).
        """
        ldap_srv = f"_ldap._tcp.{self.domain}."
        try:
            anser = query_srv(ldap_srv)
        except DNSException as e:
            logger.error("DNS SRV lookup error: %s", e)
            return []
        result = []
        for rec in anser:
            result.append(str(rec.target).rstrip(".").lower())
        logger.debug("%s servers: %r", ldap_srv, result)
        return result

    @classmethod
    def _sort_servers(
        cls,
        server_list: typing.List[dict],
        dns_srvs: typing.List[str],
        location: typing.Optional[str] = None,
    ) -> typing.List[str]:
        """Sort servers by location and DNS SRV records

        1) If `location` is set, prefer servers from that location.
        2) Keep ordering of DNS SRV records. SRV lookup already sorts by priority and
           uses weighted randomization.
        3) Ignore any server in DNS SRV records that is not in `server_list`.
        4) Append additional servers (with randomization).
        """
        # fqdn -> location
        enrollment_servers = {
            s["fqdn"].rstrip(".").lower(): s.get("location")
            for s in server_list
        }
        # decorate-sort-undecorate, larger value means higher priority
        # [0.0, 1.0) is used for additional servers
        dsu: typing.Dict[str, typing.Union[int, float]]
        dsu = {
            name: i
            for i, name in enumerate(reversed(dns_srvs), start=1)
            if name in enrollment_servers
        }  # only enrollment-servers
        for fqdn, server_location in enrollment_servers.items():
            idx: typing.Union[int, float, None]
            idx = dsu.get(fqdn)
            # sort additional servers after DNS SRV entries, randomize order
            if idx is None:
                # [0.0, 1.0)
                idx = random.random()  # noqa: S311
            # bump servers with current location
            if location is not None and server_location == location:
                idx += 1000
            dsu[fqdn] = idx

        return sorted(dsu, key=dsu.get, reverse=True)  # type: ignore

    def hcc_host_conf(self) -> dict:
        body = {
            "domain_type": HCC_DOMAIN_TYPE,
        }
        for key in ["domain_name", "domain_id", "location"]:
            value = getattr(self.args, key)
            if value is not None:
                body[key] = value

        url = "{api_url}/host-conf/{inventory_id}/{hostname}".format(
            api_url=self.args.idmsvc_api_url.rstrip("/"),
            inventory_id=self.inventory_id,
            hostname=self.args.hostname,
        )
        verify = not self.args.insecure
        logger.info(
            "Getting host configuration from %s (secure: %s).", url, verify
        )
        try:
            j = self._do_json_request(
                url,
                body=body,
                verify=verify,
                proxy=self.args.console_proxy,
            )
        except Exception:
            logger.error("Failed to get host configuration from %s", url)
            raise SystemExit(2) from None

        with open(self.ipa_cacert, "w", encoding="utf-8") as f:
            f.write(j[HCC_DOMAIN_TYPE]["cabundle"])

        if j["domain_type"] != HCC_DOMAIN_TYPE:
            raise ValueError(j["domain_type"])
        self.domain = j["domain_name"]
        self.domain_id = j["domain_id"]
        # TODO: make token required
        self.token = j.get("token")
        self.realm = j[HCC_DOMAIN_TYPE]["realm_name"]
        # install args and automount location are optional
        self.install_args = j[HCC_DOMAIN_TYPE].get(
            "ipa_client_install_args", []
        )
        self.automount_location = j[HCC_DOMAIN_TYPE].get(
            "automount_location", None
        )
        self.enrollment_servers = j[HCC_DOMAIN_TYPE]["enrollment_servers"]
        if typing.TYPE_CHECKING:
            assert self.enrollment_servers
        logger.info("Domain: %s", self.domain)
        logger.info("Realm: %s", self.realm)
        logger.info(
            "Enrollment servers: %s", json.dumps(self.enrollment_servers)
        )
        logger.info(
            "Extra install args: %s",
            # Python 3.6 has no shlex.join()
            " ".join(shlex.quote(arg) for arg in self.install_args),
        )
        return j

    def set_dnsresolver(self):
        """Configure DNS resolver (/etc.resolv.conf, NM, resolve1)"""
        nameservers = self.args.nameservers
        if not nameservers:
            logger.info("No --nameserver arg, not changing DNS resolver")
            return

        resolve1_enabled = detect_resolve1_resolv_conf()
        logger.info(
            "Configuring DNS resolver to nameservers: %s, searchdomaine %s "
            "(resolve1 enabled: %s)",
            nameservers,
            self.domain,
            resolve1_enabled,
        )
        tasks.configure_dns_resolver(
            nameservers,
            [self.domain],
            resolve1_enabled=resolve1_enabled,
        )

    def update_serverlist(self):
        """Update and sort server list

        The list has to be sorted after the DNS resolver is configured.
        """
        if typing.TYPE_CHECKING:
            assert self.enrollment_servers
        self.servers = self._sort_servers(
            self.enrollment_servers,
            self._lookup_dns_srv(),
            self.args.location,
        )
        if typing.TYPE_CHECKING:
            assert self.servers
        logger.info(
            "Sorted servers with SRV records for location %s: %s",
            self.args.location,
            ", ".join(self.servers),
        )
        if self.args.override_ipa_server is None:
            self.server = self.servers[0]
        else:
            self.server = self.args.override_ipa_server
        logger.info("Using server '%s' for enrollment", self.server)

    def hcc_register(self) -> dict:
        """Register this host with /hcc API endpoint

        TODO: On 404 try next server
        """
        url = "https://{server}/hcc/{inventory_id}/{hostname}".format(
            server=self.server,
            inventory_id=self.inventory_id,
            hostname=self.args.hostname,
        )
        body = {
            "domain_type": HCC_DOMAIN_TYPE,
            "domain_name": self.domain,
            "domain_id": self.domain_id,
        }
        if self.token is not None:
            body["token"] = self.token
        logger.info("Registering host at %s", url)
        try:
            j = self._do_json_request(
                url,
                body=body,
                verify=True,
                cafile=self.ipa_cacert,
                proxy=None,  # don't use console proxy for IPA request
            )
        except Exception:
            logger.exception("Failed to register host at %s", url)
            raise SystemExit(3) from None
        if j["status"] != "ok":
            raise SystemExit(3)
        with open(self.kdc_cacert, "w", encoding="utf-8") as f:
            f.write(j["kdc_cabundle"])
        return j

    def ipa_client_install(self) -> None:
        """Install IPA client with PKINIT"""
        # fmt: off
        cmd = [
            paths.IPA_CLIENT_INSTALL,
            "--ca-cert-file", self.ipa_cacert,
            "--hostname", self.args.hostname,
            "--domain", self.domain,
            "--realm", self.realm,
            "--pkinit-identity", self.pkinit_identity,
        ]
        # fmt: on
        for anchor in self.pkinit_anchors:
            cmd.extend(["--pkinit-anchor", anchor])
        # TODO: Make ipa-client-install prefer servers from current location.
        if self.args.override_ipa_server:
            cmd.extend(["--server", self.args.override_ipa_server])
        if self.args.force:
            cmd.append("--force")
        cmd.append("--unattended")
        cmd.extend(self.install_args)

        return self._run(cmd)

    def ipa_client_automount(self, location: str, server: str) -> None:
        """Configure automount and SELinux boolean"""
        logger.info("Configuring automount location '%s'", location)
        cmd = [
            paths.IPA_CLIENT_AUTOMOUNT,
            "--unattended",
            "--location",
            location,
            "--server",
            server,
        ]
        self._run(cmd)
        logger.info("Enabling SELinux boolean for home directory on NFS")
        tasks.set_selinux_booleans({"use_nfs_home_dirs": "on"})


def main(args=None):
    args = parser.parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    logger.info("Arguments: %s", sys.argv[1:])

    with AutoEnrollment(args) as autoenrollment:
        autoenrollment.enroll_host()

    logger.info("Done")


if __name__ == "__main__":
    main()

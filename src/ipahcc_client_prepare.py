#!/usr/bin/env python3
"""IPA HCC client preparation service

Prepares a host in stage and ephemeral testing environment

- Look up magic ``_hccconf.podengo-project.internal.`` URI record in DNS
- Retrieve configuration from the HCC configuration endpoint, which is
  provided by mockapi.
- Fix up hostname if the hostname is not a FQDN
- Write ``/etc/sysconfig/ipa-hcc-auto-enrollment`` with ephemeral
  configuration.
- Run post fixers (e.g. SELinux bool for NFS home directory)
"""
import argparse
import json
import logging
import shlex
import socket
import ssl
import typing
from urllib.request import Request, urlopen

import dns.exception
import dns.rdatatype
from ipaplatform.tasks import tasks
from ipapython.dnsutil import get_ipa_resolver
from ipapython.version import VENDOR_VERSION as IPA_VERSION

# version is updated by Makefile
VERSION = "0.16"

HCCCONF_URI = "_hccconf.podengo-project.internal."
RHSM_CERT = "/etc/pki/consumer/cert.pem"
RHSM_KEY = "/etc/pki/consumer/key.pem"
SYSCONFIG = "/etc/sysconfig/ipa-hcc-auto-enrollment"

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    prog="ipa-hcc-client-prepare",
    description="IPA client prepare for testing of auto-enrollment",
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
    "--timeout",
    help="timeout for HTTP request",
    type=int,
    default=10,
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version=f"ipa-hcc {VERSION} (IPA {IPA_VERSION})",
)


class ClientPrepare:
    def __init__(self, args: argparse.Namespace):
        self.args = args

    def configure(self):
        url = self.dns_discover()

        j = self.fetch_config(url)
        domain = j["domain"]
        api_url = j["idmsvc_api_url"]
        dev_username = j.get("dev_username")
        dev_password = j.get("dev_password")

        self.fix_hostname(domain)
        self.sysconfig_auto_enrollment(api_url, dev_username, dev_password)

    def dns_discover(self) -> str:
        """Auto-discover configuration endpoint with DNS"""
        logger.debug("Resolving DNS URI %s", HCCCONF_URI)
        resolver = get_ipa_resolver()
        try:
            answer = resolver.resolve(HCCCONF_URI, rdtype=dns.rdatatype.URI)
        except dns.exception.DNSException:
            logger.exception("Failed")
            raise
        target = answer[0].target.decode("ascii")
        logger.info("Resolved URI '%s' to '%s'", HCCCONF_URI, target)
        return target

    def fetch_config(self, url: str, verify: bool = False) -> dict:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        req = Request(url, headers=headers)
        context = ssl.create_default_context()
        context.load_cert_chain(RHSM_CERT, RHSM_KEY)
        if getattr(context, "post_handshake_auth", None) is not None:
            context.post_handshake_auth = True
        if verify:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with urlopen(  # noqa: S310
            req,
            timeout=self.args.timeout,
            context=context,
        ) as resp:  # nosec
            j = json.load(resp)
        logger.info("Server response: %s", j)
        return j

    def fix_hostname(self, domain: str):
        current = socket.gethostname()
        logger.debug("Current hostname: %s", current)
        if current.endswith(f".{domain}"):
            logger.debug(
                "OK, current hostname %s ends with domain suffix %s",
                current,
                domain,
            )
        else:
            left = current.split(".", 1)[0]
            # limit to 63 characters (Cyrus SASL bug)
            left = left[: 63 - 1 - len(domain)].rstrip("-")
            new = f"{left}.{domain}"
            logger.info("Setting hostname from %s to %s", current, new)
            tasks.set_hostname(new)

    def sysconfig_auto_enrollment(
        self,
        api_url: str,
        dev_username: typing.Optional[str] = None,
        dev_password: typing.Optional[str] = None,
    ):
        # AUTO_ENROLLMENT_ARGS
        args = [
            "--verbose",
            "--insecure",
            "--idmsvc-api-url",
            api_url,
        ]
        if dev_username is not None and dev_password is not None:
            args.extend(
                [
                    "--dev-username",
                    dev_username,
                    "--dev-password",
                    dev_password,
                ]
            )
        # Python 3.6 has no shlex.join()
        arg_str = " ".join(shlex.quote(arg) for arg in args)
        content = f'AUTO_ENROLLMENT_ARGS="{arg_str}"\n'
        logger.info("Setting %s to %s", SYSCONFIG, content)
        with open(SYSCONFIG, "w", encoding="utf-8") as f:
            f.write(content)


def main(args=None):
    args = parser.parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    prepare = ClientPrepare(args)
    prepare.configure()

    logger.info("Done")


if __name__ == "__main__":
    main()

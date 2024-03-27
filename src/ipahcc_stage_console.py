#!/usr/bin/env python3
"""IPA HCC stage console setup

Configure system to use stage console services:
- subscription manager
- rhc
- insights-client

WARNING: This script is for testing only. It makes no effort to retain
existing configuration.
"""
import argparse
import configparser
import logging
import pathlib
import shutil
import subprocess
from urllib.parse import urlparse

# version is updated by Makefile
VERSION = "0.16"

RHSM_CONF_FILE = pathlib.Path("/etc/rhsm/rhsm.conf")
RHSM_SERVER_HOSTNAME = "subscription.rhsm.{suffix}"
RHSM_RHSM_BASEURL = "https://cdn.{suffix}"

INSIGHTS_CLIENT_CONF_FILE = pathlib.Path(
    "/etc/insights-client/insights-client.conf"
)
INSIGHTS_BASE_URL = "cert.cloud.{suffix}/api"

RHC_CONFIG_TOML_FILE = pathlib.Path("/etc/rhc/config.toml")
RHC_CONF = """\
# rhc global configuration settings

broker = ["wss://connect.cloud.{suffix}:443"]
data-host = "cert.cloud.{suffix}"
cert-file = "/etc/pki/consumer/cert.pem"
key-file = "/etc/pki/consumer/key.pem"
log-level = "error"
"""

# https://access.redhat.com/solutions/7005002
RHCD_SYSTEMD_PROXY_CONF_FILE = pathlib.Path(
    "/etc/systemd/system/rhcd.service.d/proyx.conf"
)
RHCD_SYSTEMD_PROXY_CONF = """\
[Service]
Environment=http_proxy={proxy}
Environment=https_proxy={proxy}
"""

IPAHCC_AUTO_ENROLLMENT_ENVFILE = pathlib.Path(
    "/etc/sysconfig/ipa-hcc-auto-enrollment"
)
IPAHCC_AUTO_ENROLLMENT_CONF = (
    'AUTO_ENROLLMENT_ARGS="'
    "--idmsvc-api-url https://cert.console.{suffix}/api/idmsvc/v1 "
    "--console-proxy {proxy}"
    '"'
)

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser(
    prog="ipa-hcc-stage-console",
    description="Configure system for stage console",
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
    "--force",
    action="store_true",
    help="Override ipa-hcc's and insight-client's auto-detection",
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version=f"ipa-hcc {VERSION}",
)
parser.add_argument(
    "suffix",
    choices=["stage.redhat.com"],
)
parser.add_argument(
    "--proxy",
    help="HTTP proxy for RHSM, RHC, and insights-client",
    # proxy is documented in public insights-client docs
    default="http://squid.corp.redhat.com:3128",
)


def _backup_file(filename: pathlib.Path):
    bak = filename.with_suffix(filename.suffix + ".bak")
    if not filename.exists():
        logger.debug("No backup, file %s does not exists", filename)
    elif bak.exists():
        logger.debug("Backup for %s already exists", filename)
    else:
        logger.debug("Backing up %s", filename)
        shutil.copy2(filename, bak)


def configure_rhsm(suffix: str, proxy: str):
    url = urlparse(proxy)
    if url.hostname is None:
        raise ValueError(url)
    logger.info("Configuring RHSM for %s, proxy: %s", suffix, url)
    _backup_file(RHSM_CONF_FILE)
    subprocess.check_call(
        [
            "/usr/bin/subscription-manager",
            "config",
            "--server.hostname",
            RHSM_SERVER_HOSTNAME.format(suffix=suffix),
            "--rhsm.baseurl",
            RHSM_RHSM_BASEURL.format(suffix=suffix),
            "--server.proxy_scheme",
            url.scheme,
            "--server.proxy_hostname",
            url.hostname,
            "--server.proxy_port",
            str(url.port or 3128),
        ]
    )


def configure_rhc(suffix: str, proxy: str):
    logger.info("Configuring RHC for %s", suffix)
    _backup_file(RHC_CONFIG_TOML_FILE)
    with RHC_CONFIG_TOML_FILE.open("w") as f:
        f.write(RHC_CONF.format(suffix=suffix))

    logger.info("Configuring rhcd.service for proxy: %s", proxy)
    RHCD_SYSTEMD_PROXY_CONF_FILE.parent.mkdir(exist_ok=True)
    with RHCD_SYSTEMD_PROXY_CONF_FILE.open("w") as f:
        f.write(RHCD_SYSTEMD_PROXY_CONF.format(proxy=proxy))
    logger.info("Reloading systemd daemon and try-restarting rhcd.service")
    subprocess.check_call(["/bin/systemctl", "daemon-reload"])
    subprocess.check_call(["/bin/systemctl", "try-restart", "rhcd.service"])


def configure_insights_client(suffix: str, proxy: str):
    logger.info(
        "Configuring insights-client for %s, proxy: %s", suffix, proxy
    )
    _backup_file(INSIGHTS_CLIENT_CONF_FILE)
    cfg = configparser.ConfigParser()
    cfg.add_section("insights-client")
    with INSIGHTS_CLIENT_CONF_FILE.open() as f:
        cfg.read_file(f)
    # https://github.com/RedHatInsights/insights-client?tab=readme-ov-file#recommended-developer-config
    cfg.set(
        "insights-client", "base_url", INSIGHTS_BASE_URL.format(suffix=suffix)
    )
    # insight-cores auto-config should detect rhsm_proxy_hostname, too.
    # Set proxy again in case auto-config is disabled.
    cfg.set("insights-client", "proxy", proxy)
    with INSIGHTS_CLIENT_CONF_FILE.open("w") as f:
        cfg.write(f, space_around_delimiters=False)


def configure_ipahcc_auto_enrollment(suffix: str, proxy: str):
    logger.info(
        "Configuring ipa-hcc-auto-enrollment.service for %s, proxy: %s",
        suffix,
        proxy,
    )
    _backup_file(IPAHCC_AUTO_ENROLLMENT_ENVFILE)
    with IPAHCC_AUTO_ENROLLMENT_ENVFILE.open("w") as f:
        f.write(
            IPAHCC_AUTO_ENROLLMENT_CONF.format(
                suffix=suffix,
                proxy=proxy,
            )
        )


def main(args=None):
    args = parser.parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    configure_rhsm(args.suffix, args.proxy)
    configure_rhc(args.suffix, args.proxy)
    if args.force:
        configure_insights_client(args.suffix, args.proxy)
        configure_ipahcc_auto_enrollment(args.suffix, args.proxy)
    else:
        logger.info("Use insight-client's and ipa-hcc's auto detection")


if __name__ == "__main__":
    main()

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

RHSM_CONF = pathlib.Path("/etc/rhsm/rhsm.conf")
RHSM_SERVER_HOSTNAME = "subscription.rhsm.{suffix}"
RHSM_RHSM_BASEURL = "https://cdn.{suffix}"

INSIGHTS_CLIENT_CONF = pathlib.Path(
    "/etc/insights-client/insights-client.conf"
)
INSIGHTS_BASE_URL = "cert.cloud.{suffix}"

RHC_CONFIG_TOML = pathlib.Path("/etc/rhc/config.toml")
RHC_CONF = """\
# rhc global configuration settings

broker = ["wss://connect.cloud.{suffix}:443"]
data-host = "cert.cloud.{suffix}"
cert-file = "/etc/pki/consumer/cert.pem"
key-file = "/etc/pki/consumer/key.pem"
log-level = "error"
"""

IPAHCC_AUTO_ENROLLMENT_ENVFILE = pathlib.Path(
    "/etc/sysconfig/ipa-hcc-auto-enrollment"
)
IPAHCC_AUTO_ENROLLMENT_CONF = """
AUTO_ENROLLMENT_ARGS="--idmsvc-api-url https://cert.console.{suffix}/api/idmsvc/v1"
"""

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
    "suffix",
    choices=["stage.redhat.com"],
)


def _backup_file(filename: pathlib.Path):
    bak = filename.with_suffix(filename.suffix + ".bak")
    if not bak.exists():
        logger.debug("Backing up %s", filename)
        shutil.copy2(filename, bak)
    else:
        logger.debug("Backup for %s already exists", filename)


def configure_rhsm(suffix: str):
    logger.info("Configuring RHSM for %s", suffix)
    _backup_file(RHSM_CONF)
    subprocess.check_call(
        [
            "/usr/bin/subscription-manager",
            "config",
            "--server.hostname",
            RHSM_SERVER_HOSTNAME.format(suffix=suffix),
            "--rhsm.baseurl",
            RHSM_RHSM_BASEURL.format(suffix=suffix),
        ]
    )


def configure_rhc(suffix: str):
    logger.info("Configuring RHC for %s", suffix)
    _backup_file(RHC_CONFIG_TOML)
    with open(RHC_CONFIG_TOML, "w") as f:
        f.write(RHC_CONF.format(suffix=suffix))


def configure_insights_client(suffix: str):
    logger.info("Configuring insights-client for %s", suffix)
    _backup_file(INSIGHTS_CLIENT_CONF)
    cfg = configparser.ConfigParser()
    cfg.add_section("insights-client")
    with open(INSIGHTS_CLIENT_CONF) as f:
        cfg.read_file(f)
    cfg.set(
        "insights-client", "base_url", INSIGHTS_BASE_URL.format(suffix=suffix)
    )
    with open(INSIGHTS_CLIENT_CONF, "w") as f:
        cfg.write(f, space_around_delimiters=False)


def configure_ipahcc_auto_enrollment(suffix: str):
    logger.info("Configuring ipa-hcc-auto-enrollment.service for %s", suffix)
    _backup_file(IPAHCC_AUTO_ENROLLMENT_ENVFILE)
    with open(IPAHCC_AUTO_ENROLLMENT_ENVFILE, "w") as f:
        f.write(IPAHCC_AUTO_ENROLLMENT_CONF.format(suffix=suffix))


def main(args=None):
    args = parser.parse_args(args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    configure_rhsm(args.suffix)
    configure_rhc(args.suffix)
    configure_insights_client(args.suffix)
    configure_ipahcc_auto_enrollment(args.suffix)


if __name__ == "__main__":
    main()

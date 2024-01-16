import argparse
import logging
import os
import pprint
import sys
import typing
import uuid

import ipalib
from ipaplatform.paths import paths
from ipapython import admintool

from ipahcc import hccplatform

from . import hccapi
from .util import prompt_yesno

logger = logging.getLogger(__name__)


def uuidtype(v):
    uuid.UUID(v)
    return v


parser = argparse.ArgumentParser(
    prog="ipa-hcc",
    description="Register or update IPA domain in Hybrid Cloud Console",
    usage="\n".join(
        [
            "",
            "  %(prog)s [options] register TOKEN",
            "  %(prog)s [options] update [--update-server-only]",
            "  %(prog)s [options] update-jwk",
            "  %(prog)s [options] status",
        ]
    ),
)
parser.set_defaults(
    prompt_timeout=30,
)
parser.add_argument(
    "--verbose",
    "-v",
    help="Enable verbose logging (-vv for extra verbose logging)",
    dest="verbose",
    default=0,
    action="count",
)
parser.add_argument(
    "--version",
    "-V",
    help="Show version number and exit",
    action="version",
    version=f"ipa-hcc {hccplatform.VERSION} (IPA {hccplatform.IPA_VERSION})",
)
parser.add_argument(
    "--timeout",
    help="Timeout for HTTP and LDAP requests",
    dest="timeout",
    default=hccapi.DEFAULT_TIMEOUT,
    type=int,
)

subparsers = parser.add_subparsers(dest="action")


def confirm_register(
    args: argparse.Namespace, result: hccapi.APIResult
) -> bool:
    j = result.json()
    if typing.TYPE_CHECKING:
        assert isinstance(j, dict)
    dns_domains = j[hccplatform.HCC_DOMAIN_TYPE]["realm_domains"]

    print("Domain information:")
    print(f" realm name:  {j[hccplatform.HCC_DOMAIN_TYPE]['realm_name']}")
    print(f" domain name: {j['domain_name']}")
    print(f" dns domains: {', '.join(dns_domains)}")
    print()
    return prompt_yesno(
        "Proceed with registration?",
        default=False,
        timeout=args.prompt_timeout,
    )


def register_callback(
    args: argparse.Namespace, result: hccapi.APIResult
) -> None:
    print(result.exit_message)


parser_register_old = subparsers.add_parser(
    "register", help="Register a domain with Hybrid Cloud Console"
)
parser_register_old.set_defaults(callback=register_callback)
parser_register_old.add_argument("token", type=str)
parser_register_old.add_argument(
    "--unattended",
    "-U",
    action="store_true",
    help="Don't prompt for confirmation",
)


def update_callback(
    args: argparse.Namespace, result: hccapi.APIResult
) -> None:
    print(result.exit_message)


parser_update = subparsers.add_parser(
    "update", help="Update domain information"
)
parser_update.set_defaults(callback=update_callback)
parser_update.add_argument("--update-server-only", action="store_true")


def update_jwk_callback(
    args: argparse.Namespace, result: hccapi.APIResult
) -> None:
    j = result.json()
    if typing.TYPE_CHECKING:
        assert isinstance(j, dict)
    print(result.exit_message)
    kids = sorted(set(j["present"] + j["added"]))
    print("Registered JWKs:", ", ".join(repr(kid) for kid in kids))
    revoked_kids = sorted(set(j["revoked"] + j["already_revoked"]))
    if revoked_kids:
        print("Revoked JWKs:", ", ".join(repr(kid) for kid in kids))


parser_update_jwk = subparsers.add_parser(
    "update-jwk", help="Update JWK signing keys"
)
parser_update_jwk.set_defaults(callback=update_jwk_callback)


def status_callback(
    args: argparse.Namespace, result: hccapi.APIResult
) -> None:
    j = result.json()
    if typing.TYPE_CHECKING:
        assert isinstance(j, dict)
    nr = "<not registered>"
    print("domain name: {}".format(j["domain_name"]))
    print("domain id: {}".format(j.get("domain_id") or nr))
    print("org id: {}".format(j.get("org_id") or nr))
    print(
        "auto enrollment: {}".format(
            j.get("auto_enrollment_enabled") or "n/a"
        )
    )
    print("servers:")
    for server in j[hccplatform.HCC_DOMAIN_TYPE]["servers"]:
        fqdn = server["fqdn"]
        has_hcc = "yes" if server["hcc_update_server"] else "no"
        print(f"\t{fqdn} (HCC plugin: {has_hcc})")


parser_status = subparsers.add_parser("status", help="Check status")
parser_status.set_defaults(callback=status_callback)

if hccplatform.DEVELOPMENT_MODE:

    def token_callback(
        args: argparse.Namespace, result: hccapi.APIResult
    ) -> None:
        j = result.json()
        if typing.TYPE_CHECKING:
            assert isinstance(j, dict)
        print(j["domain_token"])

    parser_token = subparsers.add_parser(
        "token", help="Get domain registration token from mockapi (dev mode)"
    )
    parser_token.set_defaults(callback=token_callback)


def main(args=None):
    args = parser.parse_args(args)

    # configure logging before api.bootstrap()
    # -v and -vv option
    if args.verbose == 0:
        level = logging.WARNING
    elif args.verbose == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    logging.basicConfig(format="%(message)s", level=level)

    ipalib.api.bootstrap(
        in_server=True,
        confdir=paths.ETC_IPA,
        context="hcc",
    )
    ipalib.api.finalize()

    # take debug flag into account
    if ipalib.api.env.debug:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

    # Python < 3.7 does not have required subparser
    if not getattr(args, "action", None):
        parser.error("action required\n")
    if not hccplatform.is_ipa_configured():
        print("IPA is not configured on this system.", file=sys.stderr)
        parser.exit(admintool.SERVER_NOT_CONFIGURED)
    if os.geteuid() != 0:
        print("Must be run as root", file=sys.stderr)
        parser.exit(3)

    jwk_result: typing.Optional[hccapi.APIResult] = None

    with hccapi.HCCAPI(api=ipalib.api, timeout=args.timeout) as api:
        try:
            if args.action == "register":
                if not args.unattended and sys.stdin.isatty():
                    # print summary and ask for confirmation
                    _, result = api.status_check()
                    do_it = confirm_register(args, result)
                    if not do_it:
                        parser.exit(
                            status=0, message="Registration cancelled\n"
                        )
                _, result = api.register_domain(args.token)
                _, jwk_result = api.update_jwk()
            elif args.action == "update":
                _, result = api.update_domain(args.update_server_only)
                _, jwk_result = api.update_jwk()
            elif args.action == "update-jwk":
                _, result = api.update_jwk()
            elif args.action == "status":
                _, result = api.status_check()
            elif hccplatform.DEVELOPMENT_MODE and args.action == "token":
                _, result = api.mock_domain_reg_token()
            else:  # pragma: no cover
                raise ValueError(args.action)
        except hccapi.APIError as e:
            logger.error("API error: %s", e)
            print(e.result.exit_message, file=sys.stderr)
            parser.exit(e.result.exit_code)
        else:
            logger.debug("APIResult: %s", pprint.pformat(result.asdict()))
            if jwk_result is not None:
                update_jwk_callback(args, jwk_result)
            args.callback(args, result)
            if result.exit_code == 0:
                parser.exit(0)
            else:
                parser.exit(
                    result.exit_code,
                    f"Error:\n    {result.exit_message}\n",
                )


if __name__ == "__main__":
    main()

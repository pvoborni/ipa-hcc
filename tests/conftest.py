# pylint: disable=too-many-locals,ungrouped-imports

import contextlib
import importlib
import io
import json
import logging
import os
import sys
import typing
import unittest
from http.client import responses as http_responses
from unittest import mock

import gssapi
from ipalib import api
from ipalib.x509 import load_pem_x509_certificate
from ipaplatform.paths import paths
from requests import Response

from ipahcc import hccplatform
from ipahcc.server.util import create_certinfo, read_cert_dir

BASEDIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
TESTDATA = os.path.join(BASEDIR, "tests", "data")

DOMAIN = "ipa-hcc.test"
REALM = DOMAIN.upper()
CLIENT_FQDN = "client.ipa-hcc.test"
SERVER_FQDN = "server.ipa-hcc.test"
DOMAIN_ID = "772e9618-d0f8-4bf8-bfed-d2831f63c619"
CLIENT_RHSM_ID = "1ee437bc-7b65-40cc-8a02-c24c8a7f9368"
CLIENT_INVENTORY_ID = "1efd5f0e-7589-44ac-a9af-85ba5569d5c3"
SERVER_RHSM_ID = "e658e3eb-148c-46a6-b48a-099f9593191a"
SERVER_INVENTORY_ID = "f0468001-7632-4d3f-afd2-770c93825adf"
ORG_ID = "16765486"

RHSM_CERT = os.path.join(TESTDATA, "autoenrollment", "cert.pem")
RHSM_KEY = os.path.join(TESTDATA, "autoenrollment", "key.pem")
IPA_CA_CRT = os.path.join(TESTDATA, "autoenrollment", "ipa_ca.crt")
KDC_CA_DIR = os.path.join(BASEDIR, "install", "server", "cacerts")
HOST_DETAILS = os.path.join(TESTDATA, "autoenrollment", "host-details.json")
MACHINE_ID = os.path.join(TESTDATA, "autoenrollment", "machine-id")
NO_FILE = os.path.join(TESTDATA, "autoenrollment", "file-does-not-exist")

KDC_CONF = os.path.join(TESTDATA, "kdc.conf")

DUMMY_TOKEN = "dummy token"  # noqa: S105
# patch
paths.IPA_CA_CRT = IPA_CA_CRT
hccplatform.HCC_CACERTS_DIR = KDC_CA_DIR

with open(RHSM_CERT, encoding="utf-8") as f:
    RHSM_CERT_DATA = f.read()
with open(IPA_CA_CRT, encoding="utf-8") as f:
    IPA_CA_DATA = f.read()
IPA_CA_NICKNAME = "IPA-HCC.TEST IPA CA"
IPA_CA_CERTINFO = create_certinfo(
    load_pem_x509_certificate(IPA_CA_DATA.encode("ascii")),
    nickname=IPA_CA_NICKNAME,
)
KDC_CA_DATA = read_cert_dir(KDC_CA_DIR)

try:
    # pylint: disable=unused-import,ungrouped-imports
    import ipalib.install  # noqa: F401
except ImportError:
    HAS_IPA_INSTALL = False
else:
    HAS_IPA_INSTALL = True

try:
    # pylint: disable=unused-import
    import ipaserver.masters  # noqa: F401
except ImportError:
    HAS_IPASERVER = False
    IS_IPASERVER_CONFIGURED = False
else:
    from ipalib.facts import is_ipa_configured

    HAS_IPASERVER = True
    IS_IPASERVER_CONFIGURED = is_ipa_configured()


requires_ipa_install = unittest.skipUnless(
    HAS_IPA_INSTALL, "requires 'ipaclient.install' or 'ipalib.install'"
)
requires_ipaserver = unittest.skipUnless(
    HAS_IPASERVER, "requires 'ipaserver'"
)

# initialize first step of IPA API so server imports work
if not api.isdone("bootstrap"):
    if IS_IPASERVER_CONFIGURED:
        # the host is configured as an IPA system
        api.bootstrap(
            force_schema_check=True,
            log=None,
            in_server=False,
            context="hcc",
        )
    else:
        # not an IPA system, use fake values
        api.bootstrap(
            log=None,
            host=CLIENT_FQDN,
            server=SERVER_FQDN,
            domain=DOMAIN,
            realm=REALM,
            context="hcc",
        )
else:  # pragma: no cover
    pass


class CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class IPABaseTests(unittest.TestCase):
    maxDiff = None

    def log_capture_start(self):
        self.log_capture = CaptureHandler()
        self.log_capture.setFormatter(
            logging.Formatter("%(levelname)s:%(name)s:%(message)s")
        )

        root_logger = logging.getLogger(None)
        self._old_handlers = root_logger.handlers[:]
        self._old_level = root_logger.level
        root_logger.handlers = [self.log_capture]
        root_logger.setLevel(logging.DEBUG)
        self.addCleanup(self.log_capture_stop)

    def log_capture_stop(self):
        root_logger = logging.getLogger(None)
        root_logger.handlers = self._old_handlers
        root_logger.setLevel(self._old_level)

    def get_logs(self):
        fmt = logging.Formatter()
        return [fmt.format(r) for r in self.log_capture.records]

    def setUp(self):
        super().setUp()
        self.log_capture_start()

    def get_mock_env(self):
        return mock.Mock(
            in_server=True,
            domain=DOMAIN,
            realm=REALM,
            host=SERVER_FQDN,
            basedn="dc=ipa-hcc,dc=test",
        )

    def mock_hccplatform(self):
        cfg = mock.Mock(spec=hccplatform.CONFIG)
        cfg.configure_mock(
            idmsvc_api_url="http://invalid.test",
            token_url="http://invalid.test",  # noqa: S106
            inventory_api_url="http://invalid.test",
            dev_org_id=None,
            dev_cert_cn=None,
            dev_username=None,
            dev_password=None,
        )

        p = mock.patch.multiple(
            "ipahcc.hccplatform",
            RHSM_CERT=RHSM_CERT,
            RHSM_KEY=RHSM_KEY,
            INSIGHTS_HOST_DETAILS=HOST_DETAILS,
            HCC_CACERTS_DIR=KDC_CA_DIR,
            HCC_ENROLLMENT_AGENT_KEYTAB=NO_FILE,
            CONFIG=cfg,
        )
        p.start()
        self.addCleanup(p.stop)

    def mkresponse(self, status_code, body):
        j = json.dumps(body).encode("utf-8")
        resp = Response()
        resp.url = "http://ipahcc.test"
        resp.status_code = status_code
        resp.reason = http_responses[status_code]
        resp.encoding = "utf-8"
        resp.headers["content-type"] = "application/json"
        resp.headers["content-length"] = str(len(j))
        resp.raw = io.BytesIO(j)
        resp.raw.seek(0)
        return resp

    def assert_response(
        self,
        expected_code: int,
        status_code: int,
        status_msg: str,
        headers: dict,
        response: dict,
    ):
        if expected_code != status_code:
            # extend error message with log output
            msg = [response]
            msg.extend(self.get_logs())
            self.assertEqual(status_code, 200, msg)
        self.assertEqual(status_msg, http_responses[status_code])
        self.assertEqual(headers["Content-Type"], "application/json")

    def assert_cli_run(self, mainfunc, *args, **kwargs):
        try:
            with capture_output() as out:
                mainfunc(list(args))
        except SystemExit as e:
            self.assertEqual(e.code, kwargs.get("exitcode", 0))
        else:  # pragma: no cover
            self.fail("SystemExit expected")
        return out.read()

    def assert_log_entry(self, msg):
        self.assertIn(msg, self.get_logs())


class IPAWSGIBaseTests(IPABaseTests):
    app: typing.Any

    wsgi_class: typing.Any

    def setUp(self):
        super().setUp()
        self.m_api = mock.Mock()
        self.m_api.env = self.get_mock_env()
        self.m_api.isdone.return_value = True
        self.m_api.Command.config_show.return_value = {
            "result": {
                "hccdomainid": (DOMAIN_ID,),
                "hccorgid": (ORG_ID,),
            }
        }

        self.app = self.wsgi_class(self.m_api)

        p = mock.patch.object(gssapi, "Credentials")
        self.m_gss_credentials = p.start()
        self.addCleanup(p.stop)

    def call_wsgi(
        self,
        path,
        body,
        content_type="application/json",
        method="POST",
        extra_headers=None,
        client_cert=RHSM_CERT_DATA,
    ):
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
        }
        if client_cert is not None:
            env["SSL_CLIENT_CERT"] = client_cert
        if body is not None:
            dump = json.dumps(body).encode("utf-8")
            wsgi_input = io.BytesIO()
            wsgi_input.write(dump)
            wsgi_input.seek(0)
            env.update(
                {
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": len(dump),
                    "wsgi.input": wsgi_input,
                }
            )
        if extra_headers:
            for key, value in extra_headers.items():
                newkey = "HTTP_" + key.upper().replace("-", "_")
                env[newkey] = value
        start_response = mock.Mock()
        response = self.app(env, start_response)
        status = start_response.call_args[0][0]
        status_code, status_msg = status.split(" ", 1)
        status_code = int(status_code)
        self.assertIsInstance(start_response.call_args[0][1], list)
        headers = dict(start_response.call_args[0][1])
        if headers["Content-Type"] == "application/json":
            response = json.loads(b"".join(response).decode("utf-8"))
        return status_code, status_msg, headers, response


@contextlib.contextmanager
def capture_output():
    out = io.StringIO()
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    sys.stdout = out
    sys.stderr = out
    try:
        yield out
    finally:
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr
        out.seek(0)


def jsonio(body: dict) -> io.BytesIO:
    j = json.dumps(body).encode("utf-8")
    out = io.BytesIO(j)
    out.seek(0)
    return out


def _fixup_ipaserver_import(name):
    path = os.path.join(BASEDIR, "src", name.replace(".", os.sep))
    mod = importlib.import_module(name)
    mod.__path__.append(path)


if HAS_IPASERVER:
    _fixup_ipaserver_import("ipaserver.install.plugins")
    _fixup_ipaserver_import("ipaserver.plugins")

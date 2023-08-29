#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#

import logging
import os

from ipahcc import hccplatform

# must be set before ipalib or ipapython is imported
os.environ["XDG_CACHE_HOME"] = hccplatform.HCC_ENROLLMENT_AGENT_CACHE_DIR
os.environ["KRB5CCNAME"] = hccplatform.HCC_ENROLLMENT_AGENT_KRB5CCNAME
os.environ["GSS_USE_PROXY"] = "1"

# pylint: disable=wrong-import-position,wrong-import-order,ungrouped-imports
from ipalib import errors  # noqa: E402

from ipahcc import sign  # noqa: E402
from ipahcc.server.framework import (  # noqa: E402
    HTTPException,
    JSONWSGIApp,
    route,
)
from ipahcc.server.util import read_cert_dir  # noqa: E402

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("ipa-hcc")
logger.setLevel(logging.DEBUG)


class Application(JSONWSGIApp):
    def __init__(self, api=None) -> None:
        super().__init__(api=api)
        # cached PEM bundle
        self._kdc_cabundle = read_cert_dir(hccplatform.HCC_CACERTS_DIR)

    def before_call(self) -> None:
        self._connect_ipa()

    def after_call(self) -> None:
        self._disconnect_ipa()

    def _load_pub_jwk(self):
        """Get JWKs from LDAP

        TODO: implement LDAP interface
        At the moment the function loads the public key from the local file
        system.
        """
        with open(hccplatform.MOCKAPI_PUB_JWK, "r", encoding="utf-8") as f:
            pub_key = sign.load_key(f.read())
        return pub_key

    def validate_token(
        self, raw_token: str, inventory_id: str, rhsm_id: str, fqdn: str
    ):
        pub_key = self._load_pub_jwk()
        try:
            header, claims = sign.validate_host_token(
                raw_token,
                pub_key,
                cert_o=str(self.org_id),
                cert_cn=rhsm_id,
                inventory_id=inventory_id,
                fqdn=fqdn,
                domain_id=self.domain_id,
            )
        except Exception as e:
            # TODO: better exception handling
            logger.exception("Token validation failed")
            raise HTTPException(401, str(e)) from None
        return header, claims

    def update_ipa(
        self,
        org_id: str,
        rhsm_id: str,
        inventory_id: str,
        fqdn: str,
    ):
        ipa_org_id = self.org_id
        if org_id != ipa_org_id:
            raise HTTPException(
                400,
                f"Invalid org_id: {org_id} != {ipa_org_id}",
            )
        rhsm_id = str(rhsm_id)
        inventory_id = str(inventory_id)
        fqdn = str(fqdn)
        try:
            self.api.Command.host_add(
                fqdn,
                # hccorgid=org_id,
                hccsubscriptionid=rhsm_id,
                hccinventoryid=inventory_id,
                force=True,
            )
            logger.info("Added IPA host %s", fqdn)
        except errors.DuplicateEntry:
            try:
                self.api.Command.host_mod(
                    fqdn,
                    # hccorgid=org_id,
                    hccsubscriptionid=rhsm_id,
                    hccinventoryid=inventory_id,
                )
                logger.info("Updated IPA host %s", fqdn)
            except errors.EmptyModlist:
                logger.info(
                    "Nothing to update for IPA host %s",
                    fqdn,
                )

    @route(
        "POST",
        "^/(?P<inventory_id>[^/]+)/(?P<fqdn>[^/]+)$",
        schema="HostRegister",
    )
    def handle(  # pylint: disable=unused-argument
        self, env: dict, body: dict, inventory_id: str, fqdn: str
    ) -> dict:
        org_id, rhsm_id = self.parse_cert(env)
        logger.warning(
            "Received self-enrollment request for org O=%s, CN=%s",
            org_id,
            rhsm_id,
        )
        # TODO: make token required
        if "token" in body:
            self.validate_token(body["token"], inventory_id, rhsm_id, fqdn)
        self.update_ipa(org_id, rhsm_id, inventory_id, fqdn)

        logger.info(
            "Self-registration of %s (O=%s, CN=%s) was successful",
            fqdn,
            org_id,
            rhsm_id,
        )
        # TODO: return value?
        return {"status": "ok", "kdc_cabundle": self._kdc_cabundle}

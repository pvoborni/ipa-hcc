#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""Configure Hybrid Cloud Console MockAPI settings
"""
import logging
import os

from ipalib import Registry, Updater, errors

from ipahcc import hccplatform, sign

logger = logging.getLogger(__name__)

register = Registry()


@register()
class update_hcc_mockapi(Updater):
    """Configure Hybrid Cloud Console MockAPI settings

    - Create private JWK
    - Upload public JWK to IPA
    """

    def generate_private_jwk(self) -> bool:
        if os.path.isfile(hccplatform.MOCKAPI_PRIV_JWK):
            logger.info(
                "Mockapi JWK %s already exists", hccplatform.MOCKAPI_PRIV_JWK
            )
            return False

        priv_key = sign.generate_private_key()
        with open(hccplatform.MOCKAPI_PRIV_JWK, "w", encoding="utf-8") as f:
            f.write(priv_key.export_private())
        hccplatform.HCC_ENROLLMENT_AGENT_USER.chown(
            hccplatform.MOCKAPI_PRIV_JWK
        )
        logger.info(
            "Generated MockAPI private JWK %s with kid %s",
            hccplatform.MOCKAPI_PRIV_JWK,
            priv_key["kid"],
        )
        return True

    def add_public_jwk(self):
        with open(hccplatform.MOCKAPI_PRIV_JWK, "r", encoding="utf-8") as f:
            priv_key = sign.load_key(f.read())
        kid = priv_key["kid"]
        try:
            self.api.Command.hccjwk_add(hccpublicjwk=priv_key.export_public())
        except errors.DuplicateEntry:
            logger.info("MockAPI public JWK '%s' is already in LDAP", kid)
            return False
        else:
            logger.info("Add MockAPI public JWK '%s'", kid)
            return True

    def execute(self, **options):
        self.generate_private_jwk()
        self.add_public_jwk()
        return False, []

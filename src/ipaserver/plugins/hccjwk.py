#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IPA plugin for Red Hat Hybrid Cloud Console
"""
import datetime
import logging
import typing

from ipalib import _, api, errors, ngettext
from ipalib.parameters import Bool, DateTime, Flag, Param, Str, StrEnum
from ipalib.plugable import Registry
from ipapython.dn import DN
from ipaserver.plugins.baseldap import (
    LDAPCreate,
    LDAPDelete,
    LDAPObject,
    LDAPRetrieve,
    LDAPSearch,
    LDAPUpdate,
)

from ipahcc import hccplatform, sign

logger = logging.getLogger(__name__)


REVOKED_MARKER = sign.KeyState.REVOKED.value


register = Registry()

# hide plugin from ipa CLI, unless we are in developer mode
NO_CLI = not hccplatform.DEVELOPMENT_MODE

HCC_ETC_DN = DN(("cn", "hcc"), ("cn", "etc"))
HCC_JWK_DN = DN(("cn", "jwk"), HCC_ETC_DN)


class JWKDictParam(Param):
    """JWKDict parameter

    Supports JSON string as input.
    """

    type = sign.JWKDict
    type_error = _("must be a public JWKDict")
    allowed_types = (
        sign.JWKDict,
        str,
    )

    def _convert_scalar(
        self,
        value: typing.Union[sign.JWKDict, str, dict],
        index: typing.Optional[int] = None,
    ) -> dict:
        if isinstance(value, sign.JWKDict):
            key = value
        elif isinstance(value, str):
            try:
                key = sign.load_key(value)
            except Exception as e:
                raise errors.ConversionError(
                    name=self.name, error=str(e)
                ) from None

        if key.has_private:
            raise errors.ConversionError(
                name=self.name, error=_("JWK with private key forbidden")
            ) from None

        return super()._convert_scalar(key, index)

    def _validate_scalar(
        self, value: sign.JWKDict, index: typing.Optional[int] = None
    ):
        super()._validate_scalar(value, index)
        sign.validate_key(value)


@register()
class hccjwk(LDAPObject):
    __doc__ = _(
        """
    Hybrid Cloud Console public JWKs
    """
    )

    container_dn = HCC_JWK_DN

    object_name = _("hccjwk")
    object_name_plural = _("hccjwks")
    object_class = ["HCCPublicJWKObject"]
    permission_filter_objectclasses = ["HCCPublicJWKObject"]

    default_attributes = [
        "cn",
        "hccpublicjwk",
        "ipatokennotafter",
        "ipakeyusage",
        "algorithmid",
        "ipaenabledflag",
    ]

    label = _("HCC public keys")
    label_singular = _("HCC public key")

    takes_params = (
        Str(
            "cn",
            cli_name="kid",
            label=_("KID"),
            doc=_("JWK key identifier"),
            primary_key=True,
        ),
        JWKDictParam(
            "hccpublicjwk",
            cli_name="jwk",
            label=_("JWK"),
            doc=_("Public JWK as JSON string"),
        ),
        DateTime(
            # We use ipaTokenNotAfter instead of notAfter because ipaldap has
            # correct syntax mappings for the IPA attribute.
            "ipatokennotafter?",
            label=_("Expiration"),
            doc=_("Expiration"),
            flags={"no_create", "no_update", "no_search"},
        ),
        StrEnum(
            "ipakeyusage?",
            values=("sig",),
            label=_("key usage"),
            doc=_("JWK key usage"),
            flags={"no_create", "no_update", "no_search"},
        ),
        StrEnum(
            "algorithmid?",
            values=("ES256",),
            label=_("Algorithm"),
            doc=_("JWK algorithm parameter"),
            flags={"no_create", "no_update", "no_search"},
        ),
        Bool(
            "ipaenabledflag",
            default=True,
            label=_("Enabled"),
            doc=_("Wether the key is enabled or disabled (revoked)"),
            flags={"no_create", "no_update", "no_search"},
        ),
        StrEnum(
            "state?",
            values=tuple(str(v) for v in sign.KeyState.__members__.values()),
            label=_("State"),
            doc=_("Key state (valid, expired, revoked, invalid)"),
            flags={"no_create", "no_update", "no_search"},
        ),
    )

    managed_permissions = {
        "System: Read HCC JWKs": {
            "ipapermlocation": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermtarget": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermright": {"read", "search", "compare"},
            "ipapermdefaultattr": {
                "objectclass",
                "cn",
                "hccpublicjwk",
                "ipatokennotafter",
                "ipaKeyUsage",
                "algorithmId",
                "ipaEnabledFlag",
            },
            "default_privileges": {hccplatform.HCC_ENROLLMENT_JWK_PRIVILEGE},
        },
        "System: Add HCC JWK": {
            "ipapermlocation": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermtarget": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermright": {"add"},
            "default_privileges": {hccplatform.HCC_ENROLLMENT_JWK_PRIVILEGE},
        },
        "System: Delete HCC JWK": {
            "ipapermlocation": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermtarget": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermright": {"delete"},
            "default_privileges": {hccplatform.HCC_ENROLLMENT_JWK_PRIVILEGE},
        },
        "System: Modify HCC JWK": {
            "ipapermlocation": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermtarget": DN(HCC_JWK_DN, api.env.basedn),
            "ipapermright": {"write"},
            "ipapermdefaultattr": {
                "objectclass",
                "cn",
                "hccpublicjwk",
                "ipaTokenNotAfter",
                "ipaKeyUsage",
                "algorithmId",
                "ipaEnabledFlag",
            },
            "default_privileges": {hccplatform.HCC_ENROLLMENT_JWK_PRIVILEGE},
        },
    }

    def decode_attrs(self, entry_attrs, **options):
        """Decode hccpublicjwk, populate state"""
        if options.get("raw"):
            return
        sv = entry_attrs.single_value
        hccpublicjwk = sv.get("hccpublicjwk")
        if not hccpublicjwk:
            # empty key is invalid
            sv["state"] = sign.KeyState.INVALID
        elif hccpublicjwk == REVOKED_MARKER:
            # literal string "revoked"
            sv["state"] = sign.KeyState.REVOKED
        else:
            try:
                # load to verify
                sign.load_key(hccpublicjwk)
            except sign.ExpiredKey:
                sv["state"] = sign.KeyState.EXPIRED
            except Exception:
                sv["state"] = sign.KeyState.INVALID
                logger.exception(
                    "Cannot decode hccpublicjwk of %s", entry_attrs.dn
                )
            else:
                sv["state"] = sign.KeyState.VALID

        if sv["state"] != sign.KeyState.VALID:
            sv["hccpublicjwk"] = f'<{sv["state"]}>'


@register()
class hccjwk_add(LDAPCreate):
    __doc__ = _("Add a new HCC public JWK.")

    msg_summary = _('Added JWK "%(value)s"')
    NO_CLI = NO_CLI

    def get_args(self):
        for key in super().get_args():
            # Do not require primary key, use JWK kid as CN
            if key.primary_key:
                yield key.clone(required=False)
            else:
                yield key

    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ):
        sv = entry_attrs.single_value
        pubkey: sign.JWKDict = options["hccpublicjwk"]

        # refuse primary key / cn that does not match the kid.
        kid = pubkey["kid"]
        if keys and keys[-1] != kid:
            raise errors.ValidationError(
                "kid", f"does not match JWK's kid '{kid}'"
            )

        sv["hccpublicjwk"] = pubkey.export_public()
        sv["ipakeyusage"] = pubkey["use"]
        sv["ipatokennotafter"] = datetime.datetime.fromtimestamp(
            pubkey["exp"]
        )
        sv["algorithmid"] = pubkey["alg"]
        sv["ipaenabledflag"] = True
        return super().pre_callback(
            ldap, dn, entry_attrs, attrs_list, *keys, **options
        )

    def execute(self, *keys, **options):
        # use JWK kid as primary key / cn
        keys = (options["hccpublicjwk"]["kid"],)
        return super().execute(*keys, **options)

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.decode_attrs(entry_attrs, **options)
        return super().post_callback(ldap, dn, entry_attrs, *keys, **options)


@register()
class hccjwk_del(LDAPDelete):
    __doc__ = _("Delete a HCC public JWK.")

    msg_summary = _('Deleted JWK "%(value)s"')
    NO_CLI = NO_CLI


@register()
class hccjwk_revoke(LDAPUpdate):
    __doc__ = _("Revoke a HCC public JWK.")

    msg_summary = _('Revoked JWK "%(value)s"')
    NO_CLI = NO_CLI

    def get_options(self):
        base_options = {p.name for p in self.obj.takes_params}
        for option in super().get_options():
            if option.name not in base_options:
                # raw, version
                yield option.clone()

    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ):
        if "rename" in options or "cn" in entry_attrs:
            raise errors.ProtectedEntryError(
                label=self.obj_name,
                key=keys[-1],
                reason="Cannot be renamed",
            )
        entry_attrs["hccpublicjwk"] = REVOKED_MARKER
        entry_attrs["ipaenabledflag"] = False
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.decode_attrs(entry_attrs, **options)
        entry_attrs["dn"] = dn
        return super().post_callback(ldap, dn, entry_attrs, *keys, **options)


@register()
class hccjwk_find(LDAPSearch):
    __doc__ = _("Search for HCC public JWKs.")

    msg_summary = ngettext(
        "%(count)d JWK matched", "%(count)d JWKs matched", 0
    )

    takes_options = LDAPSearch.takes_options + (
        Flag(
            "valid",
            cli_name="valid",
            doc=_("search for valid public keys"),
        ),
    )

    NO_CLI = NO_CLI

    def pre_callback(
        self, ldap, filters, attrs_list, base_dn, scope, *args, **options
    ):
        assert isinstance(base_dn, DN)

        if options["valid"]:
            # add filter for non-expired, non-revoked entries
            now = datetime.datetime.now(datetime.timezone.utc)
            valid_filters = [
                filters,
                "(ipaenabledflag=TRUE)",
                f"(ipatokennotafter<={ldap.encode(now)})",  # sic!
            ]
            filters = ldap.combine_filters(
                valid_filters, rules=ldap.MATCH_ALL
            )
        return filters, base_dn, scope

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry_attrs in entries:
            self.obj.decode_attrs(entry_attrs, **options)
        return super().post_callback(
            ldap, entries, truncated, *args, **options
        )


@register()
class hccjwk_show(LDAPRetrieve):
    __doc__ = _("Display information about a HCC public JWK.")

    NO_CLI = NO_CLI

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.decode_attrs(entry_attrs, **options)
        return super().post_callback(ldap, dn, entry_attrs, *keys, **options)

#
# IPA plugin for Red Hat Hybrid Cloud Console
# Copyright (C) 2023  Christian Heimes <cheimes@redhat.com>
# See COPYING for license
#
"""IdP provider for Red Hat Hybrid Cloud Console

External IdP needs a registered client id. See "External SSO Enablements" in
the CIAM section on Source how to request a client id for an OAuth app. IPA
and SSSD use RFC 8628 Device Authorization flow to authenticate logins on
hosts. It is considered a RFC 6749 native application and public client.
Therefore it does not use authentication with a client secret.

ipa idp-add --provider=sso.redhat.com --client-id=YOUR_CLIENT_ID ssorhc
ipa user-mod --user-auth-type=idp --idp=ssorhc --idp-user-id=YOUR_SSO_LOGIN YOUR_USER

The `openid` is required since Keycloak 19.0.2. Otherwise userinfo requests
are failing with `403 insufficient_scope`
https://www.keycloak.org/docs/latest/upgrading/index.html#userinfo-endpoint-changes

The `openid` scope includes (amongst others) `organization.id`, `email`, and
`preferred_username`.
"""
from ipalib.text import _
from ipaserver.plugins.idp import idp_add
from ipaserver.plugins.internal import i18n_messages

from ipahcc import hccplatform

# pylint: disable=line-too-long
SSO_PROVIDERS = {
    "sso.redhat.com": {
        "ipaidpauthendpoint": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth",
        "ipaidpdevauthendpoint": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth/device",
        "ipaidptokenendpoint": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        "ipaidpuserinfoendpoint": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/userinfo",
        "ipaidpkeysendpoint": "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs",
        "ipaidpscope": "openid",
        "ipaidpsub": "preferred_username",
    }
}

if hccplatform.DEVELOPMENT_MODE:
    SSO_PROVIDERS["sso.stage.redhat.com"] = {
        "ipaidpauthendpoint": "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth",
        "ipaidpdevauthendpoint": "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/auth/device",
        "ipaidptokenendpoint": "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
        "ipaidpuserinfoendpoint": "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/userinfo",
        "ipaidpkeysendpoint": "https://sso.stage.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs",
        "ipaidpscope": "openid",
        "ipaidpsub": "preferred_username",
    }

idp_add.idp_providers.update(SSO_PROVIDERS)


def hcc_get_options(self):
    for option in orig_get_options(self):
        if option.name == "ipaidpprovider":
            yield option.clone(values=tuple(idp_add.idp_providers))
        else:
            yield option


orig_get_options = idp_add.get_options
idp_add.get_options = hcc_get_options  # type: ignore

i18n_messages.messages["objects"]["idp"].update(
    template_sso_redhat_com=_("sso.redhat.com"),
    template_sso_stage_redhat_com=_("sso.stage.redhat.com"),
)

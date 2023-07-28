from .baseldap import (
    LDAPCreate as LDAPCreate,
    LDAPDelete as LDAPDelete,
    LDAPObject as LDAPObject,
    LDAPRetrieve as LDAPRetrieve,
    LDAPSearch as LDAPSearch,
    LDAPUpdate as LDAPUpdate,
)
from _typeshed import Incomplete
from collections.abc import Generator

logger: Incomplete
register: Incomplete

def normalize_baseurl(url): ...
def validate_uri(ugettext, uri): ...

class idp(LDAPObject):
    container_dn: Incomplete
    object_name: Incomplete
    object_name_plural: Incomplete
    object_class: Incomplete
    default_attributes: Incomplete
    search_attributes: Incomplete
    allow_rename: bool
    label: Incomplete
    label_singular: Incomplete
    takes_params: Incomplete
    permission_filter_objectclasses: Incomplete
    managed_permissions: Incomplete

class idp_add(LDAPCreate):
    __doc__: Incomplete
    msg_summary: Incomplete
    idp_providers: Incomplete
    takes_options: Incomplete
    def get_options(self) -> Generator[Incomplete, None, None]: ...
    def pre_callback(
        self, ldap, dn, entry_attrs, attrs_list, *keys, **options
    ): ...

class idp_del(LDAPDelete):
    __doc__: Incomplete
    msg_summary: Incomplete

class idp_mod(LDAPUpdate):
    __doc__: Incomplete
    msg_summary: Incomplete

class idp_find(LDAPSearch):
    __doc__: Incomplete
    msg_summary: Incomplete
    def get_options(self) -> Generator[Incomplete, None, None]: ...

class idp_show(LDAPRetrieve):
    __doc__: Incomplete

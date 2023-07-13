from _typeshed import Incomplete

UUID_RE: str
UUID_ERRMSG: str
hcc_host_class: str
hcc_host_attributes: Incomplete
takes_params: Incomplete

def get_config_orgid(ldap): ...
def check_hcc_attr(ldap, dn, entry) -> None: ...
def host_add_hcc_precb(
    self, ldap, dn, entry, attrs_list, *keys, **options
): ...
def host_mod_hcc_precb(
    self, ldap, dn, entry, attrs_list, *keys, **options
): ...

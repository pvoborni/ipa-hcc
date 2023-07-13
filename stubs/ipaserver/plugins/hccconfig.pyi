from _typeshed import Incomplete

hcc_config_class: str
hcc_config_attributes: Incomplete
takes_params: Incomplete

def config_show_hcc_postcb(self, ldap, dn, entry_attrs, *keys, **options): ...
def config_mod_hcc_precb(
    self, ldap, dn, entry, attrs_list, *keys, **options
): ...
def config_mod_hcc_postcb(self, ldap, dn, entry_attrs, *keys, **options): ...
def config_mod_hcc_exccb(
    self, keys, options, exc, call_func, *call_args, **call_kwargs
) -> None: ...

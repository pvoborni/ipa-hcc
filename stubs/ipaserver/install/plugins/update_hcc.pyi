from _typeshed import Incomplete
from ipalib import Updater

logger: Incomplete
register: Incomplete

class update_hcc(Updater):
    def modify_krb5kdc_conf(self): ...
    def configure_global_hcc_orgid(self, org_id): ...
    def configure_host_rhsm_id(self, rhsm_id): ...
    def execute(self, **options): ...
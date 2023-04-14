from copy import copy
from ldap3 import SUBTREE

from plugins.__HXAD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADGuestEnable(PluginADScanBase):
    """内置guest帐户已启用"""

    display = "内置guest帐户已启用"
    alias = "GuestEnable"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)

        query = "(cn=guest)"
        attributes = ["cn", "UserAccountControl"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)
        instance_list = []
        instance = {}

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            else:
                uac = entry["attributes"]["UserAccountControl"]
                if uac & 2 == 0:
                    result['status'] = 1
                    instance['guest账户是否启用'] = "是"
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result


from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADKerberosDelegation(PluginADScanBase):
    """可以使用Kerberos委派通过受信任的域林来控制当前域林"""

    display = "可以使用Kerberos委派通过受信任的域林来控制当前域林"
    alias = "TGTDelegation"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)

        query = "(objectclass=trusteddomain)"
        attributes = [
            "cn", "trustDirection",
            "trustAttributes", "trustPartner"
        ]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        instance_list = []

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["trustDirection"] == 0 or entry["attributes"]["trustDirection"] == 2:
                continue
            else:
                if (entry["attributes"]["trustAttributes"] & 0x00000008 != 0) and (
                        entry["attributes"]["trustAttributes"] & 0x00000200
                        == 0) and (entry["attributes"]["trustAttributes"] & 0x00000800 != 0):
                    result['status'] = 1
                    instance = {}
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result


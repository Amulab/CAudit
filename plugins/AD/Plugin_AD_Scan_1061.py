from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADExitUD(PluginADScanBase):
    """检查域内是否存在非约束委派"""

    display = "检查域内是否存在非约束委派的账户"
    alias = "ExistUnconstrainedDelegation"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        query = "(&(objectclass=*)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(|(primarygroupid=516)(primarygroupid=521))))"
        attributes = ["cn", "distinguishedName"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            result['status'] = 1
            instance = {}
            instance["名称"] = entry["attributes"]["cn"]
            instance["DN"] = entry["attributes"]["distinguishedName"]
            instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result


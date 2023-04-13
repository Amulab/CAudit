from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNoRecycleBinDC(PluginADScanBase):
    """`域控制器没有启用回收站功能"""

    display = "域控制器没有启用回收站功能"
    alias = "no_recycle_bin_dc"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        # 另一种查找方式是直接查msDS-EnabledFeature属性，
        # 配了之后会出现在”CN=Partitions,CN=Configuration,DC=test12,DC=local“和
        # ”CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=test12,DC=local“
        # （上一个位置是固定的，这一个不固定）
        query = "(objectclass=*)"
        attributes = ["cn", "msDS-EnabledFeature", "distinguishedName"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(
            search_base="CN=Configuration," + self.ldap_cli.domain_dn,
            search_filter=query,
            search_scope=SUBTREE,
            get_operational_attributes=True,
            attributes=attributes,
            paged_size=1000,
            generator=True)

        s = ""
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            msDSEnabledFeature = str(
                entry["attributes"]["msDS-EnabledFeature"])
            s = s + msDSEnabledFeature
        if "['CN=Recycle Bin Feature," not in s:
            result['status'] = 1
            instance_list.append({"ip address":self.dc_ip})

        result['data'] = {"instance_list": instance_list}
        return result

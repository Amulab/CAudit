from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADSIDHistoryEnable(PluginADScanBase):
    """启用`SIDHistory`创建功能"""

    display = "启用`SIDHistory`创建功能"
    alias = "域迁移之后审核组未删除"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(objectClass=group)"
        attributes = ["cn", "sAMAccountName", "distinguishedName"]
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
            group = entry["attributes"]["sAMAccountName"]
            ret = group.find('-$$$')
            if ret != -1:
                result['status'] = 1
                instance = {}
                instance["名称"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result


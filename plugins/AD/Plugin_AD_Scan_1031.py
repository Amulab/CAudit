from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADDuplicateAccount(PluginADScanBase):
    """存在重复的账户"""
    # 出现原因是不同用户登录不同域控同时添加同一账户，域控之间同步导致的，添加后有的账户只有"CNF"字段，有的账户有"CNF"的同时
    # 在SAMAccountName里也有"$DUPLICATE-"字段

    display = "存在重复的账户"
    alias = "dup_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=user)(|(cn=*cnf:*)(SAMAccountName=*$duplicate-*)))"
        attributes = ["cn", "distinguishedName", "SAMAccountName"]

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
            instance = {}
            result['status'] = 1
            instance["用户名"] = entry["attributes"]["cn"]
            instance["DN"] = entry["attributes"]["distinguishedName"]
            instance["SAMAccountName"] = entry["attributes"]["SAMAccountName"]
            instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

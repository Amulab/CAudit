from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADEmptyAccountOperators(PluginADScanBase):
    """`操作员组不为空"""

    display = "操作员组不为空"
    alias = "ept_act_opts"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        # query = "(&(objectclass=group)(|(sAMAccountName=Account Operators)(sAMAccountName=Server Operators)))"
        query = "(&(objectclass=group)(|(sAMAccountName=Account Operators)(sAMAccountName=Server Operators)(sAMAccountName=Access Control Assistance Operators)(sAMAccountName=Backup Operators)(sAMAccountName=Cryptographic Operators)(sAMAccountName=Network Configuration Operators)(sAMAccountName=Print Operators)))"
        attributes = ["cn", "member", "distinguishedName"]

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
            if entry["attributes"]["member"] != None:
                for member_res in entry["attributes"]["member"]:
                    result['status'] = 1
                    instance = {}
                    instance["组名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["成员"] = member_res
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

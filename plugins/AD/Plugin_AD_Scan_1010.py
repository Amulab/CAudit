from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNoPreAuth(PluginADScanBase):
    """
    存在不需要kerberos预身份验证的账户

    参数:
    :param: domain
    :param: username
    :param: password
    """

    display = "存在不需要kerberos预身份验证的账户"
    alias = "no_pre_auth"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(|(objectclass=computer)(objectclass=user))(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
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
            if entry != None:
                result['status'] = 1
                instance = {"名称": entry["attributes"]["cn"], "DN": entry["attributes"]["distinguishedName"]}
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

from copy import copy

from ldap3 import SUBTREE

from plugins.__HXAD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNormalUser(PluginADScanBase):
    """“存在异常域控制器机器账户"""

    display = "存在异常域控制器机器账户"
    alias = "ADnormalUser"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(|(primarygroupid=516)(primarygroupid=521))"
        attributes = ["cn", "distinguishedName", "servicePrincipalName"]

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

            if entry["attributes"]["servicePrincipalName"] == []:
                result['status'] = 1
                instance = {}
                instance["组名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result




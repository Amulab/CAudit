from copy import copy

from ldap3 import SUBTREE



from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADExceptPrimaryGPAttr(PluginADScanBase):
    """计算机帐户的primarygroup属性异常"""

    display = "计算机帐户的primarygroup属性异常"
    alias = "excep_primgp_attr"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(objectclass=computer)"
        attributes = ["cn", "primaryGroupID", "distinguishedName"]

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
            distinguishedName = str(entry["attributes"]["distinguishedName"])
            ret = distinguishedName.find("OU=Domain Controllers")
            if ret == -1 and (entry["attributes"]["primaryGroupID"] == 516 or entry["attributes"]["primaryGroupID"] == 521):
                result['status'] = 1
                instance = {}
                instance["主机名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["primaryGroupID"] = entry["attributes"]["primaryGroupID"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

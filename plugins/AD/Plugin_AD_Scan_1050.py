from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADAnonymousUserOperateLDAP(PluginADScanBase):
    """匿名用户可以执行任何 LDAP 操作"""

    display = "匿名用户可以执行任何 LDAP 操作"
    alias = "anony_u_op_ldap"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        search_base = "CN=Configuration," + self.ldap_cli.domain_dn
        query = f"(distinguishedName=CN=Directory Service,CN=Windows NT,CN=Services,{search_base})"
        attributes = ["cn", "distinguishedName", "DSHeuristics"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            # distinguishedName1 = str(entry["attributes"]["distinguishedName"])
            # ret = distinguishedName1.find(
            #     "CN=Directory Service,CN=Windows NT,CN=Services")
            str1 = entry["attributes"]["DSHeuristics"]
            # if ret != -1 and len(entry["attributes"]["DSHeuristics"]) >= 7 and str(
            #         str1[6:7]) == "2":
            if len(entry["attributes"]["DSHeuristics"]) >= 7 and str(
                    str1[6:7]) == "2":
                result['status'] = 1
                instance = {}
                instance["名称"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

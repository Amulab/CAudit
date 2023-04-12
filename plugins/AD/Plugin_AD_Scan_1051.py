from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADDisablefDoListObject(PluginADScanBase):
    """fDoListObject未启用"""

    display = "fDoListObject未启用"
    alias = "disab_f_dolistobject"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        search_base = "CN=Configuration," + self.ldap_cli.domain_dn
        query = f"(distinguishedName=CN=Directory Service,CN=Windows NT,CN=Services,{search_base})"
        attributes = ["cn", "dSHeuristics", "distinguishedName"]

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
            if entry["attributes"]["dSHeuristics"] != None:
                dsh = entry["attributes"]["DSHeuristics"]
                # if len(entry["attributes"]["DSHeuristics"]) >= 3 and str(str1[2:3]) != "0":
                if len(dsh) >= 3 and str(dsh[2:3]) != "1":  # 强制启用为1，不为1则是false，默认为0，未启用就是非1
                    result['status'] = 1
                    instance = {}
                    instance["名称"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

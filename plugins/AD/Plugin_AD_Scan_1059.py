from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADConstrainedDelegationWithDC(PluginADScanBase):
    """存在配置了约束委派的DC"""

    display = "存在配置了约束委派的DC"
    alias = "cs_dele_dc"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=computer)(|(primaryGroupID=516)(primaryGroupID=521)))"
        attributes = ["cn", "distinguishedName", "msDS-AllowedToDelegateTo"]

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
            if isinstance(entry["attributes"]["msDS-AllowedToDelegateTo"], list) and len(
                    entry["attributes"]["msDS-AllowedToDelegateTo"]) != 0:
                result['status'] = 1
                instance["主机名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["msDS-AllowedToDelegateTo"] = entry["attributes"]["msDS-AllowedToDelegateTo"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

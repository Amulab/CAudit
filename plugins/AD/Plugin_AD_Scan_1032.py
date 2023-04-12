from copy import copy

from ldap3 import SUBTREE



from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADIllegalMAQ(PluginADScanBase):
    """MAQ值配置风险"""

    display = "MAQ值配置风险"
    alias = "i_maq"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(objectclass=domain)"
        attributes = [
            "distinguishedName",
            "ms-DS-MachineAccountQuota", "cn"
        ]

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
            MachineAccountQuota = entry["attributes"]["ms-DS-MachineAccountQuota"]
            if int(MachineAccountQuota) > 0:
                result['status'] = 1
                instance = {}
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["MAQ"] = entry["attributes"][
                    "ms-DS-MachineAccountQuota"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

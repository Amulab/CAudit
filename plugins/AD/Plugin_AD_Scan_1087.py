from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADRODCNeverReveal(PluginADScanBase):
    """“防止泄露特权组的保护措施不处于活动状态"""

    display = "防止泄露特权组的保护措施”不处于活动状态"
    alias = "RODCNeverReveal"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        # 521 – Domain Controllers (Read-Only)
        query = "(&(objectclass=computer)(primaryGroupID=521))"
        attributes = ["cn", "msDS-NeverRevealGroup", "distinguishedName"]
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
            # msDS-NeverRevealGroup: Points to the distinguished names of security principals that are denied replication to the RODC.
            if entry["attributes"]["msDS-NeverRevealGroup"] != None:
                msDSNeverRevealGroup = str(
                    entry["attributes"]["msDS-NeverRevealGroup"])
                ret1 = msDSNeverRevealGroup.find("Administrators")
                ret2 = msDSNeverRevealGroup.find("Server Operators")
                ret3 = msDSNeverRevealGroup.find("Account Operators")
                ret4 = msDSNeverRevealGroup.find("Backup Operators")
                if ret1 != -1 and ret2 != -1 and ret3 != -1 and ret4 != -1:
                    continue
                else:
                    result['status'] = 1
                    instance = {}
                    instance["名称"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["NeverRevealGroup"] = entry["attributes"]["msDS-NeverRevealGroup"]
                    instance_list.append(instance)
                    result['data'] = {"instance_list": instance_list}

        return result


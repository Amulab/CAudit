from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADRodcDisplayPrivilegeAccount(PluginADScanBase):
    """RODC上可以显示特权用户"""

    display = "RODC上可以显示特权用户"
    alias = "rodc_dp_priv_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectCategory=person)(objectclass=user)(admincount=1))"
        attributes = ["cn", "DistinguishedName"]

        attributes1 = ["cn", "DistinguishedName", "objectSid"]
        entry_generator1, des_dict1 = self.ldap_cli.search_admins_info(attributes1)

        query = "(&(objectclass=computer)(primaryGroupID=521))"
        attributes = ["cn", "msDS-RevealedUsers", "distinguishedName", "objectSid"]

        entry_generator2 = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                          search_filter=query,
                                                                          search_scope=SUBTREE,
                                                                          get_operational_attributes=True,
                                                                          attributes=attributes,
                                                                          paged_size=1000,
                                                                          generator=True)

        entry_generator2_list = list(entry_generator2)
        for entry in entry_generator2_list:
            if entry["type"] != "searchResEntry":
                continue
            if len(entry["attributes"]["msDS-RevealedUsers"]) == 0:
                continue
            for j in entry["attributes"]["msDS-RevealedUsers"]:
                flag = 0
                for entry2 in entry_generator1:
                    if entry2["type"] != "searchResEntry":
                        continue
                    cn = str(entry2["attributes"]["cn"])
                    ret = str(j).find('CN=' + cn + ',')
                    if ret != -1:
                        result['status'] = 1
                        instance = {}
                        instance["用户"] = cn
                        instance["DN"] = entry2["attributes"]["distinguishedName"]
                        instance["描述"] = des_dict1.get(entry2["attributes"]["objectSid"], '')
                        instance_list.append(instance)
                        flag = 1
                        break
                    else:
                        continue
                if flag == 1:
                    break
        result['data'] = {"instance_list": instance_list}
        return result

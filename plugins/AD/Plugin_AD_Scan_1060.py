from copy import copy

from ldap3 import SUBTREE



from impacket.ldap.ldaptypes import  SR_SECURITY_DESCRIPTOR

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADExistDCRBCD(PluginADScanBase):
    """存在配置了基于资源的约束委派的DC"""

    display = "存在配置了基于资源的约束委派的DC"
    alias = "ExistDCRBCD"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        if self.dc_platform == "Windows Server 2008 R2 Enterprise":
            return result
        instance_list = []

        query = "(&(objectclass=computer)(primaryGroupID=516))"
        attributes = [
                "cn", "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "distinguishedName"
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
            if len(entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]) > 0:
                result['status'] = 1
                instance = {}
                instance["主机名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]

                AllowedToActOnBehalfOfOtherIdentity = entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]
                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(AllowedToActOnBehalfOfOtherIdentity)
                for ace in sd['Dacl'].aces:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    instance["配置SID"] = sid

                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result




from copy import copy

import ldap3.core.exceptions
from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR


class PluginADRBCDProtTransform(PluginADScanBase):
    """存在基于资源的约束委派（协议转换）"""

    display = "存在基于资源的约束委派（协议转换）"
    alias = "rbcd_prot_tns"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(|(objectclass=computer)(objectclass=user))"
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

        try:
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
        except ldap3.core.exceptions.LDAPAttributeError as e:
            # 域控没有这个属性的时候会在for循环报错
            result["status"] = 0

        result['data'] = {"instance_list": instance_list}
        return result

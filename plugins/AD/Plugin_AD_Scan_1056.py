from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADWin2kCompatibleAccess(PluginADScanBase):
    """Windows 2000以前版本的兼容访问”组是否未从其默认值中被修改"""

    display = "”Windows 2000以前版本的兼容访问”组是否未从其默认值中被修改"
    alias = "win2k_cmpb_acs"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=group)(!(member=null)))"
        attributes = ["cn", "distinguishedName", "member"]

        search = "CN=Pre-Windows 2000 Compatible Access,CN=Builtin," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=search,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["member"] != None:

                member1 = entry["attributes"]["member"]
                for s in member1:
                    if "CN=S-1-5-11,CN=ForeignSecurityPrincipals," not in s:
                        result['status'] = 1
                        instance = {}
                        instance["组名"] = entry["attributes"]["cn"]
                        instance["DN"] = entry["attributes"]["distinguishedName"]
                        instance["成员"] = s
                        instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADIllegalPreW2kCompatibleAccessGroup(PluginADScanBase):
    """Pre-Windows 2000 Compatible Access组存在异常组成员"""

    display = "Pre-Windows 2000 Compatible Access组存在异常组成员"
    alias = "i_pre_w2k_cptb_acs"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=group)(!(member=null)))"
        attributes = ["cn", "distinguishedName", "member"]

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
            # if not entry.get('raw_attributes'):
            #     continue
            distinguishedName1 = str(entry["attributes"]["distinguishedName"])
            ret = distinguishedName1.find(
                "CN=Pre-Windows 2000 Compatible Access,CN=Builtin,")
            member1 = str(entry["attributes"]["member"])
            ret1 = member1.find("S-1-5-7")  # Anonymous Logon
            ret2 = member1.find("S-1-1-0")  # everyone

            if ret != -1 and (ret1 != -1 or ret2 != -1):
                for member_res in entry["attributes"]["member"]:
                    result['status'] = 1
                    instance = {}
                    instance["组名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["成员"] = member_res
                    instance_list.append(instance)
                break

        result['data'] = {"instance_list": instance_list}
        return result

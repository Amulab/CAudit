from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADFindUnixUserPwdAndUserPwd(PluginADScanBase):
    """存在unixUserPassword和userPassword属性"""

    display = "存在unixUserPassword和userPassword属性"
    alias = "fd_unix_u_pwd"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=*)(|(unixUserPassword=*)(userPassword=*)))"
        attributes = [
            "cn", "unixUserPassword",
            "userPassword", "distinguishedName"
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
            if len(entry["attributes"]["unixUserPassword"]) > 0 or len(entry["attributes"]["userPassword"]) > 0:
                result['status'] = 1
                instance = {}
                instance["名称"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["UnixUserPassword"] = entry["attributes"]["unixUserPassword"]
                instance["UserPassword"] = entry["attributes"]["userPassword"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

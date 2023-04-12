from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADLowVersionComputerWinNT(PluginADScanBase):
    """存在过低的操作系统版本（Windows-NT）"""

    display = "存在过低的操作系统版本（Windows-NT）"
    alias = "low_ver_cpt_win_nt"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=computer)(operatingSystem=Windows NT*))"  # 这个不修改为包含"NT"，因为datecenter包含这个字符串

        attributes = ["cn", "operatingSystem", "distinguishedName", "pwdlastset", "lastlogontimestamp"]

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
            if entry == None:
                continue
            instance = {}
            if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                    entry["attributes"]["lastLogonTimestamp"]) == 0:
                result['status'] = 1
                instance["主机名"] = entry["attributes"]["cn"]
                instance["操作系统版本"] = entry["attributes"]["operatingSystem"]
                instance["上次登陆时间"] = "该计算机账户从未登陆过"
                instance_list.append(instance)
            else:
                result['status'] = 1
                instance["主机名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["操作系统版本"] = entry["attributes"]["operatingSystem"]
                instance["上次登陆时间"] = entry["attributes"]["lastlogontimestamp"]
                instance["上次密码修改时间"] = entry["attributes"]["pwdlastset"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

from copy import copy

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADPwdNeverExpiresPrivilegeAccount(PluginADScanBase):
    """存在密码永不过期的特权账号"""

    display = "存在密码永不过期的特权账号"
    alias = "nver_expire_priv_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        attributes = ["cn", "distinguishedName", "objectSid"]
        query = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            flag = str(entry["attributes"]["cn"]).find("krbtgt")
            if flag == -1:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

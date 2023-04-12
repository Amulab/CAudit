from copy import copy

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADDelegatedPrivilegedAccount(PluginADScanBase):
    """特权账号帐户可以被委派"""

    display = "特权账号帐户可以被委派"
    alias = "dele_priv_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        attributes = ["cn", "memberof", "distinguishedName", "objectSid"]
        query = "(!(userAccountControl:1.2.840.113556.1.4.803:=1048576))"  # NOT_DELEGATED  1048576 - 设置此标志时，即使将服务帐户设置为 Kerberos 委派的受信任帐户，用户的安全上下文也不会委派给服务。
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["cn"] != "krbtgt":
                memberof1 = (str(entry["attributes"]["memberof"]))
                ret = memberof1.find("Protected Users")
                if ret == -1:
                    result['status'] = 1
                    instance = {}
                    instance["用户名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

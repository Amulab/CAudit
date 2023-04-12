from copy import copy

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNotAdminGroupPrivilegeAccount(PluginADScanBase):
    """
    存在不属于管理员组的特权账户
    """

    display = "存在不属于管理员组的特权账户"
    alias = "not_adm_gp_priv_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        attributes = ["cn", "distinguishedName", "objectSid", "memberOf"]
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            member = str(entry["attributes"]["memberOf"])

            name = entry["attributes"]["cn"]

            if member.find("Administrators") != -1 or member.find("Domain Admins") != -1 or member.find("Enterprise Admins") != -1 or member.find("DnsAdmins") != -1:
                continue
            else:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                instance_list.append(instance)

        if result['status'] == 1:
            result['data'] = {"instance_list": instance_list}
        return result

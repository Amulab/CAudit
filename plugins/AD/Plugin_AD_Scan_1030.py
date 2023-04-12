from copy import copy



from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNotProtectAccount(PluginADScanBase):
    """存在不在`Protected Users`组中的特权帐户"""

    display = "存在不在`Protected Users`组中的特权帐户"
    alias = "act_no_in_protected_users"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        attributes = [
            "cn", "adminCount", "memberof",
            "distinguishedName", "objectSid"
        ]
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)

        for entry in entry_generator:

            if entry["type"] != "searchResEntry":
                continue
            memberof1 = (str(entry["attributes"]["memberof"]))
            ret = memberof1.find("Protected Users")
            if ret == -1:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                # instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

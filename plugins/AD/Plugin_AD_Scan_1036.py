from copy import copy
import datetime
import time



from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADIllegalPrivilegedAccount(PluginADScanBase):
    """存在无效的特权账号帐户"""

    display = "存在无效的特权账号帐户"
    alias = "i_priv_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_lastLogon_day = 180

        attributes = [
            "cn", "adminCount", "userAccountControl", "lastLogonTimestamp",
            "distinguishedName", "whenCreated", "objectSid"
        ]
        query = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["cn"] != "krbtgt":
                if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                        entry["attributes"]["lastLogonTimestamp"]) == 0:

                    result['status'] = 1
                    instance = {}
                    instance["用户名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["创建时间"] = entry["attributes"]["whenCreated"]
                    instance["上次登陆时间"] = "该用户未登陆过"
                    instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                    instance_list.append(instance)

                else:
                    lastLogon = entry["attributes"]["lastLogonTimestamp"]
                    lastLogon1, lastLogon2, lastLogon3 = (
                        str(lastLogon).partition(' '))
                    time_lastLogon = time.strptime(lastLogon1, "%Y-%m-%d")
                    time_lastLogon = datetime.datetime(
                        time_lastLogon[0], time_lastLogon[1],
                        time_lastLogon[2])
                    num_days = datetime.datetime.now() - time_lastLogon
                    if num_days.days > min_lastLogon_day:
                        result['status'] = 1
                        instance = {}
                        instance["用户名"] = entry["attributes"]["cn"]
                        instance["DN"] = entry["attributes"][
                            "distinguishedName"]
                        instance["创建时间"] = entry["attributes"]["whenCreated"]
                        instance["上次登陆时间"] = entry["attributes"]["lastLogonTimestamp"]
                        instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                        instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

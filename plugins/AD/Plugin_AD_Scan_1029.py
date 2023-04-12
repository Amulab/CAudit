from copy import copy
import datetime
import time

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADPwdNoChangePrivilegeAccount(PluginADScanBase):
    """特权账户密码没有定期修改"""

    display = "特权账户密码没有定期修改"
    alias = "pwd_no_change_priv_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_created_day = 0
        min_pwdLastSet_day = 90
        query = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        attributes = [
            "cn", "whenCreated", "adminCount",
            "pwdLastSet", "distinguishedName", "objectSid"
        ]

        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            whenCreated = entry["attributes"]["whenCreated"]
            pwdLastSet = entry["attributes"]["pwdLastSet"]
            whenCreated1, whenCreated2, whenCreated3 = (
                str(whenCreated).partition(' '))
            pwdLastSet1, pwdLastSet2, pwdLastSet3 = (
                str(pwdLastSet).partition(' '))
            time_whenCreated = time.strptime(whenCreated1, "%Y-%m-%d")
            time_whenCreated = datetime.datetime(
                time_whenCreated[0], time_whenCreated[1],
                time_whenCreated[2])
            time_pwdLastSet = time.strptime(pwdLastSet1, "%Y-%m-%d")
            time_pwdLastSet = datetime.datetime(
                time_pwdLastSet[0], time_pwdLastSet[1],
                time_pwdLastSet[2])
            num_days1 = datetime.datetime.now() - time_whenCreated
            num_days2 = datetime.datetime.now() - time_pwdLastSet

            if num_days1.days > min_created_day and num_days2.days > min_pwdLastSet_day:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["创建时间"] = entry["attributes"]["whenCreated"]
                instance["上次密码修改时间"] = entry["attributes"]["pwdLastSet"]
                instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

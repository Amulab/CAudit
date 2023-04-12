import datetime
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADPwdNoChange90(PluginADScanBase):
    """
    存在超过3个月未更改密码的计算机帐户
    """

    display = "存在超过3个月未更改密码的计算机帐户"
    alias = "pwd_no_change_90"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        max_password_day = 90

        query = "(objectclass=computer)"
        attributes = ["cn", "lastLogonTimestamp",
                      "pwdLastSet", "distinguishedName", "whenCreated"]

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

            pwdLastSet = entry["attributes"]["pwdLastSet"]
            time_pwdLastSet = datetime.datetime.combine(pwdLastSet, datetime.time.min)
            localtime = datetime.datetime.now()
            time_da1 = localtime - time_pwdLastSet
            if time_da1.days > max_password_day:
                if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                        entry["attributes"]["lastLogonTimestamp"]) == 0:
                    result['status'] = 1
                    instance = {"主机名": entry["attributes"]["cn"], "DN": entry["attributes"]["distinguishedName"],
                                "活跃": "True",
                                "创建时间": entry["attributes"]["whenCreated"],
                                "上次登陆时间": "该计算机账户从未登陆过",
                                "上次密码更改时间": entry["attributes"]["pwdLastSet"]}
                    instance_list.append(instance)
                else:
                    result['status'] = 1
                    instance = {}
                    instance["主机名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["活跃"] = "True"
                    instance["上次登陆时间"] = entry["attributes"]["lastLogonTimestamp"]
                    instance["创建时间"] = entry["attributes"]["whenCreated"]
                    instance["上次密码更改时间"] = entry["attributes"]["pwdLastSet"]
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

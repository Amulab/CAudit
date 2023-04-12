from copy import copy
from ldap3 import SUBTREE
import datetime

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADPwdNoChange45(PluginADScanBase):
    """
    存在超过45天未更改密码的计算机帐户
    """

    display = "存在超过45天未更改密码的计算机帐户"
    alias = "pwd_no_change"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_password_day = int(self.meta_data["min_password_day"])

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

            instance = {"计算机名": entry["attributes"]["cn"], "DN": entry["attributes"]["distinguishedName"],
                        "是否激活": "True",
                        "创建时间": entry["attributes"]["whenCreated"]}
            pwdLastSet = entry["attributes"]["pwdLastSet"]
            time_lastpwdset = datetime.datetime.combine(pwdLastSet, datetime.time.min)
            localtime = datetime.datetime.now()
            num_d1 = localtime - time_lastpwdset
            #print(entry["attributes"]["cn"],time_lastpwdset,num_d1.days)

            if num_d1.days > min_password_day:
                if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                        entry["attributes"]["lastLogonTimestamp"]) == 0:
                    result['status'] = 1
                    instance["上次登陆时间"] = "该计算机账户从未登陆过"
                    instance["上次更改密码时间"] = entry["attributes"]["pwdLastSet"]
                    instance_list.append(instance)
                else:
                        result['status'] = 1
                        instance["上次登陆时间"] = entry["attributes"]["lastLogonTimestamp"]
                        instance["上次更改密码时间"] = entry["attributes"]["pwdLastSet"]
                        instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

import datetime
import time
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADInactiveUser(PluginADScanBase):
    """域内存在无用或长时间非活跃的用户帐户"""
    display = "域内存在无用或长时间非活跃的用户帐户"
    alias = "i_user"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_created_day = 180
        min_logon_day = 180

        # 通过objectCategory=person和objectclass=user来筛选用户，通过！（userAccountControl:1.2.840.113556.1.4.803:=2）来筛选已启用的用户
        query = "(&(objectCategory=person)(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = [
            "cn", "lastLogonTimestamp", "pwdLastSet", "distinguishedName",
            "whenCreated"
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

            flag = str(entry["attributes"]["cn"]).find("HealthMailbox")
            # name = entry["attributes"]["cn"]

            if flag == -1:
                if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                        entry["attributes"]["lastLogonTimestamp"]) == 0:
                    result['status'] = 1
                    instance = {}
                    instance["用户名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["创建时间"] = entry["attributes"]["whenCreated"]
                    instance["上次登陆时间"] = "该用户从未登陆过"
                    instance["上次密码更改时间"] = entry["attributes"]["pwdLastSet"]
                    instance_list.append(instance)

                else:
                    lastLogon = entry["attributes"]["lastLogonTimestamp"]
                    time_lastLogon = datetime.datetime.combine(lastLogon, datetime.time.min)
                    whenCreated = entry["attributes"]["whenCreated"]
                    time_whenCreated = datetime.datetime.combine(whenCreated, datetime.time.min)
                    num_days1 = datetime.datetime.now() - time_whenCreated
                    num_days2 = datetime.datetime.now() - time_lastLogon

                    # 180天以前建的账户并且180天内没有修改密码的
                    if num_days1.days > min_created_day and num_days2.days > min_logon_day:
                        result['status'] = 1
                        instance = {}
                        instance["用户名"] = entry["attributes"]["cn"]
                        instance["DN"] = entry["attributes"]["distinguishedName"]
                        instance["创建时间"] = entry["attributes"]["whenCreated"]
                        instance["上次登陆时间"] = entry["attributes"]["lastLogonTimestamp"]
                        instance["上次密码更改时间"] = entry["attributes"]["pwdLastSet"]
                        instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

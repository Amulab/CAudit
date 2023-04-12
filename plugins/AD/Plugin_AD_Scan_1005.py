import datetime
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADInactiveComputer(PluginADScanBase):
    """
    域内存在无用或长时间非活跃的计算机帐户
    """

    display = "域内存在无用或长时间非活跃的计算机帐户"
    alias = "i_cpt"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_created_day = 180
        min_logon_day = 180

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
            if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                    entry["attributes"]["lastLogonTimestamp"]) == 0:
                result['status'] = 1
                instance = {}
                instance["主机名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["活跃"] = True
                instance["创建时间"] = entry["attributes"]["whenCreated"]
                instance["上次登陆时间"] = "该用户从未登陆过"
                instance["上次密码修改时间"] = entry["attributes"]["pwdLastSet"]
                instance_list.append(instance)

            else:
                lastLogon = entry["attributes"]["lastLogonTimestamp"]
                time_lastLogon = datetime.datetime.combine(lastLogon, datetime.time.min)
                whenCreated = entry["attributes"]["whenCreated"]
                time_whenCreated = datetime.datetime.combine(whenCreated, datetime.time.min)
                num_days1 = datetime.datetime.now() - time_whenCreated
                num_days2 = datetime.datetime.now() - time_lastLogon
                if num_days1.days > min_created_day and num_days2.days > min_logon_day:
                    result['status'] = 1
                    instance = {}
                    instance["主机名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["活跃"] = True
                    instance["创建时间"] = entry["attributes"]["whenCreated"]
                    instance["上次登陆时间"] = entry["attributes"]["lastLogonTimestamp"]
                    instance["上次密码修改时间"] = entry["attributes"]["pwdLastSet"]
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

import datetime
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADKrbtgtpwdNoChange(PluginADScanBase):
    """krbtgt帐户太长时间未更改密码"""

    display = "krbtgt帐户太长时间未更改密码"
    alias = "krbtgt_act_no_chge"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_pwdLastSet_day = 90

        query = "(&(objectclass=user)(sAMAccountName=krbtgt))"
        attributes = [
            "cn", "sAMAccountName", "pwdLastSet", "distinguishedName"
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
            pwdLastSet = entry["attributes"]["pwdLastSet"]
            time_pwdLastSet = datetime.datetime.combine(pwdLastSet, datetime.time.min)
            num_days1 = datetime.datetime.now() - time_pwdLastSet
            if num_days1.days > min_pwdLastSet_day:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["上次密码修改时间"] = entry["attributes"]["pwdLastSet"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

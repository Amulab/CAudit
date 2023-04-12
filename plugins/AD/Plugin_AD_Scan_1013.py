from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADPwdNeverExpire(PluginADScanBase):
    """存在密码永不过期的帐户"""

    display = "存在密码永不过期的帐户"
    alias = "pwd_no_expire"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectCategory=person)(objectclass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = ["cn", "distinguishedName"]

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
            if entry_generator != None:
                result['status'] = 1
                flag = str(entry["attributes"]["cn"]).find("HealthMailbox")
                flag2 = str(entry["attributes"]["cn"]).find("krbtgt")
                if flag == -1 and flag2 == -1:
                    instance = {"用户名": entry["attributes"]["cn"], "DN": entry["attributes"]["distinguishedName"]}
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADIllegalAdminCount(PluginADScanBase):
    """存在adminCount属性异常用户"""

    display = "存在adminCount属性异常用户"
    alias = "i_adm_ct"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=user)(adminCount=1)(!(cn=krbtgt)))"
        attributes = ["cn", "memberof", "distinguishedName", "name"]

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

            # 如果账户，除了加入了domain user组之外，没有加入任何组，那么memberof_li的值将会是空列表
            memberof_li = entry["attributes"]["memberof"]
            mem_result = []
            privilege_set = {"Account Operators", "Administrators", "Backup Operators", "Domain Admins",
                             "Domain Controllers", "Enterprise Admins", "Enterprise key Admins", "Key Admins", "krbtgt",
                             "Print Operators", "Read-only Domain Controllers", "Replicator", "Schema Admins",
                             "Server Operators"}

            for mem in memberof_li:
                # 将mem字符串以,分割生成列表，去列表的首个值，
                m = (mem.split(','))[0]

                m1 = m.split('=')[1]

                mem_result.append(m1)
                
            s1 = set(mem_result)
            s = entry["attributes"]["distinguishedName"]
            if s1 & privilege_set == set():
                if "CN=HealthMailbox" not in s and "SystemMailbox{" not in s and "FederatedEmail." not in s and "Migration" not in s and "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}" not in s and "CN=Exchange Online-ApplicationAccount" not in s:
                    result['status'] = 1
                    instance = {}
                    instance["用户"] = entry["attributes"]["name"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

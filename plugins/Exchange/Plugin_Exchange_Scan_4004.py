import urllib3
from ldap3 import SUBTREE
from copy import copy

from plugins.Exchange import PluginExchangeScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PluginExchangeExcepTrustedSubsystem(PluginExchangeScanBase):
    """Exchange Trusted Subsystem组存在异常成员"""

    display = "Exchange Trusted Subsystem组存在异常成员"
    alias = "ex_trust_sub"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        computer_list = []
        query = "(&(objectclass=top)(objectclass=group))"
        attributes = ["member", "cn"]
        ldap_cli = "CN=Exchange Servers,OU=Microsoft Exchange Security Groups," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            computer_list = entry["attributes"]['member']

        # print(computer_list)
        query = "(&(objectclass=top)(objectclass=group))"
        attributes = ["member", "cn"]
        ldap_cli = "CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            attrs = entry["attributes"]['member']
            for attr in attrs:
                if attr in computer_list:
                    continue
                else:
                    result['status'] = 1
                    instance ={}
                    instance["组名"] = entry["attributes"]['cn']
                    instance["异常成员"] = attr
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

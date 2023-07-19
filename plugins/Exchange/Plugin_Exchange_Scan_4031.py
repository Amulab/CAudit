import urllib3
from ldap3 import SUBTREE, LEVEL, BASE
from copy import copy
from plugins.Exchange import PluginExchangeScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginExchangeLowUMSecureLevel(PluginExchangeScanBase):
    """ UM拨号计划安全级别较低"""

    display = "UM拨号计划安全级别较低"
    alias = "ex_low_um_secure"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        query = "(objectClass=*)"
        attributes = ["cn"]
        ldap_cli = "CN=Microsoft Exchange,CN=Services,CN=Configuration," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli,
                                                                         search_filter=query,
                                                                         search_scope=LEVEL,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            ldap_cli1 = "CN=UM DialPlan Container,CN=" + entry["attributes"]['cn'] + "," + ldap_cli
            entry_generator1 = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli1,
                                                                             search_filter=query,
                                                                             search_scope=LEVEL,
                                                                             get_operational_attributes=True,
                                                                             attributes=attributes,
                                                                             paged_size=1000,
                                                                             generator=True)

            for entry1 in entry_generator1:
                attributes = ["msExchUMDialPlanVoipSecurity", "cn"]
                ldap_cli2 = "CN=" + entry1["attributes"]['cn'] + "," + ldap_cli1
                entry_generator3 = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli2,
                                                                                  search_filter=query,
                                                                                  search_scope=BASE,
                                                                                  get_operational_attributes=True,
                                                                                  attributes=attributes,
                                                                                  paged_size=1000,
                                                                                  generator=True)
                for entry3 in entry_generator3:
                    if entry3["attributes"]['msExchUMDialPlanVoipSecurity'] == 2:
                        result['status'] = 1
                        instance ={}
                        instance["UM拨号计划名称"] = entry3["attributes"]['cn']
                        instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result
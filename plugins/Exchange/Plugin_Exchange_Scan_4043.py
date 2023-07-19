import urllib3
from ldap3 import SUBTREE, LEVEL, BASE
from copy import copy
from plugins.Exchange import PluginExchangeScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginExchangeExistsMailForwardRules(PluginExchangeScanBase):
    """存在邮箱转发规则"""

    display = "存在邮箱转发规则"
    alias = "ex_exis_fwd_rul"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        query = "(objectClass=*)"
        attributes = ["cn", "msExchDelegateListLink"]
        ldap_cli = "CN=TransportVersioned,CN=Rules,CN=Transport Settings,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli,
                                                                         search_filter=query,
                                                                         search_scope=LEVEL,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            result['status'] = 1
            instance ={}
            instance["转发规则"] = entry["attributes"]['cn']
            instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

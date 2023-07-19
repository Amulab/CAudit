import urllib3
from ldap3 import SUBTREE
from copy import copy

from plugins.Exchange import PluginExchangeScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginExchangInvalidOrganizationManagementGroup(PluginExchangeScanBase):
    """Organization Management组存在异常成员"""

    display = "Organization Management组存在异常成员"
    alias = "ex_inv_org"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:

        result = copy(self.result)
        instance_list = []
        query = "(&(objectclass=top)(objectclass=group))"
        attributes = ["member", "cn"]
        ldap_cli = "CN=Organization Management,OU=Microsoft Exchange Security Groups," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli,  # TODO  确认是否一致
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
                if "CN=Administrator" in attr:
                    continue
                else:
                    result['status'] = 1
                    instance = {}
                    instance["账户名"] = entry["attributes"]['cn']
                    instance["异常成员"] = attr
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

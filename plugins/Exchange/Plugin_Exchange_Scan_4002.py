import urllib3
from ldap3 import SUBTREE
from copy import copy

from plugins.Exchange import PluginExchangeScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginExchangeAbuseMailboxImportExport(PluginExchangeScanBase):
    """Mailbox Import Export权限滥用"""

    display = "Mailbox Import Export权限滥用"
    alias = "ex_abuse_mailbox"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        query = "(&(objectClass=person)(objectCategory=person))"
        attributes = ["msExchUserBL", "cn"]
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
            if entry["attributes"]['cn'] == "Administrator" or entry["attributes"]['cn'] == "administrator":
                continue
            if entry["attributes"]['msExchUserBL']:
                for ms in entry["attributes"]['msExchUserBL']:
                    if 'Mailbox Import Export' in ms:
                        result['status'] = 1
                        instance = {}
                        instance["用户名"] = entry["attributes"]['cn']
                        instance_list.append(instance)
                        break
        result['data'] = {"instance_list": instance_list}
        return result

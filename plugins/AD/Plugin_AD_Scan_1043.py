from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADRODCAccessSYSVOLVolume(PluginADScanBase):
    """RODC对SYSVOL卷具有写访问权"""

    display = "RODC对SYSVOL卷具有写访问权"
    alias = "rodc_acs_sysvol"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(primaryGroupID = 521)"
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

            dn = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings," + entry["attributes"][
                "distinguishedName"]
            query = "(&(msDFSR-ReadOnly=FALSE)(distinguishedName={}))".format(dn)
            attributes = ["cn", "msDFSR-ReadOnly", "distinguishedName"]

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

                result['status'] = 1
                instance = {}
                instance["组名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["msDFSR-ReadOnly"] = entry["attributes"]["msDFSR-ReadOnly"]
                instance_list.append(instance)

        if result['status'] == 1:
            result['data'] = {"instance_list": instance_list}
        return result

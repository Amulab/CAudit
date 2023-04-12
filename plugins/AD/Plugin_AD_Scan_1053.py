from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNoBackupDC(PluginADScanBase):
    """发现域内无备用DC"""

    display = "发现域内无备用DC"
    alias = "no_bck_dc"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        # query = "(&(objectclass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2)(|(PrimaryGroupID=516)(PrimaryGroupID=521)))"
        query = "(&(objectclass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        attributes = ["cn", "distinguishedName", "servicePrincipalName"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)
        a = []
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if isinstance(entry["attributes"]["servicePrincipalName"], list) and len(
                    entry["attributes"]["servicePrincipalName"]) == 0:
                continue  # 判断spn
            distinguishedName1 = str(entry["attributes"]["distinguishedName"])
            ret = distinguishedName1.find("OU=Domain Controllers,DC=")

            if ret != -1:
                a.append(distinguishedName1)
        if len(a) < 2:
            instance = {}
            instance["描述："] = "此域只有一台已启用DC"
            instance["主机名"] = a[0].split('CN=')[1].split(',')[0]
            instance_list.append(instance)
            result['status'] = 1

        result['data'] = {"instance_list": instance_list}
        return result

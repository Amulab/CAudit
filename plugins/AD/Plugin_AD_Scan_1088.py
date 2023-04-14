from copy import copy

from ldap3 import SUBTREE

from plugins.__HXAD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADRODCRevealPwd(PluginADScanBase):
    """RODC可以缓存用户密码"""

    display = "RODC可以缓存用户密码"
    alias = "RODCRevealOnDemand"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=computer)(primaryGroupID=521))"
        attributes = [
            "cn", "msDS-RevealOnDemandGroup", "distinguishedName"
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
            for account in entry["attributes"]["msDS-RevealOnDemandGroup"]:
                num = account.find(",",1)
                if "Allowed RODC Password Replication Group" not in account:
                    instance = {}
                    instance["用户名/组名"] = account[3:num]
                    instance["DN"] = account
                    instance_list.append(instance)

        if len(instance_list) != 0:
            result['status'] = 1

        result['data'] = {"instance_list": instance_list}
        return result



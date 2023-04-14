from copy import copy

from ldap3 import SUBTREE

from plugins.__HXAD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADProUserNull(PluginADScanBase):
    """发现域Protected Users组为空"""

    display = "发现域Protected Users组为空"
    alias = "ProtectedUsersNull"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=group)(sAMAccountName=Protected Users))"
        attributes = ["cn", "member", "distinguishedName"]

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

            if len(entry["attributes"]["member"]) == 0:
                result['status'] = 1
                instance = {}
                instance["组名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["成员"] = "Protected Users组成员为空"
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result



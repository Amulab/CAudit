from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNotEmptyDnsAdmins(PluginADScanBase):
    """`DnsAdmins`组不为空"""

    display = "`DnsAdmins`组不为空"
    alias = "no_emt_dns_admins"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = ["cn", "memberof", "distinguishedName"]

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
            memberof1 = (str(entry["attributes"]["memberof"]))
            # name = entry["attributes"]["cn"]
            # guid = entry["attributes"]["primarygroupid"]
            
            ret = memberof1.find("DnsAdmins")
            if ret != -1:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                # instance["primarygroupid"] = entry["attributes"]["primarygroupid"]
                instance["MemberOf"] = []
                for memberof_res in entry["attributes"]["memberof"]:
                    instance["MemberOf"].append(memberof_res)
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

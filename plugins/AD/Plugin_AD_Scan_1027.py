from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADIllegalPrimaryGroupIDAccount(PluginADScanBase):
    """用户帐户的PrimaryGroupID属性异常"""  # gpid判定可以不用去输出组，可能不全，直接输出gpid也可以
    display = "用户帐户的PrimaryGroupID属性异常"
    alias = "i_prim_gid_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = self.result
        instance_list = []

        query = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = [
            "cn", "primaryGroupID", "memberof",
            "distinguishedName"
        ]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        primary_list = {512: 'Domain Admins', 514: 'Domain Guests', 515: 'Domain Computers', 516: 'Domain Controllers',
                        517: 'Cert Publishers', 518: 'Schema Admins', 519: 'Enterprise Admins',
                        520: 'Group Policy Creator Owners', 521: 'Enterprise Read-only Domain Controllers',
                        544: 'Administrator', 548: 'Account Operators', 549: 'Server Operators', 550: 'Print Operators',
                        551: 'Backup Operators', 552: 'Replicator'}
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["primaryGroupID"] == 513:
                continue
            if entry["attributes"]["cn"] == "Guest":
                continue
            if int(entry["attributes"]["primaryGroupID"]) in primary_list.keys():
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["MemberOf"] = []
                for memberof_res in entry["attributes"]["memberof"]:
                    instance["MemberOf"].append(memberof_res)
                instance["PrimaryGroupID"] = entry["attributes"]["primaryGroupID"]
                instance["所在组"] = primary_list[int(entry["attributes"]["primaryGroupID"])]
            else:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["MemberOf"] = []
                for memberof_res in entry["attributes"]["memberof"]:
                    instance["MemberOf"].append(memberof_res)
                instance["PrimaryGroupID"] = entry["attributes"]["primaryGroupID"]
            instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

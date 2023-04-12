from copy import copy

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
from ldap3 import SUBTREE


class PluginADPrivilageAccountNumberGT50(PluginADScanBase):
    """`特权账号数量不符合基线要求"""  # 特权账号超过50个或者总用户账户数量的百分之五就会告警

    display = "特权账号数量过多"
    alias = "priv_act_gt_50"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        attributes = ["cn", "sAMAccountName", "distinguishedName", "objectSid"]
        query = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)  # 账户特权只判定一次，所以不会重复
        admin_count = 50
        instance_list = []

        query2 = "(&(objectCategory=person)(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        entry_generator2 = self.ldap_cli.con.extend.standard.paged_search(
            search_base=self.ldap_cli.domain_dn,
            search_filter=query2,
            search_scope=SUBTREE,
            get_operational_attributes=True,
            attributes=attributes,
            paged_size=1000,
            generator=True)
        aq = []
        for entry in entry_generator2:
            if entry["type"] != "searchResEntry":
                continue
            flag = str(entry["attributes"]["cn"]).find("HealthMailbox")  # HealthMailbox是exchange相关账户
            if flag != -1:
                continue
            ss = {}

            ss["name"] = entry["attributes"]["cn"]
            aq.append(ss)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            instance = {}
            instance["用户名"] = entry["attributes"]["cn"]
            instance["DN"] = entry["attributes"]["distinguishedName"]
            instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
            instance_list.append(instance)

        if len(instance_list) >= admin_count:
            result['status'] = 1
            result['data'] = {"instance_list": instance_list}
        # elif len(instance_list) >= len(aq) * 0.05:
        elif len(instance_list) >= len(aq) * 5 // 100:  # 之前写的时候没考虑到小数的问题，修改了一下，向下取整
            result['status'] = 1
            result['data'] = {"instance_list": instance_list}
        return result

from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNSPIAccess(PluginADScanBase):
    """在没有任何帐户的情况下检查对名称服务提供商接口（NSPI）协议的访问"""

    display = "在没有任何帐户的情况下检查对名称服务提供商接口（NSPI）协议的访问"
    alias = "nspi_acs"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        search_base = "CN=Configuration," + self.ldap_cli.domain_dn
        # print(search_base)
        query = f"(distinguishedName=CN=Directory Service,CN=Windows NT,CN=Services,{search_base})"  # 也可以用下面这种直接找DSHeuristics，然后再在下面判定字符串CN=Directory Service,CN=Windows NT,CN=Services,
        # query = "(DSHeuristics=*)
        # (distinguishedName=CN=Directory Service,CN=Windows NT,CN=Services,CN = Configuration, DC = test12, DC = local)
        attributes = ["cn", "distinguishedName", "DSHeuristics"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            # distinguishedName1 = str(entry["attributes"]["distinguishedName"])
            # ret = distinguishedName1.find(
            #     "CN=Directory Service,CN=Windows NT,CN=Services,")            #这句删掉了，因为查询语句决定了结果的DN必然包含这个字段
            str1 = entry["attributes"]["DSHeuristics"]

            # if ret != -1 and len(entry["attributes"]["DSHeuristics"]) >= 8 and str(
            #         str1[7:8]) != "0":
            if len(entry["attributes"]["DSHeuristics"]) >= 8 and str(
                    str1[7:8]) != "0":  # 因为没有ret这个地方也不需要判定
                result['status'] = 1
                instance = {}
                instance["名称"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNT4CompatibleTrust(PluginADScanBase):
    """存在与NT4兼容的信任关系"""

    display = "存在与NT4兼容的信任关系"
    alias = "nt4_ct"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(ObjectCategory=*)(TrustType=1))"  # 如果要跟下面一样匹配"trusteddomain"，此处应该使用objectclass。
        attributes = [
            "cn", "member", "TrustType",
            "ObjectCategory", "distinguishedName"
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
            ObjectCategory1 = str(entry["attributes"]["ObjectCategory"])
            # ret = ObjectCategory1.find("trustedDomain")                       #我2012看到是下面这种形式的，不排除旧版本是这种,在objectclass属性里是trustedDomain。
            ret = ObjectCategory1.find("CN=Trusted-Domain,")
            # print(ret)
            if ret != -1:
                result['status'] = 1
                instance = {}
                instance["名称"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

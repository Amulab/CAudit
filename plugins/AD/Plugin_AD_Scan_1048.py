import datetime
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADInvalidTrust(PluginADScanBase):
    """检查无效的信任"""

    display = "检查无效的信任"
    alias = "ck_i_tst"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        # query = "(ObjectCategory=*)"
        query = "(&(ObjectCategory=*)(trusttype=*))"  # 直接再ldap里把配置了信任的项筛出来
        attributes = [
            "cn", "whenChanged", "ObjectCategory",
            "distinguishedName"
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
            whenChanged = entry["attributes"]["whenChanged"]
            time_whenChanged = datetime.datetime.combine(whenChanged, datetime.time.min)
            t = str(time_whenChanged)
            num_days1 = datetime.datetime.now() - time_whenChanged
            ObjectCategory1 = str(entry["attributes"]["ObjectCategory"])
            # ret = ObjectCategory1.find("trustedDomain")
            ret = ObjectCategory1.find("Trusted-Domain")  # 2012的属性表示为Trusted-Domain(字符串注意大小写)
            if ret != -1 and num_days1.days > 40:
                result['status'] = 1
                instance = {}
                instance["名称"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["最后修改时间"] = t
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

import datetime
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADInactiveDC(PluginADScanBase):
    """
    域内存在不活跃的域控
    """

    display = "域内存在不活跃的域控"
    alias = "inactive_dc"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        min_active_day = 45

        query = "(|(primarygroupid=516)(primarygroupid=521))"  # 516域控,521只读域控
        attributes = [
            "cn", "lastLogonTimestamp", "primaryGroupID",
            "distinguishedName", "whenCreated", "servicePrincipalName"
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
            if isinstance(entry["attributes"]["servicePrincipalName"], list) and len(
                    entry["attributes"]["servicePrincipalName"]) == 0:
                continue
            if isinstance(entry["attributes"]["lastLogonTimestamp"], list) and len(
                    entry["attributes"]["lastLogonTimestamp"]) == 0:
                result['status'] = 1
                instance = {"主机名": entry["attributes"]["cn"], "DN": entry["attributes"]["distinguishedName"],
                            "活跃": True,
                            "创建时间": entry["attributes"]["whenCreated"], "上次登陆时间": "该域控从未登陆过"}
                instance_list.append(instance)
            else:
                lastLogon = entry["attributes"]["lastLogonTimestamp"]
                time_lastLogon = datetime.datetime.combine(lastLogon, datetime.time.min)
                num_days = datetime.datetime.now() - time_lastLogon
                if num_days.days > min_active_day:
                    result['status'] = 1
                    instance = {"主机名": entry["attributes"]["cn"], "DN": entry["attributes"]["distinguishedName"],
                                "活跃": True,
                                "创建时间": entry["attributes"]["whenCreated"],
                                "上次登陆时间": entry["attributes"]["lastLogonTimestamp"]}
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

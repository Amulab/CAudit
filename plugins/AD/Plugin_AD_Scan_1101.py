from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
from ldap3 import SUBTREE
from copy import copy


class PluginADDCShadow(PluginADScanBase):
    """
    存在DCShadow攻击
    """

    display = "存在DCShadow攻击"
    alias = "dc_shadow"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        query = "(&(objectcategory=computer)(servicePrincipalName=*)(!(|(primarygroupid=516)(primarygroupid=521))))"
        attributes = [
            "cn", "distinguishedName",
            "whenCreated", "servicePrincipalName"
        ]
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)
        instance_list = []
        attacked = False

        # 遍历域内所有所有计算机(非DC)，如果他的SPN包含E3514235-4B06-11D1-AB04-00C04FC2DCD2，不包含-ADAM就告警
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            contain_e3 = False
            contain_adam = False
            for SPN in entry["attributes"]["servicePrincipalName"]:
                flag1 = SPN.find("E3514235-4B06-11D1-AB04-00C04FC2DCD2")
                flag2 = SPN.find("-ADAM")
                if flag1 != -1 :
                    contain_e3 = True
                if flag2 != -1:
                    contain_adam = True
            if contain_e3 and not contain_adam:
                attacked = True
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["创建时间"] = entry["attributes"]["whenCreated"]
                instance["SPN"] = entry["attributes"]["servicePrincipalName"]
                instance_list.append(instance)

        if attacked:
            result['status'] = 1
            result['data'] = {"instance_list": instance_list}

        return result

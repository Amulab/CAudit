from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADNoLAPS(PluginADScanBase):
    """未安装LAPS管理工具"""

    display = "未安装LAPS管理工具"
    alias = "LAPSNotInstalled"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:

        result = copy(self.result)
        instance_list = []

        try:

            query = "(&(objectclass=computer)(!(|(primaryGroupID=516)(primaryGroupID=521))))"
            attributes = [
                "cn", "ms-Mcs-AdmPwd",
                "ms-Mcs-AdmPwdExpirationTime"
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

                if isinstance(entry["attributes"]["ms-Mcs-AdmPwd"], list) and isinstance(entry["attributes"]["ms-Mcs-AdmPwdExpirationTime"], list) :
                    instance = {}
                    result["status"] = 1
                    instance["cn"] = entry["attributes"]["cn"]
                    instance["Status"] = "LAPS配置未生效"
                    instance_list.append(
                        instance)
                    result['data'] = {"instance_list": instance_list}


                # 检测LAPS生效的逻辑
                # print(len((entry["attributes"]["ms-Mcs-AdmPwd"])))
                # print(type((entry["attributes"]["ms-Mcs-AdmPwd"])))
                # if len(entry["attributes"]["ms-Mcs-AdmPwd"]) > 0 and len(str(entry["attributes"]["ms-Mcs-AdmPwdExpirationTime"])) > 0:
                #     result["status"] = 0
                #     #print(entry["attributes"]["cn"])
                #     break


        except Exception as e:
            if "invalid attribute type ms-Mcs-AdmPwd" in str(e):
                instance = {}
                result["status"] = 1
                instance["Status"] = "该域未安装LAPS工具"
                instance_list.append(instance)
                result['data'] = {"instance_list": instance_list}

        return result


from copy import copy



from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADKerberoastingPrivilegeAccount(PluginADScanBase):
    """特权账号容易受到`Kerberoasting`攻击"""

    display = "特权账号容易受到`Kerberoasting`攻击"
    alias = "kerberoast_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        attributes = ["cn", "servicePrincipalName", "distinguishedName", "objectSid"]
        query = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(servicePrincipalName=null))"
        entry_generator, des_dict = self.ldap_cli.search_admins_info(attributes, query)
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue

            if entry["attributes"]["cn"] != "krbtgt":
                if len(entry["attributes"]["servicePrincipalName"]) > 0:
                    result['status'] = 1
                    instance = {}
                    instance["用户名"] = entry["attributes"]["cn"]
                    instance["DN"] = entry["attributes"]["distinguishedName"]
                    instance["SPN"] = entry["attributes"][
                        "servicePrincipalName"]
                    instance["描述"] = des_dict.get(entry["attributes"]["objectSid"], '')
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

import urllib3
from ldap3 import SUBTREE
from copy import copy

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from plugins.Exchange import PluginExchangeScanBase
from utils.consts import AllPluginTypes


class PluginExchangEexceptionGroup(PluginExchangeScanBase):
    """Exchange Windows Permissions组存在异常成员"""

    display = "Exchange Windows Permissions组存在异常成员"
    alias = "ex_excep_gp"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        query = "(&(objectclass=top)(objectclass=group))"
        attributes = ["member", "cn"]
        # ldap_cli = "CN=Mailbox Import Export,OU=Microsoft Exchange Security Groups," + self.ldap_cli.domain_dn
        ldap_cli = "CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups," + self.ldap_cli.domain_dn
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=ldap_cli,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            attrs = entry["attributes"]['member']

            for attr in attrs:
                if "CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups" in attr:
                    continue
                else:
                    result['status'] = 1
                    instance = {}
                    instance["账户名"] = entry["attributes"]['cn']
                    instance["异常成员"] = attr
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result
#
#
# if __name__ == '__main__':
#     dc_conf = {
#         'ldap_conf': {"password": "High123456",
#                       "dn": "DC=exchange16,DC=local",
#                       "ldapServer": "ldap://192.168.31.185:389",
#                       "DNS": "192.168.31.185",
#                       "user": "exchange16\\administrator"},
#         'name': 'exchange16.local',
#         'ip': '192.168.31.185',
#         'hostname': 'exchange2016',
#         'fqdn': 'exchange2016.exchange16.local',
#         'platform': 'Windows Server 2016 Standard'
#     }
#     meta_data = {
#         "min_password_day": "45",
#     }
#
#     env = {
#         'redis_conf': {
#             'uri': 'redis://:XVMhPmZIAfiwc4k4ZQ@192.168.30.167:6379/0'
#         },
#         'mongo_conf': {
#             'host': '192.168.30.167:27017',
#             'password': 'Aqm3GzSaw2dYABncD',
#             'user': 'user_adm',
#             'db_name': 'db_adm'
#         }
#     }
#
#     plugin = Plugin(dc_conf, meta_data, env)
#     # print(plugin.info)
#     print(plugin.verify())

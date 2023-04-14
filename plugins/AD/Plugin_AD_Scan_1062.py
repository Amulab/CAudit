import struct
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADExistSID(PluginADScanBase):
    """SIDHistory属性中存储了危险的SID"""

    display = "SIDHistory属性中存储了危险的SID"
    alias = "SIDHistoryDangerous"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = ["cn", "SIDHistory", "distinguishedName"]

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
            if entry["attributes"]["SIDHistory"] != None and entry["attributes"]["SIDHistory"] != []:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["SIDHistory"] = Plugin.sid_to_str(
                    entry["attributes"]["SIDHistory"][0])
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

    def sid_to_str(sid):
        revision = sid[0]
        number_of_sub_ids = sid[1]
        iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
        sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
                   for i in range(number_of_sub_ids)]
        return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))



if __name__ == '__main__':
    dc_conf = {
        'ldap_conf': {
            'dn': 'DC=test12,DC=local',
            'password': 'zawx@2022',
            'user': 'Administrator@test12.local',
            'DNS': '192.168.12.249',
            'server': 'ldap://DC01.test12.local'
        },
        'name': 'test12.local',
        'ip': '192.168.12.249',
        'hostname': 'DC01',
        'fqdn': 'DC01.test12.local',
        'platform': 'Windows Server 2016 Datacenter'
    }
    meta_data = {'port': '445', 'key2': 'value2'}
    env = {
        'redis_conf': {
            'uri': 'redis://:XVMhPmZIAfiwc4k4ZQ@192.168.30.167:6379/0'
        },
        'mongo_conf': {
            'host': '192.168.30.167:27017',
            'password': 'Aqm3GzSaw2dYABncD',
            'user': 'user_adm',
            'db_name': 'db_adm'
        }
    }
    plugin = Plugin(dc_conf, meta_data, env)
    #print(plugin.info)
    print(plugin.verify())

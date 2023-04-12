import struct
from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADSidHis(PluginADScanBase):
    """存在SIDHistory"""

    display = "存在SIDHistory"
    alias = "sid_his"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []

        query = "(&(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = ["cn", "sIDHistory", "distinguishedName"]

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
            if entry["attributes"]["sIDHistory"] != None and entry["attributes"]["sIDHistory"] != []:
                result['status'] = 1
                instance = {}
                instance["用户名"] = entry["attributes"]["cn"]
                instance["DN"] = entry["attributes"]["distinguishedName"]
                instance["SIDHistory"] = Plugin.sid_to_str(
                    entry["attributes"]["sIDHistory"][0])
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

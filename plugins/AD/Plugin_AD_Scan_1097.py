from copy import copy
import struct

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class DnsPropertyId:
    DSPROPERTY_ZONE_TYPE = 0x00000001
    DSPROPERTY_ZONE_ALLOW_UPDATE = 0x00000002
    DSPROPERTY_ZONE_SECURE_TIME = 0x00000008
    DSPROPERTY_ZONE_NOREFRESH_INTERVAL = 0x00000010
    DSPROPERTY_ZONE_REFRESH_INTERVAL = 0x00000020
    DSPROPERTY_ZONE_AGING_STATE = 0x00000040
    DSPROPERTY_ZONE_SCAVENGING_SERVERS = 0x00000011
    DSPROPERTY_ZONE_AGING_ENABLED_TIME = 0x00000012
    DSPROPERTY_ZONE_DELETED_FROM_HOSTNAME = 0x00000080
    DSPROPERTY_ZONE_MASTER_SERVERS = 0x00000081
    DSPROPERTY_ZONE_AUTO_NS_SERVERS = 0x00000082
    DSPROPERTY_ZONE_DCPROMO_CONVERT = 0x00000083
    DSPROPERTY_ZONE_SCAVENGING_SERVERS_DA = 0x00000090
    DSPROPERTY_ZONE_MASTER_SERVERS_DA = 0x00000091
    DSPROPERTY_ZONE_AUTO_NS_SERVERS_DA = 0x00000092
    DSPROPERTY_ZONE_NODE_DBFLAGS = 0x00000100


class DnsProperty:
    def __init__(self, property_id, data):
        self.data = data
        self.property_id = property_id


class PluginADDnsZoneUpdate1(PluginADScanBase):
    """域内DNS区域配置了不安全的更新"""

    display = "域内DNS区域配置了不安全的更新"
    alias = "DnsZoneUpdate1"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)

        search_base = "DC=DomainDnsZones," + self.ldap_cli.domain_dn
        query = "(objectClass=dnsZone)"
        attributes = ["cn", "dNSProperty", "name"]
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        instance_list = []
        domain = self.dc_domain
        data = {}
        data["dnsProperties"] = []

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["cn"] is not None:
                if entry["attributes"]["name"] == domain or entry["attributes"]["name"] == "RootDNSServers":
                    for d in entry["attributes"]["dNSProperty"]:
                        fmt = f"<5I{len(d) - 21}sB"
                        data_len, name_len, flag, ver, identity, datas, name = struct.unpack(fmt, d)
                        data["dnsProperties"].append(DnsProperty(identity, datas[:data_len]))

        for property in data['dnsProperties']:
            if property.property_id == DnsPropertyId.DSPROPERTY_ZONE_ALLOW_UPDATE:
                if len(property.data) == 1 and property.data[0] == 1:
                    result['status'] = 1
                    instance = {}
                    # instance["dns区域"] = domain                      #添加dns区域输出
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result



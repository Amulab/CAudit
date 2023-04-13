from impacket.krb5.kerberosv5 import getKerberosTGT, constants, Principal

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADMasterPwd(PluginADScanBase):
    """
    万能密码检测(检测mimikatz密码能否登录)
    """

    display = "万能密码检测"
    alias = "mst_pwd"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        MIMIKATZ_BACKDOOR = 'mimikatz'
        try:
            userName = Principal(self.ldap_username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            getKerberosTGT(userName, MIMIKATZ_BACKDOOR, self.dc_domain, None, None, kdcHost=self.dc_ip)

            self.result['status'] = 1
            self.result['instance_list'] = [{"ip address": self.dc_ip}]
        except Exception as e:
            if 'KDC_ERR_PREAUTH_FAILED' in str(e) or 'SessionKeyDecryptionError' in str(e):
                pass
            else:
                self.result['status'] = -1
                self.result['error'] = str(e)

        return self.result

import urllib3
import ssl
from pyVim import connect
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterInvalidPasswordExpired(PluginVCenterScanBase):
    display = "vpxuser用户密码过期时间异常"
    alias = "inv_pwd_exp"
    p_type = AllPluginTypes.Scan
    """"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        sslContext = None
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        vc_cont = connect.SmartConnect(host=self.dc_ip, user=self.ldap_conf['user'], pwd=self.ldap_conf['password'],
                                       sslContext=sslContext)
        result = copy(self.result)
        sets = vc_cont.content.setting.setting
        PasswordExpirationInDays = 0
        for set1 in sets:
            if set1.key == 'VirtualCenter.VimPasswordExpirationInDays':
                PasswordExpirationInDays = set1.value
                if PasswordExpirationInDays >= 30:
                    result['status'] = 0
                else:
                    result['status'] = 1
                    result['data'] = {"instance_list": [{
                        '密码有效期': PasswordExpirationInDays
                    }]}
        return result

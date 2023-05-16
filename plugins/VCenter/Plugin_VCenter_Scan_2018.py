import urllib3
import ssl
from pyVim import connect
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterVCenterLog(PluginVCenterScanBase):
    display = "vCenter 日志记录"
    alias = "vc_log"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        sslContext = None
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        vc_cont = connect.SmartConnect(host=self.dc_ip, user=self.ldap_conf['user'], pwd=self.ldap_conf['password'],
                                       sslContext=sslContext)
        sets = vc_cont.content.setting.setting

        result = copy(self.result)
        instance_list = []
        for set in sets:
            if (set.key=="log.level"): #log.level的值代表现在的日志记录级别
                log_value=set.value
                if log_value !="info" and log_value !="trivia" and log_value !="verbose":    #判断日志记录级别，如果不为这些日志记录级别则进行告警
                    instance = {}
                    result['status'] = 1
                    instance['描述'] = "日志记录级别为:"+log_value
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result


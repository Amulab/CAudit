import urllib3
import ssl
from pyVmomi import vim
from pyVim import connect
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterInvalidPasswordPolicy(PluginVCenterScanBase):
    display = "ESXI 密码策略异常"
    alias = "inv_pwd_poly"
    p_type = AllPluginTypes.Scan
    """"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        sslContext = None
        instance_list = []
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        vc_cont = connect.SmartConnect(host=self.dc_ip, user=self.ldap_conf['user'], pwd=self.ldap_conf['password'],
                                       sslContext=sslContext)
        result = copy(self.result)
        content = vc_cont.RetrieveContent()
        object_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        for host_system in object_view.view:
            host_config_manager = host_system.configManager.advancedOption.setting
            test = {}
            for option in host_config_manager:
                test[option.key] = option.value
            if "Security.PasswordHistory" in test.keys() and "Security.PasswordMaxDays" in test.keys():
                PasswordHistory = test["Security.PasswordHistory"]
                PasswordMaxDays = test["Security.PasswordMaxDays"]
                if PasswordHistory != 0:    #用户记录的密码数，应该不为0
                    result['status'] = 1
                    instance = {}
                    instance['host'] = host_system.name
                    instance['描述'] = "用户密码记录数为：" + str(PasswordHistory)
                    instance_list.append(instance)
                if PasswordMaxDays > 90:  #用户密码使用最大天数，应该小于90天
                    result['status'] = 1
                    instance = {}
                    instance['host'] = host_system.name
                    instance['描述'] = "密码更改最大天数为："+str(PasswordMaxDays)
                    instance_list.append(instance)
            else:
                result['status'] = 1
                instance = {}
                instance['host'] = host_system.name
                instance['描述'] = "没有这个选项"
                instance_list.append(instance)
            result['data'] = {"instance_list": instance_list}
        return result

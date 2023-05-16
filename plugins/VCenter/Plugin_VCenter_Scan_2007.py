import ssl
from copy import copy

import urllib3
from pyVim import connect
from pyVmomi import vim

from plugins.VCenter import PluginVCenterScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterLockdownModeOff(PluginVCenterScanBase):
    display = "ESXI 未开启锁定模式"
    alias = "esxi_lock_off"
    p_type = AllPluginTypes.Scan

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
            instance = {}
            if host_system.config is not None and host_system.config.lockdownMode == "lockdownDisabled":
                result['status'] = 1
                instance['主机IP'] = host_system.name
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

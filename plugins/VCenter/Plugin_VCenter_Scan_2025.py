import urllib3
import ssl
from pyVmomi import vim
from pyVim import connect
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterManageESXIStatus(PluginVCenterScanBase):
    display = "vCenter 管理ESXI主机连接状态"
    alias = "vc_mana_exsi_sta"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        sslContext = None
        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        vc_cont = connect.SmartConnect(host=self.dc_ip, user=self.ldap_conf['user'], pwd=self.ldap_conf['password'],
                                       sslContext=sslContext)
        result = copy(self.result)
        instance_list = []
        content = vc_cont.RetrieveContent()
        object_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)

        for host_system in object_view.view:
            if host_system.summary.runtime.connectionState == "disconnected":
                result['status'] = 1
                instance = {}
                instance['host'] = host_system.name
                instance['connection_state'] = 'disconnected'
                instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result


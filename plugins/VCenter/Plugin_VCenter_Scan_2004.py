import ssl
from copy import copy

import urllib3
from pyVim import connect
from pyVmomi import vim

from plugins.VCenter import PluginVCenterScanBase
from utils import output
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterEsxiSSHOpened(PluginVCenterScanBase):
    display = "ESXI SSH开启"
    alias = "esxi_ssh_open"
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
            try:
                services = host_system.configManager.serviceSystem.serviceInfo.service
            except Exception as e:
                output.debug(e)
                return result

            for service in services:
                if service.key == 'TSM-SSH':
                    if service.running == True:
                        instance = {}
                        result['status'] = 1
                        instance['ESXIIP'] = host_system.name
                        instance['SSH状态'] = '已启用'
                        instance_list.append(instance)
        result['data'] = {"instance_list":instance_list}
        return result


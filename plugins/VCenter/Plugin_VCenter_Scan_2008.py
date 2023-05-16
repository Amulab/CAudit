import ssl
from copy import copy

import urllib3
from pyVim import connect
from pyVmomi import vim

from plugins.VCenter import PluginVCenterScanBase
from utils import output
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterNTPNoConfig(PluginVCenterScanBase):
    display = "ESXI 未配置NTP或PTP"
    alias = "esxi_ntp_nocfg"
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
        content = vc_cont.RetrieveContent()
        object_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        instance_list = []
        for host_system in object_view.view:

            try:
                host_system.configManager.serviceSystem.serviceInfo.service
            except Exception as e:
                output.debug(e)
                return  result

            services = host_system.configManager.serviceSystem.serviceInfo.service
            for service in services:
                if service.key == 'ntpd' and service.running == False:
                    instance = {}
                    result['status'] = 1
                    instance["ESXI主机"] = host_system.name
                    instance["描述"] = "ESXI 未启用NTP"
                    instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}

        return result


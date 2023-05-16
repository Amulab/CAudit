import urllib3
import ssl
from pyVmomi import vim
from pyVim import connect
from copy import copy
import datetime
from plugins.VCenter import PluginVCenterScanBase
from utils import output

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterCertExpired(PluginVCenterScanBase):
    display = "vCenter 证书过期日期"
    alias = "vc_cert_exp"
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
            instance = {}

            try:
                host_system.configManager.certificateManager.certificateInfo
            except Exception as e:
                output.debug(e)
                return result

            time1 = str(host_system.configManager.certificateManager.certificateInfo.notAfter).split(' ')[0]
            time2 = str(datetime.datetime.now()).split(' ')[0]
            timecert = datetime.datetime.strptime(time1, "%Y-%m-%d")
            timenow = datetime.datetime.strptime(time2, "%Y-%m-%d")
            if timecert < timenow:
                result['status'] = 1
                instance['host'] = host_system.name
                instance['证书过期时间'] = timecert
                instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

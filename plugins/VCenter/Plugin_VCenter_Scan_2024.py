import ssl
import urllib3
from pyVmomi import vim
from pyVim import connect
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterInvalidStorageInfo(PluginVCenterScanBase):
    display = "vCenter 存储信息异常"
    alias = "vc_inv_stoinf"
    p_type = AllPluginTypes.Scan

    def hum_convert(self, cp):
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        size = 1024.0
        for i in range(len(units)):
            if (cp / size) < 1:
                return "%.2f%s" % (cp, units[i])
            cp = cp / size

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

            for ds in host_system.datastore:
                if ds.summary.capacity == 0 and ds.summary.freeSpace == 0:
                    pass
                else:
                    if (ds.summary.freeSpace / ds.summary.capacity) * 100 < 5:
                        result['status'] = 1
                        instance = {}
                        instance['主机'] = host_system.name
                        instance['磁盘名称'] = ds.name
                        instance['剩余磁盘'] = self.hum_convert(ds.summary.freeSpace)
                        instance_list.append(instance)
            result['data'] = {"instance_list": instance_list}
        return result


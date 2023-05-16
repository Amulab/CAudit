import urllib3
import ssl
from pyVmomi import vim
from pyVim import connect
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterEsxiFireWall(PluginVCenterScanBase):
    display = "ESXI 防火墙"
    alias = "esxi_fw"
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
        instance_list = []
        object_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        firedefault = ["cimhttpserver", "cimhttpsserver", "cimslp", "dhcpv6", "dvfilter", "dvssync", "hbr", "nfc",
                       "wol", "dhcp",
                       "dns", "faulttolerance", "iofiltervp", "nfsclient", "rabbitmqproxy", "snmp", "sshserver",
                       "updatemanager",
                       "vmotion", "vsphereclient", "vpxheartbeats", "webaccess", "ntpclient", "rdt",
                       "activedirectoryall", "vspc",
                       "trusted-infrastructure-kmxa", "cmmds"]
        for host_system in object_view.view:
            if host_system.config is not None:
                for rule in host_system.config.firewall.ruleset:
                    if rule.enabled:
                        if rule.key.lower() not in firedefault:
                            instance = {}
                            result['status'] = 1
                            instance['ESXi主机'] = host_system.name  # 没有考虑到多个ESXi主机存在的情况，此处增加一项ESXi主机描述
                            instance['异常规则'] = rule.key
                            instance['状态'] = "开启"
                            instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result

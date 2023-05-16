import ssl
from copy import copy

import urllib3
from pyVim import connect

from plugins.VCenter import PluginVCenterScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterLowVersion(PluginVCenterScanBase):
    """vCenter SDK版本过低"""

    display = "vCenter SDK版本过低"
    alias = "vc_low_ver"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        sslContext = None
        instance_list = []
        instance = {}

        if hasattr(ssl, '_create_unverified_context'):
            sslContext = ssl._create_unverified_context()
        vc_cont = connect.SmartConnect(host=self.dc_ip, user=self.ldap_conf['user'], pwd=self.ldap_conf['password'],
                                       sslContext=sslContext)
        vcsdk = vc_cont.content.about
        result = copy(self.result)
        if vcsdk:
            vCenterName = vcsdk.name
            vCenterBuild = vcsdk.build
            vCenterVersion = vcsdk.version
            version = '.'.join(vCenterVersion.split('.')[:-1])  # 将获取到的版本信息只截取x.x,例如6.0,5.6
            lowVersion = ['6.0', '5.5']  # 小于6.0 的版本还有5.5 如果存在5.5版本也进行告警
            if version in lowVersion:
                result['status'] = 1
                instance['vCenterName'] = vCenterName
                instance['vCenterBuild'] = vCenterBuild
                instance['vCenterVersion'] = vCenterVersion
                instance_list.append(instance)
            result['data'] = {"instance_list": instance_list}
            return result


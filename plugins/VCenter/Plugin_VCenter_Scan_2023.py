import urllib3
from ldap3 import Server, Connection, SUBTREE
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterInvalidLoginPolicy(PluginVCenterScanBase):
    display = "vCenter 登录锁定策略异常"
    alias = "vc_inv_login_poly"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        base_passwordpolicy = "cn=password and lockout policy,dc=vsphere,dc=local"
        filter_passwordpolicy = "(&(objectclass=vmwPolicy))"
        attr_passwordpolicy = ["vmwPasswordChangeMaxFailedAttempts",
                               "vmwPasswordChangeAutoUnlockIntervalSec",
                               "vmwPasswordChangeFailedAttemptIntervalSec",
                               ]
        result = copy(self.result)
        Server1 = Server(self.dc_ip)
        user, domain = self.ldap_conf["user"].split("@")
        dc1, dc2 = domain.split(".")
        ccc = "CN=" + user + ",CN=Users,DC=" + dc1 + ",DC=" + dc2
        conn = Connection(Server1, ccc, self.ldap_conf["password"], auto_bind=True)
        res = conn.extend.standard.paged_search(search_base=base_passwordpolicy,
                                                search_filter=filter_passwordpolicy,
                                                search_scope=SUBTREE,
                                                attributes=attr_passwordpolicy,
                                                )
        instance_list = []
        for entry in res:
            attr = entry["attributes"]
            if attr['vmwPasswordChangeMaxFailedAttempts'] > 5:
                instance = {}
                result['status'] = 1
                instance["描述"] = "最多失败登录尝试次数"
                instance["值"] = attr['vmwPasswordChangeMaxFailedAttempts']
                instance_list.append(instance)
            if attr['vmwPasswordChangeFailedAttemptIntervalSec'] < 180:
                instance = {}
                result['status'] = 1
                instance["描述"] = "故障时间间隔"
                instance["值"] = attr['vmwPasswordChangeFailedAttemptIntervalSec']
                instance_list.append(instance)
            if attr['vmwPasswordChangeAutoUnlockIntervalSec'] < 300:
                instance = {}
                result['status'] = 1
                instance["描述"] = "解除锁定时间"
                instance["值"] = attr['vmwPasswordChangeAutoUnlockIntervalSec']
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result


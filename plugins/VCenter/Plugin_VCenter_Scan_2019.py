from ldap3 import Server, Connection, SUBTREE
from copy import copy
from plugins.VCenter import PluginVCenterScanBase

from utils.consts import AllPluginTypes


class PluginVCenterInvalidPasswordPolicy(PluginVCenterScanBase):
    display = "vCenter 密码策略异常"
    alias = "vc_inv_pwd_poly"
    p_type = AllPluginTypes.Scan
    """"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        base_passwordpolicy = "cn=password and lockout policy,dc=vsphere,dc=local"
        filter_passwordpolicy = "(&(objectclass=vmwPolicy))"
        attr_passwordpolicy = ["vmwPasswordLifetimeDays",
                               "vmwPasswordMinLength",
                               "vmwPasswordChangeMaxFailedAttempts",
                               "vmwPasswordProhibitedPreviousCount",
                               "vmwPasswordChangeAutoUnlockIntervalSec",
                               "vmwPasswordMaxIdenticalAdjacentChars",
                               "vmwPasswordMaxLength",
                               "vmwPasswordMinAlphabeticCount",
                               "vmwPasswordChangeFailedAttemptIntervalSec",
                               "vmwPasswordMinLowerCaseCount",
                               "vmwPasswordMinNumericCount",
                               "vmwPasswordMinSpecialCharCount",
                               "vmwPasswordMinUpperCaseCount"
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
            if attr['vmwPasswordMinUpperCaseCount'] < 1:
                instance = {}
                result['status'] = 1
                instance["描述"] = "大写字符"
                instance["值"] = attr['vmwPasswordMinUpperCaseCount']
                instance_list.append(instance)
            if attr['vmwPasswordMinLowerCaseCount'] < 1:
                instance = {}
                result['status'] = 1
                instance["描述"] = "小写字符"
                instance["值"] = attr['vmwPasswordMinLowerCaseCount']
                instance_list.append(instance)
            if attr['vmwPasswordMinAlphabeticCount'] < 2:
                instance = {}
                result['status'] = 1
                instance["描述"] = "字母个数"
                instance["值"] = attr['vmwPasswordMinAlphabeticCount']
                instance_list.append(instance)
            if attr['vmwPasswordMinLength'] < 8:
                instance = {}
                result['status'] = 1
                instance["描述"] = "最小长度"
                instance["值"] = attr['vmwPasswordMinLength']
                instance_list.append(instance)
            if attr['vmwPasswordMaxLength'] > 20:
                instance = {}
                result['status'] = 1
                instance["描述"] = "最大长度"
                instance["值"] = attr['vmwPasswordMaxLength']
                instance_list.append(instance)
            if attr['vmwPasswordMinSpecialCharCount'] < 1:
                instance = {}
                result['status'] = 1
                instance["描述"] = "特殊字符"
                instance["值"] = attr['vmwPasswordMinSpecialCharCount']
                instance_list.append(instance)
            if attr['vmwPasswordMinNumericCount'] < 1:
                instance = {}
                result['status'] = 1
                instance["描述"] = "数字字符"
                instance["值"] = attr['vmwPasswordMinNumericCount']
                instance_list.append(instance)
            if attr['vmwPasswordMaxIdenticalAdjacentChars'] < 3:
                instance = {}
                result['status'] = 1
                instance["描述"] = "相邻字符数"
                instance["值"] = attr['vmwPasswordMaxIdenticalAdjacentChars']
                instance_list.append(instance)
            if attr['vmwPasswordLifetimeDays'] < 90:
                instance = {}
                result['status'] = 1
                instance["描述"] = "密码过期时间"
                instance["值"] = attr['vmwPasswordLifetimeDays']
                instance_list.append(instance)
            if attr['vmwPasswordProhibitedPreviousCount'] > 5:
                instance = {}
                result['status'] = 1
                instance["描述"] = "用户重用以前密码数"
                instance["值"] = attr['vmwPasswordProhibitedPreviousCount']
                instance_list.append(instance)
        result['data'] = {"instance_list": instance_list}
        return result


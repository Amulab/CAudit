from copy import copy
from plugins.VCenter import PluginVCenterScanBase
from ldap3 import Connection

from utils.consts import AllPluginTypes


class PluginVCenterMultipleHighAccount(PluginVCenterScanBase):
    display = "vCenter 高权限账户过多"
    alias = "vc_mul_acc"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:

        user, domain = self.ldap_conf["user"].split("@")
        dc1, dc2 = domain.split(".")
        ccc = "CN=" + user + ",CN=Users,DC=" + dc1 + ",DC=" + dc2

        instance_list = []
        result = copy(self.result)
        c = Connection(self.dc_ip, user=ccc, password=self.ldap_conf["password"], auto_bind=True)

        c.search(search_base="cn=AclModel,cn=VmwAuthz,cn=services,dc=vsphere,dc=local",
                 search_filter='(&(objectClass=vmwAuthzAclMap)(vmwAuthzPermissionRoleId=-1))',
                 search_scope='SUBTREE', attributes=['vmwAuthzPrincipalName']
                 )
        resp = c.response
        for r in resp:
            admin_g_cn = r['attributes']['vmwAuthzPrincipalName'].split('\\')[-1]
            c.search(search_base="dc=vsphere,dc=local",
                     search_filter=f'(&(objectClass=group)(cn={admin_g_cn}))',
                     search_scope='SUBTREE', attributes=['member']
                     )
            for r in c.response:
                for it in r['attributes']['member']:
                    instance = {}
                    instance['高权限'] = it.split(',')[0]
                    instance_list.append(instance)
        if (len(instance_list) > 10):
            result['status'] = 1
            result['data'] = {"instance_list": instance_list}
        return result

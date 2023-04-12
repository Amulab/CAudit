from copy import copy

import impacket
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK
from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADAdminSDHolderPermissionException(PluginADScanBase):
    """AdminSDHolder权限异常"""

    display = "AdminSDHolder权限异常"
    alias = "i_adm_sid_hld"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)

        query = "(cn=AdminSDHolder)"
        attributes = ["nTSecurityDescriptor"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        impacket.ldap.ldaptypes.RECALC_ACL_SIZE = False
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
        # domain = self.dc_domain
        instance_list = []
        sid_cl = []
        sid_pre = ["10", "561", "544", "18", "517", "519", "512"]
        secDescData = entry["attributes"]["nTSecurityDescriptor"]
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(secDescData)
        for ace in sd['Dacl'].aces:

            if (ace['Ace']['Mask']['Mask'] == 983551):
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid not in sid_cl:
                    sid_result = sid.split('-')
                    sid_last = sid_result[-1]
                    if sid_last not in sid_pre:
                        result['status'] = 1
                        instance = {}
                        instance["objectSid"] = sid
                        instance["描述"] = "具有对adminSDholder完全控制权限"
                        instance_list.append(instance)

            if ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP):
                sid = ace['Ace']['Sid'].formatCanonical()

                if sid not in sid_cl:
                    sid_cl.append(sid)
                    sid_result = sid.split('-')
                    sid_last = sid_result[-1]
                    if sid_last not in sid_pre:
                        result['status'] = 1
                        instance = {}
                        instance["objectSid"] = sid
                        instance["描述"] = "具有对adminSDHolder写入权限"
                        instance_list.append(instance)

            if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL):
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid not in sid_cl:
                    sid_cl.append(sid)
                    sid_result = sid.split('-')
                    sid_last = sid_result[-1]
                    if sid_last not in sid_pre:
                        result['status'] = 1
                        instance = {}
                        instance["objectSid"] = sid
                        instance["描述"] = "具有对adminSDHolder修改ACL权限"
                        instance_list.append(instance)
            if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_OWNER):
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid not in sid_cl:
                    sid_cl.append(sid)
                    sid_result = sid.split('-')
                    sid_last = sid_result[-1]
                    if sid_last not in sid_pre:
                        result['status'] = 1
                        instance = {}
                        instance["objectSid"] = sid
                        instance["描述"] = "具有对adminSDHolder修改所有者权限"
                        instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

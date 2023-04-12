from copy import copy

import impacket
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE
from ldap3 import SUBTREE
from impacket.uuid import bin_to_string

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADAddDomainWithUnprivilegedUser(PluginADScanBase):
    """非特权用户可以将计算机帐户添加到域"""

    display = "非特权用户可以将计算机帐户添加到域"
    alias = "unpriv_user_add_domain"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)

        query = "(objectclass=domain)"
        attributes = ["nTSecurityDescriptor"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        impacket.ldap.ldaptypes.RECALC_ACL_SIZE = False

        instance_list = []

        guid_1 = "bf967a86-0de6-11d0-a285-00aa003049e2"

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            secDescData = entry["attributes"]["nTSecurityDescriptor"]  ### 打印ACL
            sd = SR_SECURITY_DESCRIPTOR()

            sd.fromString(secDescData)

            for ace in sd['Dacl'].aces:
                if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    continue
                if len(ace['Ace']['ObjectType']) == 0:
                    continue

                objectTypeGuid = bin_to_string(ace['Ace']['ObjectType']).lower().strip()

                if objectTypeGuid != guid_1 and ace['Ace']['Mask']['Mask'] != 1:
                    continue
                sid = ace['Ace']['Sid'].formatCanonical()

                query = "(objectSid=%s)" % sid
                attributes = ["cn"]

                entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                                 search_filter=query,
                                                                                 search_scope=SUBTREE,
                                                                                 get_operational_attributes=True,
                                                                                 attributes=attributes,
                                                                                 paged_size=1000,
                                                                                 generator=True)

                for entry in entry_generator:
                    if entry["type"] != "searchResEntry":
                        continue

                    result['status'] = 1
                    instance = {}
                    instance['name'] = entry["attributes"]["cn"]
                    instance["Sid"] = sid
                    instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

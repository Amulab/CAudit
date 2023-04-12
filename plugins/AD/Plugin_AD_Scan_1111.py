import time
from copy import copy
from io import BytesIO

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes
import traceback
from ldap3 import SUBTREE
from modules.adi_lib.ldap.acls import SecurityDescriptor, ACE, EXTRIGHTS_GUID_MAPPING, can_write_property, ACCESS_MASK


class PluginADIllegalMSDSAllowedToActOnBehalfOfOtherIdentity(PluginADScanBase):
    """用户msDS-AllowedToActOnBehalfOfOtherIdentity权限异常"""

    display = "用户msDS-AllowedToActOnBehalfOfOtherIdentity权限异常"
    alias = "i_ms_ds_allow_t_act"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        # query = "(&(objectCategory=person)(objectclass=user))"
        query = "(&(objectCategory=person)(objectclass=user)(!(|(cn=DiscoverySearchMailbox*)(cn=Exchange Online*)(cn=FederatedEmail*)(cn=HealthMailbox*)(cn=Migration.*)(cn=SystemMailbox*)))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        attributes = [
            "cn", "nTSecurityDescriptor", "name"
        ]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        instance_list = []
        ignoresids = ["S-1-3-0", "S-1-5-18", "S-1-5-10", "S-1-5-32-544", "S-1-5-32-548" ,"S-1-5-32-561"]
        try:
            for entry in entry_generator:
                if not entry.get('raw_attributes'):
                    continue
                sd = SecurityDescriptor(BytesIO(entry['raw_attributes'].get('nTSecurityDescriptor')[0]))
                for ace_obj in sd.dacl.aces:
                    if ace_obj.ace.AceType != 0x05 and ace_obj.ace.AceType != 0x00:
                        # These are the only two aces we care about currently
                        continue
                    sid = str(ace_obj.acedata.sid)
                    is_inherited = ace_obj.has_flag(ACE.INHERITED_ACE)
                    mask = ace_obj.acedata.mask
                    if sid in ignoresids:
                        continue
                    if mask.has_priv(ACCESS_MASK.GENERIC_ALL):
                        instance = {}
                        instance["用户名"] = entry['attributes']["name"]
                        instance["被授予权限用户"] = sid
                        instance["权限"] = 'GenericAll'
                        instance["继承"] = is_inherited
                        instance_list.append(instance)
                        continue
                    if mask.has_priv(ACCESS_MASK.GENERIC_WRITE):
                        instance = {}
                        instance["用户名"] = entry['attributes']["name"]
                        instance["被授予权限用户"] = sid
                        instance["权限"] = 'GenericWrite'
                        instance["继承"] = is_inherited
                        instance_list.append(instance)
                        continue
                    if ace_obj.ace.AceType == 0x05:
                        if can_write_property(ace_obj, EXTRIGHTS_GUID_MAPPING['AllowedToAct']):
                            instance = {}
                            instance["用户名"] = entry['attributes']["name"]
                            instance["被授予权限用户"] = sid
                            instance["权限"] = 'AllowedToAct'
                            instance["继承"] = is_inherited
                            instance_list.append(instance)

            instance_list = [i for i in instance_list if
                             not (i.get('被授予权限用户').endswith('519') or i.get('被授予权限用户').endswith('512') or i.get('被授予权限用户').endswith('526') or \
                                  i.get('被授予权限用户').endswith('527') or i.get('被授予权限用户').endswith('517'))]

            for i in instance_list:
                query = "(objectSid=%s)"%i.get("被授予权限用户")
                attributes = ["distinguishedName","name"]

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
                    if "Microsoft Exchange Security Groups" in entry['attributes']["distinguishedName"]:
                        id = i.get('被授予权限用户').split("-")[-1]
                        instance_list = [info for info in instance_list if not (info.get('被授予权限用户').endswith(id[-1]))]
                        continue
                    name = entry['attributes']["name"]
                    i.update({"被授予权限用户":name})


            if instance_list:
                result['status'] = 1

        except Exception as e:
            output.error(str(e))
            output.error(traceback.format_exc())
            result['error'] = str(e)
            result["status"] = -1

        result['data'] = {"instance_list": instance_list}
        return result

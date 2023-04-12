from copy import copy

from utils.consts import AllPluginTypes

from modules import certilib

from plugins.AD import PluginADScanBase

EX_RIGHT_CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
EX_RIGHT_CERTIFICATE_AUTOENROLLMENT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"


def print_sids(sids, sids_resolver, offset=0):
    blanks = " " * offset
    msg = []
    for sid in sids:
        domain, name = sids_resolver.get_name_from_sid(sid)
        msg.append("{} {}\{}".format(sid, domain, name))

    return "\n".join(["{}{}".format(blanks, line) for line in msg])


def guid_to_string(guid):
    return "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(
        guid[3], guid[2], guid[1], guid[0],
        guid[5], guid[4],
        guid[7], guid[6],
        guid[8], guid[9],
        guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )


def sid_not_manager(sids):
    enroll_sidss = []
    for sid in sids:
        if len(sid.split('-')) == 8:
            lenth = str(sid.split('-')[7].strip())
            if lenth == '512' or lenth == '519':
                continue
            else:
                enroll_sidss.append(sid)
        else:
            enroll_sidss.append(sid)

    return enroll_sidss


class PluginADESC32(PluginADScanBase):
    """
    ESC3.2 - 注册代理模板配置不当
    """

    display = "ESC3.2 - 注册代理模板配置不当"
    alias = "esc3_2"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        target_ip = self.dc_ip
        domain = self.dc_domain
        username = self.ldap_conf["user"].split("@")[0]
        password = self.ldap_conf["password"]
        attacked = False
        result = copy(self.result)
        instance_list = []
        vuln_templates, sids_resolver = certilib.checkECS32(domain, username, password, target_ip)
        for temp in vuln_templates:

            # 展示ACL
            enrollment_acl = ""
            autoenrollment_acl = ""
            writeowner_acl = ""
            writedacl_acl = ""
            riteprop_acl = ""
            enroll_sids = set()
            autoenroll_sids = set()
            write_owner_sids = set()
            write_dacl_sids = set()
            write_property_sids = set()
            for ace in temp.dacl.aces:
                if ace["TypeName"] == "ACCESS_ALLOWED_OBJECT_ACE":
                    ace = ace["Ace"]
                    mask = ace["Mask"]
                    sid = ace["Sid"].formatCanonical()
                    if ace.hasFlag(ace.ACE_OBJECT_TYPE_PRESENT):
                        if guid_to_string(ace["ObjectType"]) == EX_RIGHT_CERTIFICATE_ENROLLMENT:
                            enroll_sids.add(sid)
                        elif guid_to_string(ace["ObjectType"]) == EX_RIGHT_CERTIFICATE_AUTOENROLLMENT:
                            autoenroll_sids.add(sid)
                elif ace["TypeName"] == "ACCESS_ALLOWED_ACE":
                    ace = ace["Ace"]
                    mask = ace["Mask"]
                    sid = ace["Sid"].formatCanonical()

                else:
                    continue

                if mask.hasPriv(mask.GENERIC_WRITE) \
                        or mask.hasPriv(mask.GENERIC_ALL) \
                        or mask.hasPriv(certilib.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP):
                    write_property_sids.add(sid)

                if mask.hasPriv(mask.WRITE_DACL):
                    write_dacl_sids.add(sid)

                if mask.hasPriv(mask.WRITE_OWNER):
                    write_owner_sids.add(sid)

            sid = sid_not_manager(enroll_sids)
            enrollment_acl = print_sids(sid, sids_resolver, offset=6)

            sid = sid_not_manager(autoenroll_sids)
            autoenrollment_acl = print_sids(sid, sids_resolver, offset=6)

            sid = sid_not_manager(write_owner_sids)
            writeowner_acl = print_sids(sid, sids_resolver, offset=6)

            sid = sid_not_manager(write_dacl_sids)
            writedacl_acl = print_sids(sid, sids_resolver, offset=6)

            sid = sid_not_manager(write_property_sids)
            writeprop_acl = print_sids(sid, sids_resolver, offset=6)

            if (len(enrollment_acl) == 0 & len(autoenrollment_acl) == 0 & len(writeowner_acl) == 0 & len(
                    writedacl_acl) == 0 & len(writeprop_acl) == 0):
                continue
            else:
                instance = {}
                if temp.name == 'User' or temp.name == 'Machine' or temp.name == 'DomainController':
                    continue
                else:
                    attacked = True
                    instance["模板名"] = temp.name
                    instance["注册CA"] = ", ".join(temp.enroll_services)
                    instance["证书标志位"] = ", ".join(temp.certificate_name_flags_names)
                    instance["注册权限"] = enrollment_acl
                    instance["自动注册权限"] = autoenrollment_acl
                    instance["修改owner权限"] = writeowner_acl
                    instance["修改DACL权限"] = writedacl_acl
                    instance["写属性权限"] = writeprop_acl
                    instance_list.append(instance)

        if attacked:
            result['status'] = 1
            result['data'] = {"instance_list": instance_list}

        return result

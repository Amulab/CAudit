from copy import copy
from ldap3 import SUBTREE
from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
import impacket.ldap.ldaptypes
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, SR_SECURITY_DESCRIPTOR, ACCESS_MASK


def sid_not_manager(sid):
    if len(sid.split('-')) == 8:
        lenth = str(sid.split('-')[7].strip())
        if "512" not in lenth and "519" not in lenth and "517" not in lenth and "526" not in lenth and "527" not in lenth:
            return sid


def ACL(sd, name):
    info = {}
    for ace in sd['Dacl'].aces:
        ace['Ace'].getData()

        # 具有写入权限
        if ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP) == True:
            sid = sid_not_manager(ace['Ace']['Sid'].formatCanonical())
            if sid != None:
                info[sid] = "对%s存在写入权限" % (name)

        # 具有完全控制权限
        if ace['Ace']['Mask']['Mask'] == 983551:
            sid = sid_not_manager(ace['Ace']['Sid'].formatCanonical())
            if sid != None:
                info[sid] = "对%s存在完全控制权限" % (name)

        # 具有writedacl权限
        if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL):
            sid = sid_not_manager(ace['Ace']['Sid'].formatCanonical())
            if sid != None:
                info[sid] = "对%s存在修改ACL权限" % (name)

        # 具有WriteOwner检测：
        if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_OWNER):
            sid = sid_not_manager(ace['Ace']['Sid'].formatCanonical())
            if sid != None:
                info[sid] = "对%s存在修改所有者权限" % (name)

    return info


class PluginADESC5(PluginADScanBase):
    """ESC5 - PKI访问控制"""

    display = "ESC5 - PKI访问控制"
    alias = "esc5"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:

        depict_dict = []
        sid_list = []
        result = copy(self.result)
        instance_list = []

        query = "(objectclass=cRLDistributionPoint)"
        attributes = ["cn", "distinguishedName"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(
            search_base="CN=Configuration," + self.ldap_cli.domain_dn,
            search_filter=query,
            search_scope=SUBTREE,
            get_operational_attributes=True,
            attributes=attributes,
            paged_size=1000,
            generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            name = entry["attributes"]["distinguishedName"].split(",")
            caname, hostname = name[0].strip('CN='), name[1].strip('CN=')

            query = "(&(objectCategory=computer)(objectClass=user)(name=%s))" % hostname
            attributes = ["cn", "nTSecurityDescriptor"]

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
                secDescData = entry["attributes"]["nTSecurityDescriptor"]
                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(secDescData)
                depict_dict.append(ACL(sd, hostname))

        PKI_list = ["Public Key Services", "Certificate Templates", "Certification Authorities", "NTAuthCertificates"]
        for PKI in PKI_list:
            query = "(name=%s)" % PKI
            attributes = ["cn", "nTSecurityDescriptor"]

            entry_generator = self.ldap_cli.con.extend.standard.paged_search(
                search_base="CN=Configuration," + self.ldap_cli.domain_dn,
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
                name = entry["attributes"]["cn"]
                secDescData = entry["attributes"]["nTSecurityDescriptor"]
                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(secDescData)
                depict_dict.append(ACL(sd, name))

        for info in depict_dict:
            for sid, scan in info.items():
                if sid not in sid_list:
                    sid_list.append(sid)

        for sid in sid_list:
            query = "(objectSid=%s)" % sid
            attributes = ["name"]

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

                for info in depict_dict:
                    result['status'] = 1
                    instance = {}
                    instance["用户名"] = entry["attributes"]["name"]
                    if len(info.get(sid, '')) != 0:
                        instance["描述"] = info.get(sid, '')
                    if len(instance) == 2:
                        instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

# coding: utf-8

"""
    通过 LDAP 检索域内的相关信息
"""

import random

from ldap3 import Server, Connection, ALL, SUBTREE
from modules.adi_lib.common.errors import LDAPSearchFailException
from modules.adi_lib.common.util import get_netbios_domain, escape_ldap_filter
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.uuid import bin_to_string
import impacket.ldap.ldaptypes
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, SR_SECURITY_DESCRIPTOR

class LDAPSearch(object):
    def __init__(self, domain, ldap_account):
        self.ldap_account = ldap_account
        self.domain = get_netbios_domain(domain)
        self.con = Connection(self._get_server(),
                              user=ldap_account["user"],
                              password=ldap_account["password"],
                              auto_bind=True)
        self.domain_dn = ldap_account["dn"]


    def _get_server(self):
        return Server(self.ldap_account["server"], get_info=ALL)

    def search_by_sid(self, sid, attributes=None):
        """
            通过SID搜索域用户的相关信息
        """
        sid = escape_ldap_filter(sid)
        if attributes is None:
            attributes = ['cn']
        self.con.search(self.domain_dn, '(ObjectSID={sid})'.format(sid=sid), attributes=attributes)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            # sid 是唯一的 取数组第一个即可
            entry = self.con.entries[0]
            return entry
        elif self.con.result["result"] != 0:
            raise LDAPSearchFailException()

    def search_by_name(self, user, attributes=None):
        """
            通过用户名搜索
        """
        user = escape_ldap_filter(user)
        if attributes is None:
            attributes = ["CN"]
        dn = self.domain_dn
        self.con.search(dn, '(sAMAccountName=%s)' % user, attributes=attributes)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            entry = self.con.entries[0]
            return entry
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_admins(self):
        admin_users = []
        self.con.search(self.domain_dn, '(&(adminCount=1)(objectclass=person))', attributes=['cn', 'objectsid'])
        if self.con.result["result"] == 0:
            entries = self.con.entries
            for en in entries:
                cn_name = en["cn"][0]
                sid = en["objectSid"][0]
                admin_users.append({
                    "user": cn_name,
                    "sid": sid,
                    "domain": self.domain
                })
            return admin_users
        else:
            raise LDAPSearchFailException()

    def search_domain_controller(self):
        dn = self.domain_dn
        self.con.search(dn, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=532480))",
                        attributes=["cn", "dnsHostName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_constrained_accounts(self):
        """
            查找所有约束委派账户
        """
        dn = self.domain_dn
        self.con.search(dn, "(msDS-AllowedToDelegateTo=*)",
                        attributes=["cn", "objectSid", "sAMAccountName", "msDS-AllowedToDelegateTo"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_unconstrained_accounts(self):
        """
            无约束委派的账户
        """
        dn = self.domain_dn
        self.con.search(dn, "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                        attributes=["cn", "objectSid", "sAMAccountName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_pre_auth_not_required(self):
        dn = self.domain_dn
        self.con.search(dn, "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
                        attributes=["cn", "objectSid", "sAMAccountName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_spn_account(self):
        dn = self.domain_dn
        self.con.search(dn, "(servicePrincipalName=ldap*)",
                        attributes=["cn", "servicePrincipalName", "sAMAccountName"])
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def get_support_aes_account(self):
        dn = self.domain_dn
        self.con.search(dn, "(&(objectClass=Computer)(msds-supportedencryptiontypes>=8))",
                        attributes=["sAMAccountName"], paged_size=200)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries[random.randint(20, 180)]
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_by_custom(self, filter_condition, attributes, paged_size=10000):
        dn = self.domain_dn
        self.con.search(dn, filter_condition, attributes=attributes, paged_size=paged_size)
        if self.con.result["result"] == 0 and len(self.con.entries) > 0:
            return self.con.entries
        elif self.con.result["result"] != 0:
            print(self.con.result)
            raise LDAPSearchFailException()

    def search_admins_info(self, attributes_value, filter_query=''):
        controls = security_descriptor_control(sdflags=0x04)
        sid_list = []
        dn_list = []
        sguid1 = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        sguid2 = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        entry_list = []
        depict_dict = {}

        # 对域控ACL进行查询
        query = "(objectClass=domain)"
        attributes = ["nTSecurityDescriptor"]

        entry_generator = self.con.extend.standard.paged_search(search_base=self.domain_dn,
                                                                search_filter=query,
                                                                search_scope=SUBTREE,
                                                                get_operational_attributes=True,
                                                                attributes=attributes,
                                                                paged_size=1000,
                                                                controls=controls,
                                                                generator=True)

        impacket.ldap.ldaptypes.RECALC_ACL_SIZE = False

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            dn = entry['dn']
            secDescData = entry["attributes"]["nTSecurityDescriptor"]
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(secDescData)

            for ace in sd['Dacl'].aces:
                # 具有写入权限的用户
                print(ace)
                if ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP) == True:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    if sid not in sid_list:
                        sid_list.append(sid)
                        depict_dict[sid] = "对域控存在写入权限"
                # 具有完全控制用户
                if ace['Ace']['Mask']['Mask'] == 983551:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    if sid not in sid_list:
                        sid_list.append(sid)
                        depict_dict[sid] = "对域控存在完全控制权限"
                # 具有Dcsync用户
                if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    continue
                if len(ace['Ace']['ObjectType']) == 0:
                    continue
                objectTypeGuid = bin_to_string(ace['Ace']['ObjectType']).lower().strip()
                if objectTypeGuid == sguid1 or objectTypeGuid == sguid2:
                    sid = ace['Ace']['Sid'].formatCanonical()
                    if sid not in sid_list:
                        sid_list.append(sid)
                        depict_dict[sid] = "对域控存在dcsync控制权限"

        # 查询组member信息
        for i in sid_list:
            query = "(objectSid=%s)" % (i)
            attributes = ["cn", "objectSid", "member", 'name']

            entry_generator = self.con.extend.standard.paged_search(search_base=self.domain_dn,
                                                                             search_filter=query,
                                                                             search_scope=SUBTREE,
                                                                             get_operational_attributes=True,
                                                                             attributes=attributes,
                                                                             paged_size=1000,
                                                                             generator=True)
            for entry in entry_generator:
                if entry["type"] != "searchResEntry":
                    continue
                if (entry["attributes"]["member"], list) and len(
                        entry["attributes"]["member"]) != 0:
                    dn = entry["attributes"]["member"]
                    name = entry["attributes"]["name"]
                    for i in dn:
                        if i not in dn_list:
                            depict = {}
                            depict['dn'] = i
                            depict['归属'] = "存在于%s高权限组" % (name)
                            dn_list.append(depict)

        # 查询组内用户
        for i in dn_list:
            query = "(distinguishedName=%s)" % (i['dn'])
            attributes = ["objectSid", "memberOf"]

            entry_generator = self.con.extend.standard.paged_search(search_base=self.domain_dn,
                                                                             search_filter=query,
                                                                             search_scope=SUBTREE,
                                                                             get_operational_attributes=True,
                                                                             attributes=attributes,
                                                                             paged_size=1000,
                                                                             generator=True)
            for entry in entry_generator:
                if entry["type"] != "searchResEntry":
                    continue
                sid1 = entry['attributes']['objectSid']
                name = i['归属']

                if sid1 not in sid_list:
                    sid_list.append(sid1)
                    depict_dict[sid1] = name

        # 对特权组或用户具有完全控制、写入权限
        for i in sid_list:
            query = "(objectSid=%s)" % (i)
            attributes = ["nTSecurityDescriptor", "name"]

            entry_generator = self.con.extend.standard.paged_search(search_base=self.domain_dn,
                                                                             search_filter=query,
                                                                             search_scope=SUBTREE,
                                                                             get_operational_attributes=True,
                                                                             attributes=attributes,
                                                                             paged_size=1000,
                                                                             controls=controls,
                                                                             generator=True)

            impacket.ldap.ldaptypes.RECALC_ACL_SIZE = False

            for entry in entry_generator:
                if entry["type"] != "searchResEntry":
                    continue
                name = entry["attributes"]['name']
                secDescData = entry["attributes"]["nTSecurityDescriptor"]
                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(secDescData)

                for ace in sd['Dacl'].aces:
                    # 具有完全控制用户
                    if ace['Ace']['Mask']['Mask'] == 983551:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid not in sid_list:
                            sid_list.append(sid)
                            depict_dict[sid] = "对%s存在完全控制权限" % (name)

                    # 具有写入权限的用户
                    if ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP) == True:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        if sid not in sid_list:
                            sid_list.append(sid)
                            depict_dict[sid] = "对%s存在写入权限" % (name)

        # 利用sid查询用户信息
        for i in sid_list:
            query = "(&(objectClass=user)(objectSid=%s)%s)" % (i, filter_query)
            attributes = attributes_value

            entry_generator = self.con.extend.standard.paged_search(search_base=self.domain_dn,
                                                                             search_filter=query,
                                                                             search_scope=SUBTREE,
                                                                             get_operational_attributes=True,
                                                                             attributes=attributes,
                                                                             paged_size=1000,
                                                                             generator=True)
            for entry in entry_generator:
                entry_list.append(entry)
        return entry_list, depict_dict

if __name__ == '__main__':
    pass

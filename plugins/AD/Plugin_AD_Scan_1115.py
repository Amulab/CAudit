import struct
from copy import copy
from ldap3 import SUBTREE
from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt, samr
import dns.resolver
import socket
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, SR_SECURITY_DESCRIPTOR


def start(remoteHost, username, password, caname):
    try:
        rpctransport = transport.SMBTransport(remoteHost, 445, r'\winreg', username, password, "", "", "", "")
    except (Exception) as e:
        
        return

    try:
        # Set up winreg RPC
        rrpclient = rpctransport.get_dce_rpc()
        rrpclient.connect()
        rrpclient.bind(rrp.MSRPC_UUID_RRP)
    except (Exception) as e:
        
        return

    try:

        ans = rrp.hOpenLocalMachine(rrpclient)
        hRootKey = ans['phKey']
        subkey = rrp.hBaseRegOpenKey(rrpclient, hRootKey,
                                     ("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s") % caname)
        # rrp.hBaseRegSetValue(rrpclient, subkey["phkResult"], "DirectoryServiceExtPt", 1, "test")
        return rrp.hBaseRegQueryValue(rrpclient, subkey["phkResult"], "Security")

    except (Exception) as e:
        
        return


def lookuphostname(hostname, dnsip):
    dnsresolver = dns.resolver.Resolver()
    try:
        socket.inet_aton(dnsip)
        dnsresolver.nameservers.clear()
        dnsresolver.nameservers = [dnsip]
    except socket.error:
        pass
    res = dnsresolver.resolve(hostname, 'A')
    return str(res.response.answer[0][0])


class PluginADESC7(PluginADScanBase):
    """ESC7 - 证书颁发机构ACL配置不当"""

    display = "ESC7 - 证书颁发机构ACL配置不当"
    alias = "esc7"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
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

            caip = lookuphostname(hostname + "." + self.dc_conf["name"], self.ldap_conf["server"])
            Security = start(caip, self.ldap_username, self.ldap_user_password, caname)
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(Security[1])
            """
                MANAGE_CA = 1
                MANAGE_CERTIFICATES = 2
                AUDITOR = 4
                OPERATOR = 8
                READ = 256
                ENROLL = 512
            """

            for ace in sd['Dacl'].aces:
                sid = ace['Ace']['Sid'].formatCanonical()
                if ace['AceType'] == ACCESS_ALLOWED_ACE.ACE_TYPE:
                    if ace['Ace']['Mask']['Mask'] & 1 == 1 and ace['Ace']['Mask']['Mask'] & 2 != 2:
                        RID = sid.split('-')[-1].strip()
                        if RID != '512' and RID != '519' and RID != '544':
                            instance = {"证书服务器": hostname, "证书CA": caname, "用户名": sid, "权限": "ManageCa"}
                            instance_list.append(instance)
                    elif ace['Ace']['Mask']['Mask'] & 2 == 2 and ace['Ace']['Mask']['Mask'] & 1 != 1:
                        RID = sid.split('-')[-1].strip()
                        if RID != '512' and RID != '519' and RID != '544':
                            instance = {"证书服务器": hostname, "证书CA": caname, "用户名": sid,
                                        "权限": "ManageCertificates"}
                            instance_list.append(instance)
                    elif ace['Ace']['Mask']['Mask'] & 3 == 3:
                        RID = sid.split('-')[-1].strip()
                        if RID != '512' and RID != '519' and RID != '544':
                            instance = {"证书服务器": hostname, "证书CA": caname, "用户名": sid,
                                        "权限": "ManageCa & ManageCertificates"}
                            instance_list.append(instance)

        for info in instance_list:

            query = "(objectSid=%s)" % info["用户名"]
            attributes = ["name"]

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
                name = entry["attributes"]["name"]
                info.update({"用户名": name})

        if len(instance_list) != 0:
            result['status'] = 1

        result['data'] = {"instance_list": instance_list}
        return result

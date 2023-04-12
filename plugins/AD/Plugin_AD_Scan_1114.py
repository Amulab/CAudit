import socket
from copy import copy

import dns.resolver
from impacket.dcerpc.v5 import transport, rrp
from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


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
        subkey = rrp.hBaseRegOpenKey(rrpclient, hRootKey, (
            "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy") % caname)
        # rrp.hBaseRegSetValue(rrpclient, subkey["phkResult"], "DirectoryServiceExtPt", 1, "test")
        return rrp.hBaseRegQueryValue(rrpclient, subkey["phkResult"], "EditFlags")

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


class PluginADESC6(PluginADScanBase):
    """ESC6 - 证书服务器配置EDITF_ATTRIBUTESUBJECTALTNAME2"""

    display = "ESC6 - 证书服务器配置EDITF_ATTRIBUTESUBJECTALTNAME2"
    alias = "esc6"
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

        flag = 0
        hostname_list = []
        caname_list = []
        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            name = entry["attributes"]["distinguishedName"].split(",")
            caname, hostname = name[0].strip('CN='), name[1].strip('CN=')

            caip = lookuphostname(hostname + "." + self.dc_conf["name"], self.ldap_conf["server"])
            EditFlags = start(caip, self.ldap_username, self.ldap_user_password, caname)
            if ((EditFlags[1] & 262144) == 262144) == True:
                flag = 1
                hostname_list.append(hostname)
                caname_list.append(caname)
            else:
                continue

        if flag == 1:
            result['status'] = 1
            instance = {}
            instance["证书服务器"] = hostname_list
            instance["证书CA"] = caname_list
            instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

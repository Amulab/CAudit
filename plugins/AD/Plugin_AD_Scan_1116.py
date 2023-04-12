from copy import copy
from ldap3 import SUBTREE
from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
import dns.resolver
import requests, socket


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


class PluginADESC8(PluginADScanBase):
    """ESC8 - 证书注册web服务启用NTLM认证"""

    display = "ESC8 - 证书注册web服务启用NTLM认证"
    alias = "esc8"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        http_list = ["/certsrv/", "/ADPolicyProvider_CEP_Kerberos/service.svc", "/certsrv/mscep/"]
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
        caip = ''

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            name = entry["attributes"]["distinguishedName"].split(",")
            caname, hostname = name[0].strip('CN='), name[1].strip('CN=')
            caip = lookuphostname(hostname + "." + self.dc_conf["name"], self.ldap_conf["server"])
            http1 = "/%s_CES_Kerberos/service.svc" % caname
            http2 = "/%s_CES_Kerberos/service.svc/CES" % caname
            http_list.append(http1)
            http_list.append(http2)
        if not caip:
            return result
        for http in http_list:
            url = "http://" + caip + http
            req = requests.get(url)
            if req.status_code != 401:
                continue
            if "NTLM" in str(req.headers):
                result['status'] = 1
                instance = {}
                instance["证书服务器"] = hostname
                instance["证书CA"] = caname
                instance["URL"] = url
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

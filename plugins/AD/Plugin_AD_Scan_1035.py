from copy import copy

from ldap3 import SUBTREE

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes
from impacket.ldap import ldaptypes


class PluginADAdminSDHolderProtectionDisabled(PluginADScanBase):
    """`某些关键组禁用了AdminSDHolder保护"""  # builtin表示本地用户或组，先查域控，筛选域控版本（这个注释掉了，要用找我）,再把sid列表写出来，根据内置组和域的组来分别判断

    display = "某些关键组禁用了AdminSDHolder保护"
    alias = "disable_admin_sid_hod"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        instance_list = []
        query = "(cn=AdminSDHolder)"
        attributes = ["cn", "NTSecurityDescriptor", "distinguishedName"]
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(
            search_base=self.ldap_cli.domain_dn,
            search_filter=query,
            search_scope=SUBTREE,
            get_operational_attributes=True,
            attributes=attributes,
            paged_size=1000,
            generator=True)
        sq = []  # 用来接收sid
        rid = []

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            secDescData = entry['attributes']['nTSecurityDescriptor']
            secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

            for ace in secDesc['Dacl'].aces:
                sid = ace['Ace']['Sid'].formatCanonical()
                if sid in sq:
                    continue
                sq.append(sid)

            for sid in sq:
                if len(sid.split('-')) == 5:
                    lenth = str(sid.split('-')[4].strip())
                    rid.append(lenth)
            if "554" not in rid:
                instance = {}
                result['status'] = 1
                instance["builtin："] = "Pre-Windows 2000 Compatible Access组禁用了AdminSDHolder保护"
                instance_list.append(instance)
            if "544" not in rid:
                instance = {}
                result['status'] = 1
                instance["builtin："] = "Administrators组禁用了AdminSDHolder保护"
                instance_list.append(instance)
            if "560" not in rid:
                instance = {}
                result['status'] = 1
                instance["builtin："] = "Windows Authorization Access Group组禁用了AdminSDHolder保护"
                instance_list.append(instance)
            if "561" not in rid:
                instance = {}
                result['status'] = 1
                instance["builtin："] = "Terminal Server License Servers组禁用了AdminSDHolder保护"
                instance_list.append(instance)

            rid = []
            for sid in sq:
                if len(sid.split('-')) == 8:
                    lenth = str(sid.split('-')[7].strip())
                    rid.append(lenth)
            if "512" not in rid:
                instance = {}
                result['status'] = 1
                instance["Domain Groups："] = "Domain Admins组禁用了AdminSDHolder保护"
                instance_list.append(instance)
            if "519" not in rid:
                instance = {}
                result['status'] = 1
                instance["Domain Groups："] = "Enterprise Admins组禁用了AdminSDHolder保护"
                instance_list.append(instance)
            if "517" not in rid:
                instance = {}
                result['status'] = 1
                instance["Domain Groups："] = "Cert Publishers组禁用了AdminSDHolder保护"
                instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

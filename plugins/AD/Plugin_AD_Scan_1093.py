from copy import copy

from ldap3 import SUBTREE
from io import BytesIO

import chardet

from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADScriptOutOfDomain(PluginADScanBase):
    """检查登录脚本是否位于受信任的域中"""
    display = "检查登录脚本是否位于受信任的域中"
    alias = "ScriptOutOfDomain"
    p_type = AllPluginTypes.Scan

    def parse(self, smb, share, filename):
        results = []
        filename = filename.replace('/', '\\')
        fh = BytesIO()
        smb.getFile(share, filename, fh.write)
        outputs = fh.getvalue()
        encoding = chardet.detect(outputs)["encoding"]
        if encoding != None:
            filecontent = outputs.decode(encoding).rstrip()
            filecontent = filecontent.split('\n')
            results = filecontent

        else:
            output.debug("Outputs cannot be correctly decoded, are you sure the text is readable ?")
            fh.close()
        return results

    def find_cpasswords(self, smb, share, base_dir, extension='ini'):
        result = copy(self.result)
        instance_list = []
        searchdirs = [base_dir + '/']
        domain = self.dc_domain
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                for sharedfile in smb.listPath(share, sdir + '*', password=None):
                    if sharedfile.get_longname() not in ['.', '..']:
                        if sharedfile.is_directory():
                            next_dirs.append(sdir + sharedfile.get_longname() + '/')
                        else:
                            if sharedfile.get_longname().endswith('.' + extension):
                                results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                if len(results) != 0:
                                    for line in results:
                                        if "0CmdLine" in line:
                                            CmdLine = line.replace("0CmdLine=", "")
                                            if CmdLine.startswith('\\\\'):
                                                cmdline = CmdLine.split('\\')
                                                ret = cmdline[2].find('.')
                                                if ret == -1:
                                                    pass
                                                else:
                                                    ret2 = cmdline[2].find(domain)
                                                    if ret2 == -1:
                                                        result['status'] = 1
                                                        instance = {"Matching file": sdir + sharedfile.get_longname()}
                                                        instance_list.append(instance)

            searchdirs = next_dirs
            output.debug('Next iteration with %d folders.' % len(next_dirs))
        result['data'] = {"instance_list": instance_list}
        return result



    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        domain = self.dc_domain
        result = self.verify2()

        query = "(|(objectClass=user)(objectClass=computer))"
        attributes = ["cn", "scriptPath", "distinguishedName"]
        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        instance_list = []

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            if entry["attributes"]["scriptPath"] != None:
                if str(entry["attributes"]["scriptPath"]).startswith('\\\\'):
                    cmdline = str(entry["attributes"]["scriptPath"]).split('\\')
                    ret = cmdline[2].find('.')
                    if ret == -1:
                        pass
                    else:
                        ret2 = cmdline[2].find(domain)
                        if ret2 == -1:
                            result['status'] = 1
                            instance = {}
                            instance["Name"] = entry["attributes"]["cn"]
                            instance["Distinguished name"] = entry["attributes"]["distinguishedName"]
                            instance["ScriptPath"] = entry["attributes"]["scriptPath"]
                            instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result

    def verify2(self, *args, **kwargs):
        target_ip = self.dc_ip
        domain = self.dc_domain
        username = self.ldap_conf["user"].split("@")[0]
        password = self.ldap_conf["password"]
        address = self.dc_ip
        result = copy(self.result)

        smbClient = self.init_smb_session(target_ip, domain, username, password, address, '', '')
        result = self.find_cpasswords(smbClient, 'SYSVOL', '//' + domain + '/Policies', extension='inf')

        return result

    def init_smb_session(self, target_ip, domain, username, password, address, lmhash, nthash):
        smbClient = SMBConnection(address, target_ip, sess_port=445)
        dialect = smbClient.getDialect()
        if dialect == SMB_DIALECT:
            output.debug("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            output.debug("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            output.debug("SMBv2.1 dialect used")
        else:
            output.debug("SMBv3.0 dialect used")
        smbClient.login(username, password, domain, lmhash, nthash)
        if smbClient.isGuestSession() > 0:
            output.debug("GUEST Session Granted")
        else:
            output.debug("USER Session Granted")
        return smbClient


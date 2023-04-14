from copy import copy
from io import BytesIO

import chardet

from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


def strip_control_characters(s):
    word = ''
    for i in s:
        if i > 31 or i == 10 or i == 13:
            word += chr(i)
    return word


class PluginADAuditPowershell(PluginADScanBase):
    """Powershell日志记录未启用"""
    display = "Powershell日志记录未启用"
    alias = "AuditPowershell"
    p_type = AllPluginTypes.Scan

    def parse(self, smb, share, filename):
        results = []
        filename = filename.replace('/', '\\')
        fh = BytesIO()
        smb.getFile(share, filename, fh.write)
        outputs = fh.getvalue()
        encoding = chardet.detect(outputs)["encoding"]
        if encoding != None:
            filecontent = strip_control_characters(outputs)
            filecontent = filecontent.split("[", 1)
            results = filecontent
        else:
            output.debug("Outputs cannot be correctly decoded, are you sure the text is readable ?")
            fh.close()
        return results

    def find_cpasswords(self, smb, share, base_dir, extension='POL'):

        result = copy(self.result)
        instance_list = []
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                for sharedfile in smb.listPath(share, sdir + '*', password=None):
                    if sharedfile.get_longname() not in ['.', '..']:
                        if sharedfile.is_directory():
                            next_dirs.append(sdir + sharedfile.get_longname() + '/')
                        else:
                            if sharedfile.get_longname().upper().endswith('.' + extension):
                                results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                # print(sdir + sharedfile.get_longname())
                                if len(results) != 0:
                                    s1 = ''
                                    i = 0
                                    # print(results)
                                    for line in results:
                                        i = i + 1
                                        s1 = s1 + line
                                        if i == 2:
                                            # print(s1)
                                            # print(12)
                                            if "[Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging;EnableScriptBlockLogging;;;][Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging;EnableScriptBlockInvocationLogging;;;]" in s1 \
                                                    and "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging;EnableModuleLogging;;;][Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames;**delvals.;;; ][Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames" in s1:
                                                result['status'] = 0
                                                instance = {}
                                                instance["Matching file"] = ""
                                                instance["Status"] = ""
                                                instance_list = [instance]
                                                result['data'] = {"instance_list": instance_list}
                                                return result
                                            else:
                                                result['status'] = 1
                                                instance = {}
                                                instance["Matching file"] = sdir + sharedfile.get_longname()
                                                instance["Status"] = "Powershell日志记录未启用"
                                                instance_list.append(instance)
                                                result['data'] = {"instance_list": instance_list}

                                        else:
                                            continue

                                        # if "[Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging;EnableScriptBlockLogging;;;][Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging;EnableScriptBlockInvocationLogging;;;]" in line:
                                        #     result['status'] = 0
                                        #     instance = {}
                                        #     instance[
                                        #         "Matching file"] = ""
                                        #     instance[
                                        #         "Status"] = ""
                                        #     instance_list = [instance]
                                        #     result['data'] = {"instance_list": instance_list}
                                        #     return  result
                                        # else:
                                        #     instance = {}
                                        #     instance[
                                        #         "Matching file"] = sdir + sharedfile.get_longname(
                                        #     )
                                        #     instance["Status"] = "Powershell日志记录未启用"
                                        #     instance_list.append(instance)
                                        #     result['data'] = {"instance_list": instance_list}

            searchdirs = next_dirs
            output.debug('Next iteration with %d folders.' % len(next_dirs))

        return result



    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        target_ip = self.dc_ip
        domain = self.dc_domain
        username = self.ldap_conf["user"].split("@")[0]
        password = self.ldap_conf["password"]
        address = self.dc_ip
        result = copy(self.result)

        smbClient = self.init_smb_session(target_ip, domain, username,
                                          password, address, '', '')
        result = self.find_cpasswords(smbClient, 'SYSVOL', '//' + domain + '/Policies', extension='POL')
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


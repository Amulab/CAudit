from copy import copy
from io import BytesIO

import chardet

from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADPwdEmpty(PluginADScanBase):
    """存在允许帐户空密码登陆的策略"""
    display = "存在允许帐户空密码登陆的策略"
    alias = "LoginEmptyPwd"
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

    def find_cpasswords(self, smb, share, base_dir, extension='inf'):

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
                            if sharedfile.get_longname().endswith('.' + extension):
                                results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                if len(results) != 0:
                                    for line in results:
                                        if "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" in line:
                                            LimitBlankPasswordUse = int(line.split(",")[-1].strip().replace("\r", ""))
                                            if LimitBlankPasswordUse == 0:
                                                result['status'] = 1
                                                instance = {}
                                                instance["Matching file"] = sdir + sharedfile.get_longname()
                                                instance["Status"] = "存在允许帐户空密码登陆的策略"
                                                instance_list.append(instance)
            searchdirs = next_dirs
            # output.debug('Next iteration with %d folders.' % len(next_dirs))
        result['data'] = {"instance_list": instance_list}
        return result

    display = "存在超过45天未更改密码的计算机帐户"
    alias = "pwd_no_change_45"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        target_ip = self.dc_ip
        domain = self.dc_domain
        username = self.ldap_conf["user"].split("@")[0]
        password = self.ldap_conf["password"]
        address = self.dc_ip

        smbClient = self.init_smb_session(target_ip, domain, username, password, address, '', '')
        result = self.find_cpasswords(smbClient, 'SYSVOL', '//' + domain + '/Policies', extension='inf')
        return result

    def init_smb_session(self, target_ip, domain, username, password, address,
                         lmhash, nthash):
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

        return smbClient



from copy import copy
import os

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


from modules.regpol_tool import parser_reg_pol


from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SMBConnection)


def bytes_16(str):
    """
    byte数组转换为16进制
    """
    return ''.join([hex(c).replace('0x', '') for c in str])


def strip_control_characters(s):
    word = ''
    for i in s:
        if i > 31 or i == 10 or i == 13:
            word += chr(i)
    return word


class PluginADNoGPOLLMNR(PluginADScanBase):
    """发现已启用LLMNR协议"""

    display = "发现已启用LLMNR协议"
    alias = "NoGPOLLMNR"
    p_type = AllPluginTypes.Scan

    def parse(self, smb, share, filename):
        filename = filename.replace('/', '\\')
        reg_pol_file_name = "./regpol.pol"
        f = open(reg_pol_file_name, "wb")
        smb.getFile(share, filename, f.write)
        f.flush()
        f.close()
        reg_pol = parser_reg_pol(reg_pol_file_name)
        os.remove(reg_pol_file_name)
        return reg_pol

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
                                reg_pol = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                dns_key = "Software\Policies\Microsoft\Windows NT\DNSClient"
                                flag = 0
                                for k, v in reg_pol.items():
                                    if dns_key not in k:
                                        continue
                                    if b'\x01\x00\x00\x00' == v:
                                        flag = 1
                                        result['status'] = 1
                                        instance = {}
                                        instance["Status"] = "关闭多播名称解析已禁用"
                                        instance["Matching file"] = sdir + sharedfile.get_longname()
                                        instance_list.append(instance)
                                    else:
                                        flag = 7
                                if flag == 0:
                                    result['status'] = 1
                                    instance = {}
                                    instance["Status"] = "关闭多播名称解析未配置"
                                    instance["Matching file"] = sdir + sharedfile.get_longname()
                                    instance_list.append(instance)
            searchdirs = next_dirs
            output.debug('Next iteration with %d folders.' % len(next_dirs))

        result['data'] = {"instance_list": instance_list}
        return result


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        target_ip = self.dc_ip
        domain = self.dc_domain
        username = self.ldap_conf["user"].split("@")[0]
        password = self.ldap_conf["password"]
        address = self.dc_ip
        smbClient = self.init_smb_session(target_ip, domain, username, password, address, '', '')
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



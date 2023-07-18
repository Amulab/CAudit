from copy import copy
from io import BytesIO

import chardet

from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADAuditDCDir(PluginADScanBase):
    """审核策略中审核目录服务访问未正常开启"""
    display = "审核策略中审核目录服务访问未正常开启"
    alias = "AuditDCDir"
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

    def findfile(self, line, path):

        result = copy(self.result)
        instance_list = []

        if line == 0:
            result['status'] = 1
            instance = {}
            instance["Matching file"] = path
            instance["Status"] = "审核策略中审核目录服务访问未开启审核"
            return instance
            # instance_list.append(
            #     instance)
        elif line == 1:
            result['status'] = 1
            instance = {}
            instance["Matching file"] = path
            instance["Status"] = "审核策略中审核目录服务访问未开启失败审核"
            return instance
            # instance_list.append(
            #     instance)
        elif line == 2:
            result['status'] = 1
            instance = {}
            instance["Matching file"] = path
            instance["Status"] = "审核策略中审核目录服务访问未开启成功审核"
            return instance
            # instance_list.append(
            #     instance)
        else:
            pass
        # result['data'] = {"instance_list": instance_list}
        # return result

    def find_cpasswords(self, smb, share, base_dir):

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
                            if sharedfile.get_longname().endswith('.' + 'csv'):
                                results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                flag1 = 0
                                if len(results) != 0:
                                    for line in results:
                                        if "0cce923b-69ae-11d9-bed3-505054503030" in line:
                                            flag1 = 1
                                            path = sdir + sharedfile.get_longname()
                                            path_list = []
                                            path_list.append(path)
                                            AuditAccountLogon = int(line.split(",")[-1].strip().replace("\r", ""))
                                            if AuditAccountLogon == 3:
                                                result['status'] = 0
                                                result['data'] = {}
                                                return result  # 一旦开启了审核，就返回函数结果，不再执行函数里面的内容
                                            if len(path_list) != 0:
                                                result['status'] = 1
                                                instance_list1 = self.findfile(AuditAccountLogon, path)
                                                instance_list.append(instance_list1)
                                                result['data'] = {"instance_list": instance_list}
                                if flag1 == 0:
                                    result['status'] = 1
                                    path = sdir + sharedfile.get_longname()
                                    instance = {}
                                    instance["Matching file"] = path
                                    instance["Status"] = "审核策略中审核目录服务访问未配置"
                                    instance_list.append(instance)
                                    result['data'] = {"instance_list": instance_list}
                            elif sharedfile.get_longname().endswith('.' + 'inf'):
                                results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                flag2 = 0
                                if len(results) != 0:
                                    for line in results:
                                        if "AuditDSAccess" in line:
                                            flag2 = 1
                                            path = sdir + sharedfile.get_longname()
                                            AuditAccountLogon = int(line.split("=")[-1].strip().replace("\r", ""))
                                            if AuditAccountLogon == 3:
                                                result['status'] = 0
                                                result['data'] = {}
                                                return result  # 一旦开启了审核，就返回函数结果，不再执行函数里面的内容
                                            result['status'] = 1
                                            instance_list2 = self.findfile(AuditAccountLogon, path)
                                            instance_list.append(instance_list2)
                                            result['data'] = {"instance_list": instance_list}
                                if flag2 == 0:
                                    result['status'] = 1
                                    path = sdir + sharedfile.get_longname()
                                    instance = {}
                                    instance["Matching file"] = path
                                    instance["Status"] = "审核策略中审核目录服务访问未配置"
                                    instance_list.append(instance)
                                    result['data'] = {"instance_list": instance_list}

            searchdirs = next_dirs
            # output.debug('Next iteration with %d folders.' % len(next_dirs))
        # result['data'] = {"instance_list": instance_list}
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

        smbClient = self.init_smb_session(target_ip, domain, username, password, address, '', '')
        result = self.find_cpasswords(smbClient, 'SYSVOL', '//' + domain + '/Policies')

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

        return smbClient





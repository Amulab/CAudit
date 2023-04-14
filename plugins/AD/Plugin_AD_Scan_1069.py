import traceback
from io import BytesIO

import chardet

from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADPwdTimeExcept(PluginADScanBase):
    """密码策略中密码使用期限设置不当"""
    display = "密码策略中密码使用期限设置不当"
    alias = "PwdTimeException"
    p_type = AllPluginTypes.Scan

    def parse(self, smb, share, filename):
        results = []
        filename = filename.replace('/', '\\')
        fh = BytesIO()
        try:
            # opening the files in streams instead of mounting shares allows for running the script from
            # unprivileged containers
            smb.getFile(share, filename, fh.write)
        except SessionError as e:
            output.error(e)
            return results
        except Exception as e:
            raise
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
        # logger.info("Searching *.%s files..." % extension)
        # Breadth-first search algorithm to recursively find .extension files
        MinimumPasswordAge = 1
        MaximumPasswordAge = 42
        result = self.result
        instance_list = []
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                try:
                    for sharedfile in smb.listPath(share, sdir + '*', password=None):
                        if sharedfile.get_longname() not in ['.', '..']:
                            if sharedfile.is_directory():
                                # print('Found directory %s/' % sharedfile.get_longname())
                                next_dirs.append(sdir + sharedfile.get_longname() + '/')
                            else:
                                if sharedfile.get_longname().endswith('.' + extension):
                                    results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                                    if len(results) != 0:  # 如果results不为空列表，那么进入if下的代码块
                                        for line in results:
                                            if "MinimumPasswordAge" in line:
                                                MinimumPasswordAge = int(line.replace("MinimumPasswordAge =", ""))
                                            if "MaximumPasswordAge" in line:
                                                MaximumPasswordAge = int(line.replace("MaximumPasswordAge =", ""))
                                        if MinimumPasswordAge != 0 and MinimumPasswordAge < MaximumPasswordAge and MaximumPasswordAge >= 30 and MaximumPasswordAge <= 90:
                                            # 以上MinimumPasswordAge不能为0，可理解为不能立即修改密码
                                            result['status'] = 0
                                        else:
                                            result['status'] = 1
                                            instance = {}
                                            instance["Matching file"] = sdir + sharedfile.get_longname()
                                            instance["MinimumPasswordAge"] = MinimumPasswordAge
                                            instance["MaximumPasswordAge"] = MaximumPasswordAge
                                            instance_list.append(instance)
                except Exception as e:
                    result['error'] = str(e)
                    result["status"] = -1
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
        result = self.result

        try:
            smbClient = self.init_smb_session(target_ip, domain, username, password, address, '', '')
            result = self.find_cpasswords(smbClient, 'SYSVOL', '//' + domain + '/Policies', extension='inf')
        except Exception as e:
            output.error(str(e))
            output.error(traceback.format_exc())
            result['error'] = str(e)
            result["status"] = -1
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



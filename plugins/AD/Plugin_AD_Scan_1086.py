from copy import copy
from io import BytesIO

import chardet

from impacket.smbconnection import (SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADPrivilegeEve(PluginADScanBase):
    """存在普通用户账户被授予危险权限"""
    display = "存在普通用户账户被授予危险权限"
    alias = "PrivilegeEveryone"
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

    @staticmethod
    def Normall_list():
        Normallist = [
            "SeAssignPrimaryTokenPrivilege = *S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415,*S-1-5-82-3876422241-1344743610-1729199087-774402673-2621913236,*S-1-5-20,*S-1-5-19,*S-1-5-82-271721585-897601226-2024613209-625570482-296978595\r",
            "SeAuditPrivilege = *S-1-5-20,*S-1-5-19,*S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415,*S-1-5-82-3876422241-1344743610-1729199087-774402673-2621913236,*S-1-5-82-271721585-897601226-2024613209-625570482-296978595\r",
            "SeBackupPrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544\r",
            "SeBatchLogonRight = *S-1-5-32-559,*S-1-5-32-551,*S-1-5-32-544,*S-1-5-32-568\r",
            "SeChangeNotifyPrivilege = *S-1-5-32-554,*S-1-5-11,*S-1-5-90-0,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0\r",
            "SeCreatePagefilePrivilege = *S-1-5-32-544\r",
            "SeDebugPrivilege = *S-1-5-32-544\r",
            "SeIncreaseBasePriorityPrivilege = *S-1-5-90-0,*S-1-5-32-544\r",
            "SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415,*S-1-5-82-3876422241-1344743610-1729199087-774402673-2621913236,*S-1-5-82-271721585-897601226-2024613209-625570482-296978595\r",
            "SeInteractiveLogonRight = *S-1-5-9,*S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-548,*S-1-5-32-551,*S-1-5-32-544\r",
            "SeLoadDriverPrivilege = *S-1-5-32-550,*S-1-5-32-544\r",
            "SeMachineAccountPrivilege = *S-1-5-11\r",
            "SeNetworkLogonRight = *S-1-5-32-554,*S-1-5-9,*S-1-5-11,*S-1-5-32-544,*S-1-1-0\r",
            "SeProfileSingleProcessPrivilege = *S-1-5-32-544\r",
            "SeRemoteShutdownPrivilege = *S-1-5-32-549,*S-1-5-32-544\r",
            "SeRestorePrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544\r",
            "SeSecurityPrivilege = *S-1-5-32-544\r",
            "SeShutdownPrivilege = *S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544\r",
            "SeSystemEnvironmentPrivilege = *S-1-5-32-544\r",
            "SeSystemProfilePrivilege = *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420,*S-1-5-32-544\r",
            "SeSystemTimePrivilege = *S-1-5-32-549,*S-1-5-32-544,*S-1-5-19\r",
            "SeTakeOwnershipPrivilege = *S-1-5-32-544\r",
            "SeUndockPrivilege = *S-1-5-32-544\r",
            "SeEnableDelegationPrivilege = *S-1-5-32-544"
        ]
        return Normallist

    def find_cpasswords(self, smb, share, base_dir, extension='inf'):

        result = copy(self.result)
        instance_list = []
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                for sharedfile in smb.listPath(share, sdir + '*', password=None):
                    if sharedfile.get_longname() in ['.', '..']:
                        continue
                    if sharedfile.is_directory():
                        next_dirs.append(sdir + sharedfile.get_longname() + '/')
                    else:
                        if not sharedfile.get_longname().endswith('.' + extension):
                            continue
                        results = self.parse(smb, 'SYSVOL', sdir + sharedfile.get_longname())
                        Normallist1 = PluginADPrivilegeEve.Normall_list()

                        if len(results) == 0 or "[Privilege Rights]\r" not in results:
                            continue
                        for index, value in enumerate(results):
                            if value.startswith('Se'):
                                if value not in Normallist1:
                                    flag = value.split(' ')[0]
                                    item = [i for i in Normallist1 if i.startswith(flag)]
                                    if not item:
                                        output.debug('not found template')
                                        continue
                                    try:
                                        scan_result = [i.strip() for i in value.split('= ')[1].split(',')]
                                        template_result = [i.strip() for i in item[0].split('= ')[1].split(',')]
                                        compare_result = set(scan_result).difference(set(template_result))
                                        if len(compare_result) != 0:
                                            result['status'] = 1
                                            instance = {"Matching file": sdir + sharedfile.get_longname(),
                                                        "Privilege": flag + ' = ' + ','.join(list(compare_result))}
                                            instance_list.append(instance)
                                    except Exception as e:
                                        output.debug('compare error')
                                        output.debug(e)
                                        continue
                            else:
                                continue
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



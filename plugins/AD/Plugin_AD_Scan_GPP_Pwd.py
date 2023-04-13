import base64
import traceback
from io import BytesIO
from xml.dom import minidom

import chardet
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from impacket.smbconnection import (SessionError, SMBConnection)

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADGPPPwd(PluginADScanBase):
    """
    GPP漏洞探测
    """

    display = "GPP漏洞探测"
    alias = "gpp_pwd"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        try:
            smbconn = SMBConnection(self.dc_ip, self.dc_ip, timeout=5)
            smbconn.login(self.ldap_username, self.ldap_user_password)

            g = GetGPPasswords(smbconn, "SYSVOL")
            g.checkgpp("/")
            self.result = g.result
        except Exception as e:
            self.result['status'] = -1
            self.result['error'] = str(e)

        return self.result


class GetGPPasswords(object):
    """docstring for GetGPPasswords."""
    GPPresult = []

    def __init__(self, smb, share):
        super(GetGPPasswords, self).__init__()
        self.smb = smb
        self.share = share
        self.result = {
            "status": 0,  # 0 没有漏洞 1有漏洞 -1是插件报错了
            "data": {},
            "desc": "",
            "error": "",
        }


    def checkgpp(self, base_dir, extension='xml'):
        rets = []
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                try:
                    for sharedfile in self.smb.listPath(self.share,sdir + '*'):
                        if sharedfile.get_longname() not in ['.', '..']:
                            if sharedfile.is_directory():
                                next_dirs.append(sdir + sharedfile.get_longname() + '/')
                            else:
                                if sharedfile.get_longname().endswith('.' + extension):
                                    results = self.parse(sdir + sharedfile.get_longname())
                                    if len(results) != 0:
                                        rets.append(results)
                                else:
                                    pass
                except Exception as e:
                    print(e)
            searchdirs = next_dirs

        if len(rets) !=0:
            self.result['status'] = 1
        self.result['data']['results'] = rets

    def parse_xmlfile_content(self, filename, filecontent):
        results = []
        try:
            root = minidom.parseString(filecontent)
            properties_list = root.getElementsByTagName("Properties")

            # function to get attribute if it exists, returns "" if empty
            def read_or_empty(element, attribute):
                return (element.getAttribute(attribute)
                        if element.getAttribute(attribute) != None else "")

            for properties in properties_list:
                cpwd_flag = read_or_empty(properties, 'cpassword')
                if not cpwd_flag:
                    output.debug("cpassword value not exist, is safety")
                else:
                    results.append({
                        'newname':
                            read_or_empty(properties, 'newName'),
                        'changed':
                            read_or_empty(properties.parentNode, 'changed'),
                        'cpassword':
                            read_or_empty(properties, 'cpassword'),
                        'password':
                            self.decrypt_password(
                                read_or_empty(properties, 'cpassword')),
                        'username':
                            read_or_empty(properties, 'userName'),
                        'file':
                            filename
                    })
        except Exception as e:
            output.debug(str(e))
        return results

    def parse(self, filename):
        results = []
        filename = filename.replace('/', '\\')
        fh = BytesIO()
        try:
            # opening the files in streams instead of mounting shares allows for running the script from
            # unprivileged containers
            self.smb.getFile(self.share, filename, fh.write)
        except SessionError as e:
            output.error(e)
            return results
        except Exception as e:
            raise
        oo = fh.getvalue()
        encoding = chardet.detect(oo)["encoding"]
        if encoding != None:
            filecontent = oo.decode(encoding).rstrip()
            if 'cpassword' in filecontent:
                output.debug(filecontent)
                results = self.parse_xmlfile_content(filename, filecontent)
                fh.close()
            else:
                output.debug("No cpassword was found in %s" % filename)
        else:
            output.debug(
                "Output cannot be correctly decoded, are you sure the text is readable ?"
            )
            fh.close()
        return results

    def decrypt_password(self, pw_enc_b64):
        if len(pw_enc_b64) != 0:
            # thank you MS for publishing the key :) (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)
            key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20' \
                  b'\x9b\x09\xa4\x33\xb6\x6c\x1b'
            # thank you MS for using a fixed IV :)
            iv = b'\x00' * 16
            pad = len(pw_enc_b64) % 4
            if pad == 1:
                pw_enc_b64 = pw_enc_b64[:-1]
            elif pad == 2 or pad == 3:
                pw_enc_b64 += '=' * (4 - pad)
            pw_enc = base64.b64decode(pw_enc_b64)
            ctx = AES.new(key, AES.MODE_CBC, iv)
            pw_dec = unpad(ctx.decrypt(pw_enc), ctx.block_size)
            return pw_dec.decode('utf-16-le')
        else:
            output.debug("cpassword is empty, cannot decrypt anything")
            return ""

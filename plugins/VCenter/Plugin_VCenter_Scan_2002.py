import base64
import json
from copy import copy

import requests
import urllib3

from plugins.VCenter import PluginVCenterScanBase
from utils.consts import AllPluginTypes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginVCenterOpenedSSH(PluginVCenterScanBase):
    display = "vCenter 开启SSH"
    alias = "vc_ssh_op"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        sessionpath = "/rest/com/vmware/cis/session"
        url = "https://" + self.dc_ip + sessionpath
        headers = {"Accept": "application/json", "vmware-use-header-authn": "test", "vmware-api-session-id": "null"}
        base64res = base64.b64encode((self.ldap_conf['user'] + ":" + self.ldap_conf['password']).encode("utf-8"))
        headers["Authorization"] = "Basic " + base64res.decode("utf-8")
        response = requests.post(url, headers=headers, verify=False)
        res = json.loads(response.text)
        cookie = res['value']

        result = copy(self.result)

        url = "https://" + self.dc_ip + "/rest/appliance/access/ssh"
        headers = {"vmware-api-session-id": cookie, "Accept": "application/json",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36"}
        response = requests.get(url, headers=headers, verify=False)
        res = json.loads(response.text)
        if res["value"]:
            result['status'] = 1
        return result


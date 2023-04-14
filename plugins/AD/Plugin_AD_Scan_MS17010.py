import socket

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADMS17010(PluginADScanBase):
    """
    ms17010漏洞插件
    """

    display = "MS17-010 漏洞检测"
    alias = "ms17_010"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        code, err = self.check2(ip=self.dc_ip)
        # 0 没有漏洞 1有漏洞 -1是插件报错了
        self.result['status'] = code
        if code == 1:
            self.result['data']['instance_list'] = [{"ip address":self.dc_ip}]
        else:
            if 'Connection reset by peer' in str(err):
                self.result['status'] = 0
            else:
                self.result['error'] = str(err)

        return self.result

    def check2(self, ip, port=445, timeout=5):
        negotiateProtocolRequest = "00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200"
        sessionSetupRequest = "00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000"
        treeConnectRequest = bytes.fromhex(
            "00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
        transNamedPipeRequest = bytes.fromhex(
            "0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))

            # 1. negotiate
            s.send(bytes.fromhex(negotiateProtocolRequest))
            resp1 = s.recv(1024)
            if len(resp1) < 36 or resp1[9:13] != b'\x00\x00\x00\x00':
                return -1, 'error in smb negotoatiation'

            # 2. session setup
            s.send(bytes.fromhex(sessionSetupRequest))
            resp2 = s.recv(1024)
            if len(resp2) < 36 or resp1[9:13] != b'\x00\x00\x00\x00':
                return -1, 'error in smb session setup'

            # 3. tree connect
            userID = resp2[32:34]
            treeConnectRequest = treeConnectRequest[:32] + userID + treeConnectRequest[34:]
            s.send(treeConnectRequest)
            resp3 = s.recv(1024)
            if len(resp3) < 36 or resp3[9:13] != b'\x00\x00\x00\x00':
                return -1, 'error in smb treeconnect'

            # 4. transNamedPipeRequest
            treeID = resp3[28:30]
            transNamedPipeRequest = transNamedPipeRequest[:28] + treeID + transNamedPipeRequest[
                                                                          30:32] + userID + transNamedPipeRequest[34:]
            s.send(transNamedPipeRequest)
            resp4 = s.recv(1024)
            s.close()

            if b"\x05\x02\x00\xc0" == resp4[9:13]:
                return 1, f"{ip} 存在ms7-010远程溢出漏洞"
            s.close()

            return 0, 'target is not vulnerable'
        except Exception as e:
            return -1, str(e)
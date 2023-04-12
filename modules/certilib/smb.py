
from impacket.smbconnection import SMBConnection


def get_machine_name(domain, dc_ip):
    if dc_ip is not None:
        s = SMBConnection(dc_ip, dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s')
    else:
        s.logoff()
    return s.getServerName()

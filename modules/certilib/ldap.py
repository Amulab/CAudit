
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_OBJECT_ACE

from .smb import get_machine_name

from ldap3.protocol.microsoft import security_descriptor_control

def ldap_results(resp):
    for item in resp:
        if isinstance(item, ldapasn1.SearchResultEntry):
            yield item


def connect_ldap(
        domain,
        user,
        password="",
        lmhash="",
        nthash="",
        aesKey="",
        dc_ip=None,
        kerberos=False,
        ssl=False,
):

    base_dn = get_base_dn(domain)

    if kerberos:
        target = get_machine_name(domain, dc_ip)
    else:
        if dc_ip is not None:
            target = dc_ip
        else:
            target = domain

    protocol = "ldaps" if ssl else "ldap"
    url = "%s://%s" % (protocol, target)

    ldap_conn = ldap.LDAPConnection(
        url=url,
        baseDN=base_dn,
        dstIp=dc_ip
    )

    if kerberos:
        ldap_conn.kerberosLogin(
            user=user,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aesKey,
            kdcHost=dc_ip,
        )
    else:
        ldap_conn.login(
            user=user,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
        )

    return ldap_conn

def search_ldap(ldap_conn, search_filter, search_base=None, attributes=None, controls=None):
    try:
        return ldap_conn.search(
            searchFilter=search_filter,
            searchBase=search_base,
            attributes=attributes,
            searchControls=controls,
        )

    except ldap.LDAPSearchError as e:
        if e.getErrorString().find('sizeLimitExceeded') >= 0:
            logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
            # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
            # paged queries
            return e.getAnswers()
        else:
            raise

def get_base_dn(domain):
    domain_parts = domain.split('.')
    base_dn = ''
    for i in domain_parts:
        base_dn += 'dc=%s,' % i

    base_dn = base_dn[:-1]
    return base_dn

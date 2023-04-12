
from __future__ import unicode_literals
from multiprocessing import Pool
from impacket.uuid import string_to_bin, bin_to_string
from .cstruct import cstruct
from io import BytesIO
from future.utils import iteritems, native_str

# from adsync.bloodhound.ad.utils import ADUtils

EXTRIGHTS_GUID_MAPPING = {
    "GetChanges": string_to_bin("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
    "GetChangesAll": string_to_bin("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
    "WriteMember": string_to_bin("bf9679c0-0de6-11d0-a285-00aa003049e2"),
    "UserForceChangePassword": string_to_bin("00299570-246d-11d0-a768-00aa006e0529"),
    "AllowedToAct": string_to_bin("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"),
    "UserAccountRestrictionsSet": string_to_bin("4c164200-20c0-11d0-a768-00aa006e0529")
}

def can_write_property(ace_object, binproperty):
    '''
    Checks if the access is sufficient to write to a specific property.
    This can either be because we have the right ADS_RIGHT_DS_WRITE_PROP and the correct GUID
    is set in ObjectType, or if we have the ADS_RIGHT_DS_WRITE_PROP right and the ObjectType
    is empty, in which case we can write to any property. This is documented in
    [MS-ADTS] section 5.1.3.2: https://msdn.microsoft.com/en-us/library/cc223511.aspx
    '''
    if not ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
        return False
    if not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
        # No ObjectType present - we have generic access on all properties
        return True
    # Both are binary here
    if ace_object.acedata.data.ObjectType == binproperty:
        return True
    return False

def has_extended_right(ace_object, binrightguid):
    '''
    Checks if the access is sufficient to control the right with the given GUID.
    This can either be because we have the right ADS_RIGHT_DS_CONTROL_ACCESS and the correct GUID
    is set in ObjectType, or if we have the ADS_RIGHT_DS_CONTROL_ACCESS right and the ObjectType
    is empty, in which case we have all extended rights. This is documented in
    [MS-ADTS] section 5.1.3.2: https://msdn.microsoft.com/en-us/library/cc223511.aspx
    '''
    if not ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
        return False
    if not ace_object.acedata.has_flag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
        # No ObjectType present - we have all extended rights
        return True
    # Both are binary here
    if ace_object.acedata.data.ObjectType == binrightguid:
        return True
    return False

def ace_applies(ace_guid, object_class, objecttype_guid_map):
    '''
    Checks if an ACE applies to this object (based on object classes).
    Note that this function assumes you already verified that InheritedObjectType is set (via the flag).
    If this is not set, the ACE applies to all object types.
    '''
    if ace_guid == objecttype_guid_map[object_class]:
        return True
    # If none of these match, the ACE does not apply to this object
    return False

def build_relation(sid, relation, acetype='', inherited=False):
    if acetype != '':
        raise ValueError("BH 4.0 incompatible output called")
    return {'rightname': relation, 'sid': sid, 'inherited': inherited}

class AclEnumerator(object):
    """
    Helper class for ACL parsing.
    """
    def __init__(self, addomain, addc, collect):
        self.addomain = addomain
        self.addc = addc
        # Store collection methods specified
        self.collect = collect
        self.pool = None

    def init_pool(self):
        self.pool = Pool()

"""
The following is Security Descriptor parsing using cstruct
Thanks to Erik Schamper for helping me implement this!
"""
cdef = native_str("""
struct SECURITY_DESCRIPTOR {
    uint8   Revision;
    uint8   Sbz1;
    uint16  Control;
    uint32  OffsetOwner;
    uint32  OffsetGroup;
    uint32  OffsetSacl;
    uint32  OffsetDacl;
};

struct LDAP_SID_IDENTIFIER_AUTHORITY {
    char    Value[6];
};

struct LDAP_SID {
    uint8   Revision;
    uint8   SubAuthorityCount;
    LDAP_SID_IDENTIFIER_AUTHORITY   IdentifierAuthority;
    uint32  SubAuthority[SubAuthorityCount];
};

struct ACL {
    uint8   AclRevision;
    uint8   Sbz1;
    uint16  AclSize;
    uint16  AceCount;
    uint16  Sbz2;
    char    Data[AclSize - 8];
};

struct ACE {
    uint8   AceType;
    uint8   AceFlags;
    uint16  AceSize;
    char    Data[AceSize - 4];
};

struct ACCESS_ALLOWED_ACE {
    uint32  Mask;
    LDAP_SID Sid;
};

struct ACCESS_DENIED_ACE {
    uint32  Mask;
    LDAP_SID Sid;
};

struct ACCESS_ALLOWED_OBJECT_ACE {
    uint32  Mask;
    uint32  Flags;
    char    ObjectType[Flags & 1 * 16];
    char    InheritedObjectType[Flags & 2 * 8];
    LDAP_SID Sid;
};

struct ACCESS_DENIED_OBJECT_ACE {
    uint32  Mask;
    uint32  Flags;
    char    ObjectType[Flags & 1 * 16];
    char    InheritedObjectType[Flags & 2 * 8];
    LDAP_SID Sid;
};
""")
c_secd = cstruct()
c_secd.load(cdef, compiled=True)


class SecurityDescriptor(object):
    # Control indexes in bit field
    SR = 0  # Self-Relative
    RM = 1  # RM Control Valid
    PS = 2  # SACL Protected
    PD = 3  # DACL Protected
    SI = 4  # SACL Auto-Inherited
    DI = 5  # DACL Auto-Inherited
    SC = 6  # SACL Computed Inheritance Required
    DC = 7  # DACL Computed Inheritance Required
    SS = 8  # Server Security
    DT = 9  # DACL Trusted
    SD = 10 # SACL Defaulted
    SP = 11 # SACL Present
    DD = 12 # DACL Defaulted
    DP = 13 # DACL Present
    GD = 14 # Group Defaulted
    OD = 15 # Owner Defaulted

    def has_control(self, control):
        # Convert to bin representation and
        # look up index. Slice off 0b
        return bin(self.control)[2:][control] == '1'

    def __init__(self, fh):
        self.fh = fh
        self.descriptor = c_secd.SECURITY_DESCRIPTOR(fh)
        self.control = self.descriptor.Control
        self.owner_sid = b''
        self.group_sid = b''
        self.sacl = b''
        self.dacl = b''

        if self.descriptor.OffsetOwner != 0:
            fh.seek(self.descriptor.OffsetOwner)
            self.owner_sid = LdapSid(fh=fh)

        if self.descriptor.OffsetGroup != 0:
            fh.seek(self.descriptor.OffsetGroup)
            self.group_sid = LdapSid(fh=fh)

        if self.descriptor.OffsetSacl != 0:
            fh.seek(self.descriptor.OffsetSacl)
            self.sacl = ACL(fh)

        if self.descriptor.OffsetDacl != 0:
            fh.seek(self.descriptor.OffsetDacl)
            self.dacl = ACL(fh)


class LdapSid(object):
    def __init__(self, fh=None, in_obj=None):
        if fh:
            self.fh = fh
            self.ldap_sid = c_secd.LDAP_SID(fh)
        else:
            self.ldap_sid = in_obj

    def __repr__(self):
        return "S-{}-{}-{}".format(self.ldap_sid.Revision, bytearray(self.ldap_sid.IdentifierAuthority.Value)[5], "-".join(['{:d}'.format(v) for v in self.ldap_sid.SubAuthority]))


class ACL(object):
    def __init__(self, fh):
        self.fh = fh
        self.acl = c_secd.ACL(fh)
        self.aces = []

        buf = BytesIO(self.acl.Data)
        for i in range(self.acl.AceCount):
            self.aces.append(ACE(buf))


class ACCESS_ALLOWED_ACE(object):
    def __init__(self, fh):
        self.fh = fh
        self.data = c_secd.ACCESS_ALLOWED_ACE(fh)
        self.sid = LdapSid(in_obj=self.data.Sid)
        self.mask = ACCESS_MASK(self.data.Mask)

    def __repr__(self):
        return "<ACCESS_ALLOWED_OBJECT_ACE Sid=%s Mask=%s>" % (str(self.sid), str(self.mask))

class ACCESS_ALLOWED_OBJECT_ACE(object):
    # Flag constants
    ACE_OBJECT_TYPE_PRESENT             = 0x01
    ACE_INHERITED_OBJECT_TYPE_PRESENT   = 0x02

    def __init__(self, fh):
        self.fh = fh
        self.data = c_secd.ACCESS_ALLOWED_OBJECT_ACE(fh)
        self.sid = LdapSid(in_obj=self.data.Sid)
        self.mask = ACCESS_MASK(self.data.Mask)

    def has_flag(self, flag):
        return self.data.Flags & flag == flag

    def get_object_type(self):
        if self.has_flag(self.ACE_OBJECT_TYPE_PRESENT):
            return bin_to_string(self.data.ObjectType)
        return None

    def get_inherited_object_type(self):
        if self.has_flag(self.ACE_INHERITED_OBJECT_TYPE_PRESENT):
            return bin_to_string(self.data.InheritedObjectType)
        return None

    def __repr__(self):
        out = []
        for name, value in iteritems(vars(ACCESS_ALLOWED_OBJECT_ACE)):
            if not name.startswith('_') and type(value) is int and self.has_flag(value):
                out.append(name)
        data = (' | '.join(out),
                str(self.sid),
                str(self.mask),
                self.get_object_type(),
                self.get_inherited_object_type())
        return "<ACCESS_ALLOWED_OBJECT_ACE Flags=%s Sid=%s \n\t\tMask=%s \n\t\tObjectType=%s InheritedObjectType=%s>" % data


"""
ACCESS_MASK as described in 2.4.3
https://msdn.microsoft.com/en-us/library/cc230294.aspx
"""
class ACCESS_MASK(object):
    # Flag constants

    # These constants are only used when WRITING
    # and are then translated into their actual rights
    SET_GENERIC_READ        = 0x80000000
    SET_GENERIC_WRITE       = 0x04000000
    SET_GENERIC_EXECUTE     = 0x20000000
    SET_GENERIC_ALL         = 0x10000000
    # When reading, these constants are actually represented by
    # the following for Active Directory specific Access Masks
    # Reference: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
    GENERIC_READ            = 0x00020094
    GENERIC_WRITE           = 0x00020028
    GENERIC_EXECUTE         = 0x00020004
    GENERIC_ALL             = 0x000F01FF

    # These are actual rights (for all ACE types)
    MAXIMUM_ALLOWED         = 0x02000000
    ACCESS_SYSTEM_SECURITY  = 0x01000000
    SYNCHRONIZE             = 0x00100000
    WRITE_OWNER             = 0x00080000
    WRITE_DACL              = 0x00040000
    READ_CONTROL            = 0x00020000
    DELETE                  = 0x00010000

    # ACE type specific mask constants (for ACCESS_ALLOWED_OBJECT_ACE)
    # Note that while not documented, these also seem valid
    # for ACCESS_ALLOWED_ACE types
    ADS_RIGHT_DS_CONTROL_ACCESS         = 0x00000100
    ADS_RIGHT_DS_CREATE_CHILD           = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD           = 0x00000002
    ADS_RIGHT_DS_READ_PROP              = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP             = 0x00000020
    ADS_RIGHT_DS_SELF                   = 0x00000008

    def __init__(self, mask):
        self.mask = mask

    def has_priv(self, priv):
        return self.mask & priv == priv

    def set_priv(self, priv):
        self.mask |= priv

    def remove_priv(self, priv):
        self.mask ^= priv

    def __repr__(self):
        out = []
        for name, value in iteritems(vars(ACCESS_MASK)):
            if not name.startswith('_') and type(value) is int and self.has_priv(value):
                out.append(name)
        return "<ACCESS_MASK RawMask=%d Flags=%s>" % (self.mask, ' | '.join(out))



class ACE(object):
    CONTAINER_INHERIT_ACE       = 0x02
    FAILED_ACCESS_ACE_FLAG      = 0x80
    INHERIT_ONLY_ACE            = 0x08
    INHERITED_ACE               = 0x10
    NO_PROPAGATE_INHERIT_ACE    = 0x04
    OBJECT_INHERIT_ACE          = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG  = 0x04

    def __init__(self, fh):
        self.fh = fh
        self.ace = c_secd.ACE(fh)
        self.acedata = None
        buf = BytesIO(self.ace.Data)
        if self.ace.AceType == 0x00:
            # ACCESS_ALLOWED_ACE
            self.acedata = ACCESS_ALLOWED_ACE(buf)
        elif self.ace.AceType == 0x05:
            # ACCESS_ALLOWED_OBJECT_ACE
            self.acedata = ACCESS_ALLOWED_OBJECT_ACE(buf)
        # else:
        #     print 'Unsupported type %d' % self.ace.AceType

        if self.acedata:
            self.mask = ACCESS_MASK(self.acedata.data.Mask)

    def __repr__(self):
        out = []
        for name, value in iteritems(vars(ACE)):
            if not name.startswith('_') and type(value) is int and self.has_flag(value):
                out.append(name)
        return "<ACE Type=%s Flags=%s RawFlags=%d \n\tAce=%s>" % (self.ace.AceType, ' | '.join(out), self.ace.AceFlags, str(self.acedata))

    def has_flag(self, flag):
        return self.ace.AceFlags & flag == flag

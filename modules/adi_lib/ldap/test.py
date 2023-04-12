# coding=utf-8
from adi_lib.ldap.ldaptypes import LDAP_SID, ACL
from impacket.structure import Structure


class SR_SECURITY_DESCRIPTOR:
    def __init__(self, data = None, alignment = 0):
        if not hasattr(self, 'alignment'):
            self.alignment = alignment

        self.fields    = {}
        self.rawData   = data
        if data is not None:
            self.fromString(data)
        else:
            self.data = None
    structure = (
        ('Revision','c'),
        ('Sbz1','c'),
        ('Control','<H'),
        ('OffsetOwner','<L'),
        ('OffsetGroup','<L'),
        ('OffsetSacl','<L'),
        ('OffsetDacl','<L'),
        ('Sacl',':'),
        ('Dacl',':'),
        ('OwnerSid',':'),
        ('GroupSid',':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)
        # All these fields are optional, if the offset is 0 they are empty
        # there are also flags indicating if they are present
        # TODO: parse those if it adds value
        if self['OffsetOwner'] != 0:
            self['OwnerSid'] = LDAP_SID(data=data[self['OffsetOwner']:])
        else:
            self['OwnerSid'] = b''

        if self['OffsetGroup'] != 0:
            self['GroupSid'] = LDAP_SID(data=data[self['OffsetGroup']:])
        else:
            self['GroupSid'] = b''

        if self['OffsetSacl'] != 0:
            self['Sacl'] = ACL(data=data[self['OffsetSacl']:])
        else:
            self['Sacl'] = b''

        if self['OffsetDacl'] != 0:
            self['Dacl'] = ACL(data=data[self['OffsetDacl']:])
        else:
            self['Sacl'] = b''

    def getData(self):
        headerlen = 20
        # Reconstruct the security descriptor
        # flags are currently not set automatically
        # TODO: do this?
        datalen = 0
        if self['Sacl'] != b'':
            self['OffsetSacl'] = headerlen + datalen
            datalen += len(self['Sacl'].getData())
        else:
            self['OffsetSacl'] = 0

        if self['Dacl'] != b'':
            self['OffsetDacl'] = headerlen + datalen
            datalen += len(self['Dacl'].getData())
        else:
            self['OffsetDacl'] = 0

        if self['OwnerSid'] != b'':
            self['OffsetOwner'] = headerlen + datalen
            datalen += len(self['OwnerSid'].getData())
        else:
            self['OffsetOwner'] = 0

        if self['GroupSid'] != b'':
            self['OffsetGroup'] = headerlen + datalen
            datalen += len(self['GroupSid'].getData())
        else:
            self['OffsetGroup'] = 0
        return Structure.getData(self)
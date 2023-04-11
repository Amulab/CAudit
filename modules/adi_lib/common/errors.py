# coding: utf-8


class SecBaseException(Exception):
    def __init__(self, msg):
        self.msg = "[error] " + msg

    def __str__(self):
        return self.msg


class LDAPSearchFailException(SecBaseException):
    def __init__(self, msg=u"LDAP search fail"):
        super().__init__(self, msg)


class MsearchException(SecBaseException):
    def __init__(self, msg=u"es msearch error"):
        super().__init__(self, msg)


class NoSuchEntryType(SecBaseException):
    def __init__(self, msg=u"no such entry type"):
        super().__init__(self, msg)

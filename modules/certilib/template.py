
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

# msPKI-Certificate-Name-Flag
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000
CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000
CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000
CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000
CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008

CERTIFICATE_NAME_FLAGS_NAMES = {
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: "ENROLLEE_SUPPLIES_SUBJECT",
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    CT_FLAG_SUBJECT_ALT_REQUIRE_SPN: "SUBJECT_ALT_REQUIRE_SPN",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN: "SUBJECT_ALT_REQUIRE_UPN",
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL: "SUBJECT_ALT_REQUIRE_EMAIL",
    CT_FLAG_SUBJECT_ALT_REQUIRE_DNS: "SUBJECT_ALT_REQUIRE_DNS",
    CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN: "SUBJECT_REQUIRE_DNS_AS_CN",
    CT_FLAG_SUBJECT_REQUIRE_EMAIL: "SUBJECT_REQUIRE_EMAIL",
    CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME: "SUBJECT_REQUIRE_COMMON_NAME",
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME: "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME",
}

# msPKI-Enrollment-Flag
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_PUBLISH_TO_KRA_CONTAINER = 0x00000004
CT_FLAG_PUBLISH_TO_DS = 0x00000008
CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
CT_FLAG_AUTO_ENROLLMENT = 0x00000020
CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
CT_FLAG_USER_INTERACTION_REQUIRED = 0x00000100
CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
CT_FLAG_ADD_OCSP_NOCHECK = 0x00001000
CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
CT_FLAG_SKIP_AUTO_RENEWAL = 0x00040000

ENROLLMENT_FLAGS_NAMES = {
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS: "INCLUDE_SYMMETRIC_ALGORITHMS",
    CT_FLAG_PEND_ALL_REQUESTS: "PEND_ALL_REQUESTS",
    CT_FLAG_PUBLISH_TO_KRA_CONTAINER: "PUBLISH_TO_KRA_CONTAINER",
    CT_FLAG_PUBLISH_TO_DS: "PUBLISH_TO_DS",
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE: "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    CT_FLAG_AUTO_ENROLLMENT: "AUTO_ENROLLMENT",
    CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT: "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    CT_FLAG_USER_INTERACTION_REQUIRED: "USER_INTERACTION_REQUIRED",
    CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE: "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF: "ALLOW_ENROLL_ON_BEHALF_OF",
    CT_FLAG_ADD_OCSP_NOCHECK: "ADD_OCSP_NOCHECK",
    CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL: "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS: "NOREVOCATIONINFOINISSUEDCERTS",
    CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS: "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT: "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
    CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST: "ISSUANCE_POLICIES_FROM_REQUEST",
    CT_FLAG_SKIP_AUTO_RENEWAL: "SKIP_AUTO_RENEWAL",
}

#msPKI-Private-Key-Flag
CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
CT_FLAG_EXPORTABLE_KEY = 0x00000010
CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
CT_FLAG_REQUIRE_SAME_KEY_RENEWAL = 0x00000080
CT_FLAG_USE_LEGACY_PROVIDER = 0x00000100
CT_FLAG_ATTEST_REQUIRED = 0x000002000
CT_FLAG_ATTEST_PREFERRED = 0x000001000
CT_FLAG_HELLO_LOGON_KEY = 0x00200000

# https://www.pkisolutions.com/object-identifiers-oid-in-pki/

EKU_CLIENT_AUTHENTICATION_OID = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT_CLIENT_AUTHENTICATION_OID = "1.3.6.1.5.2.3.4"
EKU_SMART_CARD_LOGON_OID = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE_OID = "2.5.29.37.0"
EKU_CERTIFICATE_REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"

EKUS_NAMES = {
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signer",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signer",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    EKU_SMART_CARD_LOGON_OID: "Smart Card Logon",
    EKU_CERTIFICATE_REQUEST_AGENT_OID: "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Driver",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.4.1.311.64.1.1": "Domain Name System (DNS) Server Trust",
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generator",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publisher",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    EKU_PKINIT_CLIENT_AUTHENTICATION_OID: "PKINIT Client Authentication",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security user",
    EKU_CLIENT_AUTHENTICATION_OID: "Client Authentication",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    EKU_ANY_PURPOSE_OID: "Any Purpose",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "2.23.133.8.2": "Platform Certificate",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
}


class Template:

    def __init__(self):
        self.name = ""

        self.certificate_name_flags = 0
        self.enrollment_flags = 0
        self.private_key_flags = 0
        self.ra_signature = None
        self.schema_version = 0
        self.ekus = []
        self.certificate_application_policies = []
        self.ra_application_policies = []
        self.enroll_services = []

        self.security_descriptor = SR_SECURITY_DESCRIPTOR()

    def allows_authentication(self):
        return self.can_be_used_for_any_purpose()\
           or EKU_CLIENT_AUTHENTICATION_OID in self.ekus\
           or EKU_SMART_CARD_LOGON_OID in self.ekus\
           or EKU_PKINIT_CLIENT_AUTHENTICATION_OID in self.ekus

    def can_be_used_for_any_purpose(self):
        return len(self.ekus) == 0\
           or EKU_ANY_PURPOSE_OID in self.ekus

    def requires_manager_approval(self):
        return self.enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS > 0

    def requires_authorized_signatures(self):
        return self.ra_signature != None and self.ra_signature > 0

    def allows_to_specify_san(self):
        return self.certificate_name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT > 0

    def allows_to_request_agent_certificate(self):
        return EKU_CERTIFICATE_REQUEST_AGENT_OID in self.ekus

    def allows_to_use_agent_certificate(self):
        return self.schema_version == 1 \
            or (
                self.schema_version > 1 \
                and self.ra_signature == 1 \
                and EKU_CERTIFICATE_REQUEST_AGENT_OID in self.ra_application_policies
            )

    # Misconfigured Certificate Templates - ESC1
    def is_vuln_to_san_impersonation(self):
        return self.allows_authentication()\
            and not self.requires_manager_approval()\
            and not self.requires_authorized_signatures()\
            and self.allows_to_specify_san()

    # Misconfigured Certificate Templates - ESC2
    def is_vuln_to_any_purpose(self):
        return not self.requires_manager_approval()\
            and not self.requires_authorized_signatures()\
            and self.can_be_used_for_any_purpose()

    # Misconfigured Enrollment Agent Templates - ESC3 - Condition 1
    def is_vuln_to_request_agent_certificate(self):
        return not self.requires_manager_approval()\
            and not self.requires_authorized_signatures()\
            and self.allows_to_request_agent_certificate()

    # Misconfigured Enrollment Agent Templates - ESC3 - Condition 2
    def is_vuln_to_request_with_agent_certificate(self):
        return not self.requires_manager_approval()\
            and self.allows_authentication()\
            and self.allows_to_use_agent_certificate()

    def is_vulnerable(self):
        return self.is_vuln_to_request_with_agent_certificate()\
            or self.is_vuln_to_request_agent_certificate()\
            or self.is_vuln_to_any_purpose()\
            or self.is_vuln_to_san_impersonation()


    def is_enabled(self):
        return len(self.enroll_services) > 0

    @property
    def owner_sid(self):
        return self.security_descriptor['OwnerSid']

    @property
    def dacl(self):
        return self.security_descriptor["Dacl"]

    @property
    def enrollment_flags_names(self):
        return [
            ENROLLMENT_FLAGS_NAMES[flag] for flag in ENROLLMENT_FLAGS_NAMES
            if self.enrollment_flags & flag == flag
        ]

    @property
    def private_key_flags_names(self):
        flags = []

        if self.private_key_flags & CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL:
            flags.append("CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL")

        if self.private_key_flags & CT_FLAG_EXPORTABLE_KEY:
            flags.append("CT_FLAG_EXPORTABLE_KEY")

        if self.private_key_flags & CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED:
            flags.append("CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED")

        if self.private_key_flags & CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM:
            flags.append("CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM")

        if self.private_key_flags & CT_FLAG_REQUIRE_SAME_KEY_RENEWAL:
            flags.append("CT_FLAG_REQUIRE_SAME_KEY_RENEWAL")

        if self.private_key_flags & CT_FLAG_USE_LEGACY_PROVIDER:
            flags.append("CT_FLAG_USE_LEGACY_PROVIDER")

        if self.private_key_flags & CT_FLAG_ATTEST_REQUIRED:
            flags.append("CT_FLAG_ATTEST_REQUIRED")

        if self.private_key_flags & CT_FLAG_ATTEST_PREFERRED:
            flags.append("CT_FLAG_ATTEST_PREFERRED")

        if self.private_key_flags & CT_FLAG_HELLO_LOGON_KEY:
            flags.append("CT_FLAG_HELLO_LOGON_KEY")

        return flags

    @property
    def certificate_name_flags_names(self):
        return [
            CERTIFICATE_NAME_FLAGS_NAMES[flag] for flag in CERTIFICATE_NAME_FLAGS_NAMES
            if self.certificate_name_flags & flag == flag
        ]

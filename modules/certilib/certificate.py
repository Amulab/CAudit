from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AttributeOID, NameOID, ObjectIdentifier
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7, pkcs12, NoEncryption, BestAvailableEncryption
from cryptography.x509.oid import ExtensionOID

import pyasn1
from pyasn1.type.char import UTF8String
from pyasn1.codec import der

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

def csr_pem_to_der(csr):
    csr = "".join(csr.split("\n")[1:-2])
    return base64.b64decode(csr)

def load_pfx(data, password):
    if password:
        password = password.encode()

    (key, cert, _) = pkcs12.load_key_and_certificates(data, password)

    return (key, cert)

def generate_pkcs7(data, key, cert):
    return pkcs7.PKCS7SignatureBuilder()\
                .set_data(data)\
                .add_signer(cert, key, hashes.SHA1())

def pkcs7_to_der(p7):
    return p7.sign(Encoding.DER, options=[pkcs7.PKCS7Options.Binary])

def pkcs7_to_pem(p7):
    return p7.sign(Encoding.PEM, options=[pkcs7.PKCS7Options.Binary])

def load_x509_certificate(cert_bytes, cert_format="PEM"):
    if cert_format.upper() == "PEM":
        return x509.load_pem_x509_certificate(cert_bytes)
    else:
        return x509.load_der_x509_certificate(cert_bytes)

def new_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def is_alt_name_in_cert(cert, alt_name):
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    for name in ext.value.get_values_for_type(x509.OtherName):
        if name.type_id == PRINCIPAL_NAME:
            alt_name_bytes = pyasn1.codec.der.encoder.encode(
                pyasn1.type.char.UTF8String(alt_name)
            )
            if name.value == alt_name_bytes:
                return True

    return False

def cert_get_extended_key_usage(cert):
    oids = []
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    for oid in ext.value:
        oids.append(oid.dotted_string)

    return oids

def generate_csr(key, cn, alt_name=None):
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
    )

    if alt_name:
        alt_name_bytes = pyasn1.codec.der.encoder.encode(
            pyasn1.type.char.UTF8String(alt_name)
        )

        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(PRINCIPAL_NAME, alt_name_bytes),
            ]), critical=False,
        )

    return builder.sign(key, hashes.SHA256())

def csr_to_der(csr):
    return csr.public_bytes(Encoding.DER)

def csr_to_pem(csr):
    return csr.public_bytes(Encoding.PEM)

def generate_pfx(key, cert, password):
    return pkcs12.serialize_key_and_certificates(
        name=b"",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(password)
    )


def cert_to_pem(cert):
    return cert.public_bytes(Encoding.PEM)

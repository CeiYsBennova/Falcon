from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.
from cryptography.hazmat.primitives.serialization import (Encoding,PrivateFormat,NoEncryption)
import falcon
sk = falcon.SecretKey(512)
pk = falcon.PublicKey(sk)
builder = x509.CertificateSigningRequestBuilder()
builder = builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"HCM City"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"HCM City"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UIT"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Group 5"),
]))
builder = builder.add_extension(
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True,
)
requests = builder.sign(
    private_key=sk,
    algorithm=hashes.SHA256(),
    backend=default_backend()
)
with open("cert.csr", "wb") as f:
    f.write(requests.public_bytes(Encoding.PEM))
with open("cert.key", "wb") as f:
    f.write(pk.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    ))







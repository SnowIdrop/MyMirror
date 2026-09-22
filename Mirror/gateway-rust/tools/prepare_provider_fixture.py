"""Build an offline TLS oracle payload with synthetic CA material. Author: MingTea.
The generated payload refuses to run unless the guest has only the loopback interface.
"""
from pathlib import Path
import datetime,ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa

root=Path(__file__).resolve().parents[1]
build=root/'.build';build.mkdir(exist_ok=True)
paths=[build/'provider-cert.pem',build/'provider-key.pem',build/'provider-ca.pem']
if not all(path.exists() for path in paths):
    ca=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Isolated fixture root')])
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'isolated-provider.invalid')])
    def builder(name,issuer,key,serial):
        return x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key()).serial_number(serial).not_valid_before(datetime.datetime(2020,1,1)).not_valid_after(datetime.datetime(2040,1,1))
    ca_cert=builder(issuer,issuer,ca,1).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(ca,hashes.SHA256())
    leaf=builder(subject,issuer,key,2).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('93.184.216.34')),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False).sign(ca,hashes.SHA256())
    ca_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    cert=leaf.public_bytes(serialization.Encoding.PEM).decode()+ca_pem
    private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    for path,value in zip(paths,[cert,private,ca_pem],strict=True):path.write_text(value,encoding='ascii')
source=(root/'tools/observe_provider_tls_v3.py').read_text(encoding='utf-8')
prefix='CERT_PEM='+repr(paths[0].read_text())+'\nKEY_PEM='+repr(paths[1].read_text())+'\nROOT_PEM='+repr(paths[2].read_text())+'\n'
output=build/'observe_provider_tls_v3.py'
output.write_text(prefix+source,encoding='utf-8')
print(output)

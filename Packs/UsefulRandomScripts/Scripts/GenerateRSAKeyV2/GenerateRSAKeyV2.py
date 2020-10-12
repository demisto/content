from datetime import datetime, timedelta

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from cryptography import x509
from cryptography.hazmat.backends import \
    default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import \
    serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def private_key_encryption(passphrase, key):
    """
    utiliy function - for encrypting the private key with the given passphrase
    """
    if passphrase:
        return key.private_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=crypto_serialization.BestAvailableEncryption(bytes(passphrase, 'utf-8'))).decode("utf-8")
    else:
        return key.private_bytes(crypto_serialization.Encoding.PEM, crypto_serialization.PrivateFormat.TraditionalOpenSSL, crypto_serialization.NoEncryption()).decode("utf-8")


def private_key(passphrase, key):
    """
    generate a private key
    """
    return private_key_encryption(passphrase, key)


def ssh_key(passphrase, key):
    """
    generate an ssh key pair
    """
    private_key = private_key_encryption(passphrase, key)
    public_key = key.public_key().public_bytes(crypto_serialization.Encoding.OpenSSH,
                                               crypto_serialization.PublicFormat.OpenSSH).decode("utf-8")

    return private_key, public_key


def self_signed_cert(passphrase, hostname, key):
    """
    generate a self signed certificate for a given hostname
    """

    # add the hostname to the name attribute and alt names
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    alt_names = [x509.DNSName(hostname)]
    san = x509.SubjectAlternativeName(alt_names)

    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), crypto_default_backend())
    )

    private_key = private_key_encryption(passphrase, key)
    public_cert = cert.public_bytes(encoding=crypto_serialization.Encoding.PEM)

    return private_key, public_cert


def main(args):
    """
    main function
    """

    # get the usage for the automation
    usage = args.get('usage', 'privatekey')

    # generate private key, as we need this for all of the functions:
    key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)

    # grab the passphrase for encrypting the private key, if provided
    passphrase = args.get('passphrase', '')

    # generate keys
    if usage == 'privatekey':
        demisto.results(private_key('', key))

    elif usage == 'ssh':
        private_key, public_key = ssh_key(passphrase, key)
        demisto.results(private_key)
        demisto.results(public_key)

    elif usage == 'selfsignedcert':
        hostname = args.get('hostname', 'xsoar')
        private_key, public_cert = self_signed_cert(passphrase, hostname, key)
        demisto.results(private_key)
        demisto.results(public_cert)

    else:
        demisto.results('Choose an option sparky')


if __name__ in ('builtins', '__builtin__'):
    main(demisto.args())

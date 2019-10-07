import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

from M2Crypto import BIO, SMIME, X509
from typing import Dict


''' HELPER FUNCTIONS '''


def makebuf(text):
    return BIO.MemoryBuffer(text)


class Client:
    def __init__(self, private_key, public_key):
        self.smime = SMIME.SMIME()

        f = open('private.pem', 'wb')
        f.write(bytes(private_key, 'utf-8'))
        f.flush()
        f.close()
        f = open('cert.pem', 'wb')
        f.write(bytes(public_key, 'utf-8'))
        f.flush()
        f.close()
        self.private_key_file = os.path.abspath('private.pem')
        self.public_key_file = os.path.abspath('cert.pem')


''' COMMANDS '''


def sign_email(client: Client, args: Dict):
    """
    send a S/MIME-signed message via SMTP.
    """
    message_body = args.get('message_body', '')

    # Make a MemoryBuffer of the message.
    buf = makebuf(message_body.encode())
    # Instantiate an SMIME object; set it up; sign the buffer.
    client.smime.load_key(client.private_key_file, client.public_key_file)
    p7 = client.smime.sign(buf, SMIME.PKCS7_DETACHED)

    # Recreate buf.
    buf = makebuf(message_body.encode())

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()
    client.smime.write(out, p7, buf)

    signed = out.read().decode('utf-8')
    signed_message = signed.split('\n\n')
    headers = signed_message[0].replace(': ', '=').replace('\n', ',')
    body = signed_message[2:]
    context = {
        'SMIME.Signed': {
            'Message': body,
            'Headers': headers
        }
    }

    return signed, context


def encrypt_email_body(client: Client, args: Dict):
    """ generate an S/MIME-encrypted message

    Args:
        client: Client
        args: Dict

    """
    message_body = args.get('message', '').encode('utf-8')

    # Make a MemoryBuffer of the message.
    buf = makebuf(message_body)

    # Load target cert to encrypt to.
    x509 = X509.load_cert(client.public_key_file)
    sk = X509.X509_Stack()
    sk.push(x509)
    client.smime.set_x509_stack(sk)

    # Set cipher: 3-key triple-DES in CBC mode.
    client.smime.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Encrypt the buffer.
    p7 = client.smime.encrypt(buf)

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()

    client.smime.write(out, p7)
    encrypted_message = out.read().decode('utf-8')
    message = encrypted_message.split('\n\n')
    headers = message[0]
    new_headers = headers.replace(': ', '=').replace('\n', ',')

    entry_context = {
        'SMIME.Encrypted': {
            'Message': encrypted_message,
            'Headers': new_headers
        }
    }
    return encrypted_message, entry_context


def verify(client: Client, args: Dict):
    """ Verify the signature

    Args:
        client: Client
        args: Dict

    """
    signed_message = demisto.getFilePath(args.get('signed_message'))

    # Load the signer's cert.
    x509 = X509.load_cert(client.public_key_file)
    sk = X509.X509_Stack()
    sk.push(x509)
    client.smime.set_x509_stack(sk)

    # Load the signer's CA cert. In this case, because the signer's
    # cert is self-signed, it is the signer's cert itself.
    st = X509.X509_Store()
    st.load_info(client.public_key_file)
    client.smime.set_x509_store(st)

    # Load the data, verify it.
    p7, data = SMIME.smime_load_pkcs7(signed_message['path'])
    v = client.smime.verify(p7, data, flags=SMIME.PKCS7_NOVERIFY)

    human_readable = f'The signature verified\n\n{v}\n{data}'
    return human_readable, {}


def decrypt_email_body(client: Client, args: Dict, file_path=None):
    """ Decrypt the message

    Args:
        client: Client
        args: Dict
        file_path: relevant for the test module
    """
    if file_path:
        encrypt_message = file_path
    else:
        encrypt_message = demisto.getFilePath(args.get('encrypt_message'))
    # Load private key and cert.
    client.smime.load_key(client.private_key_file, client.public_key_file)

    # Load the encrypted data.
    p7, data = SMIME.smime_load_pkcs7(encrypt_message['path'])

    # Decrypt p7.
    out = client.smime.decrypt(p7).decode('utf-8')
    entry_context = {
        'SMIME.Decrypted': {
            'Message': out
        }
    }
    human_readable = f'The decrypted message is: \n{out}'

    return human_readable, entry_context


def test_module(client, *_):
    message_body = 'testing'
    encrypt_message = encrypt_email_body(client, {'message': message_body})
    with open('test.p7', 'wb') as f:
        f.write(bytes(encrypt_message[0], 'utf-8'))

    decrypt_message = decrypt_email_body(client, {}, file_path={'path': os.path.abspath('test.p7')})
    if decrypt_message:
        demisto.results('ok')
    else:
        demisto.results('There might be a problem with one of your keys')


def main():

    public_key: str = demisto.params().get('public_key', '')
    private_key: str = demisto.params().get('private_key', '')

    client = Client(private_key, public_key)
    LOG(f'Command being called is demisto.command()')
    commands = {
        'test-module': test_module,
        'smime-sign-email': sign_email,
        'smime-encrypt-email-body': encrypt_email_body,
        'smime-verify-sign': verify,
        'smime-decrypt-email-body': decrypt_email_body
    }
    try:
        command = demisto.command()
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))  # type: ignore

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

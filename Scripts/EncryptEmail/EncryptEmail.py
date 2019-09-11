import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from M2Crypto import BIO, Rand, SMIME, X509


def makebuf(text):
    return BIO.MemoryBuffer(text)


def main():

    encrypt_key = demisto.getFilePath(demisto.args().get('key'))
    message_body = demisto.args().get('message').encode('utf-8')

    # Make a MemoryBuffer of the message.
    buf = makebuf(message_body)

    # Instantiate an SMIME object.
    s = SMIME.SMIME()

    # Load target cert to encrypt to.
    x509 = X509.load_cert(os.path.abspath(encrypt_key['path']))
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)

    # Set cipher: 3-key triple-DES in CBC mode.
    s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

    # Encrypt the buffer.
    p7 = s.encrypt(buf)

    # Output p7 in mail-friendly format.
    out = BIO.MemoryBuffer()

    s.write(out, p7)
    encrypted_message = out.read().decode('utf-8')
    message = encrypted_message.split('\n\n')
    content = message[1]

    entry_context = {
        'Email': {
            'Message': encrypted_message,
            'Headers': 'MIME-Version=1.0,Content-Disposition=attachment; filename="smime.p7m",'
                       'Content-Type=application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m",'
                       'Content-Transfer-Encoding=base64'
        }
    }
    return_outputs(encrypted_message, entry_context)


if __name__ in ('__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

from M2Crypto import BIO, SMIME, X509
from tempfile import NamedTemporaryFile

from charset_normalizer import from_bytes
import quopri
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import pytz


''' HELPER FUNCTIONS '''


def makebuf(text):
    return BIO.MemoryBuffer(text)


def create_pem_string(base64_cert) -> str:
    """This function takes the base64 encoded certificate received via
    ad-search in the "UserCertificate" attribute and converts it to a PEM

    Args:
        base64_cert (_type_): _description_

    Returns:
        str: PEM string for the certificate
    """
    pemstring = "-----BEGIN CERTIFICATE-----\n"
    pemstring += "\n".join(
        [base64_cert[i: i + 64] for i in range(0, len(base64_cert), 64)]
    )
    pemstring += "\n-----END CERTIFICATE-----\n"
    return pemstring


class Client:
    def __init__(self, private_key, public_key):
        self.smime = SMIME.SMIME()

        public_key_file = NamedTemporaryFile(delete=False)
        public_key_file.write(bytes(public_key, 'utf-8'))
        self.public_key_file = public_key_file.name
        public_key_file.close()

        private_key_file = NamedTemporaryFile(delete=False)
        private_key_file.write(bytes(private_key, 'utf-8'))
        self.private_key_file = private_key_file.name
        private_key_file.close()


''' COMMANDS '''


def sign_email(client: Client, args: dict):
    """
    send a S/MIME-signed message via SMTP.
    """
    use_transport_encoding: bool = argToBoolean(args.get('use_transport_encoding', 'false'))
    if use_transport_encoding:
        message_body = (
            b'Content-Type: text/plain;  charset="utf-8"\nContent-Transfer-Encoding: quoted-printable\n\n'
            + quopri.encodestring(args.get('message_body', '').encode("utf-8"))
        )
        buf = makebuf(message_body)

        client.smime.load_key(client.private_key_file, client.public_key_file)
        p7 = client.smime.sign(buf, SMIME.PKCS7_DETACHED)

        buf = makebuf(message_body)
        out = BIO.MemoryBuffer()

        client.smime.write(out, p7, buf)
    else:
        message_body = args.get('message_body', '')
        buf = makebuf(message_body.encode())  # type: ignore

        client.smime.load_key(client.private_key_file, client.public_key_file)
        p7 = client.smime.sign(buf, SMIME.PKCS7_DETACHED)

        buf = makebuf(message_body.encode())  # type: ignore
        out = BIO.MemoryBuffer()

        client.smime.write(out, p7, buf, SMIME.PKCS7_TEXT)
    signed = out.read().decode('utf-8')
    signed_message = signed.split('\n\n')
    headers = signed_message[0].replace(': ', '=').replace('\n', ',')
    context = {
        'SMIME.Signed': {
            'Message': signed,
            'Headers': headers
        }
    }

    return signed, context


def encrypt_email_body(client: Client, args: dict):
    """ generate an S/MIME-encrypted message

    Args:
        client: Client
        args: Dict

    """
    message_body = args.get('message', '').encode('utf-8')
    buf = makebuf(message_body)

    x509 = X509.load_cert(client.public_key_file)
    sk = X509.X509_Stack()
    sk.push(x509)
    client.smime.set_x509_stack(sk)
    client.smime.set_cipher(SMIME.Cipher('des_ede3_cbc'))
    p7 = client.smime.encrypt(buf)
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


def verify(client: Client, args: dict):
    """ Verify the signature

    Args:
        client: Client
        args: Dict

    """
    signed_message = demisto.getFilePath(args.get('signed_message'))
    cert = args.get('public_key', 'instancePublicKey')

    sk = X509.X509_Stack()
    st = X509.X509_Store()
    if cert == 'instancePublicKey':
        sk.push(X509.load_cert(client.public_key_file))
        st.load_info(client.public_key_file)
    elif cert:
        public_key_file = NamedTemporaryFile(delete=False)
        public_key_file.write(bytes(cert, "utf-8"))
        public_key_file.close()
        sk.push(X509.load_cert(public_key_file.name))
        st.load_info(public_key_file.name)
        os.unlink(public_key_file.name)

    client.smime.set_x509_stack(sk)
    client.smime.set_x509_store(st)
    try:
        p7, data = SMIME.smime_load_pkcs7(signed_message['path'])
        v = client.smime.verify(p7, data, flags=SMIME.PKCS7_NOVERIFY)
        human_readable = f'The signature verified\n\n{v}'

    except SMIME.SMIME_Error as e:

        if str(e) == 'no content type':  # If no content type; see if we can process as DER format
            with open(signed_message['path'], "rb") as message_file:
                p7data = message_file.read()
            p7bio = BIO.MemoryBuffer(p7data)
            p7 = SMIME.load_pkcs7_bio_der(p7bio)
            v = client.smime.verify(p7, flags=SMIME.PKCS7_NOVERIFY)
            return_results(fileResult(f'unwrapped-{signed_message["name"]}', v))
            human_readable = 'The signature verified\n\n'
        else:
            raise e

    return CommandResults(
        readable_output=human_readable,
    )


def decode_str(decrypted_text: bytes, encoding: str) -> tuple[str, str]:
    """
    Detect encoding type using chardet, if the confidence of the detected encoding is lower than 0.9 we will add a
    message indicates it. If encoding is given, will use it.
    """
    msg = ''
    out = ''
    if not encoding:
        with warnings.catch_warnings(record=True) as e:
            charset_match = from_bytes(decrypted_text)
            if len(charset_match):
                out = str(charset_match[0])
                demisto.debug(f"Decode decrypted text using {charset_match[0].encoding} encoding")
            if e:
                msg = f'Note: encoding detection ended with warning: {e[0].message} Characters may be missing.' \
                      ' You can try running this command again and pass the encoding code as argument.\n'
    else:
        out = decrypted_text.decode(encoding)

    return out, msg


def decrypt_email_body(client: Client, args: dict, file_path=None):
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
        demisto.debug(f'\n\nFile Name:{encrypt_message["name"]}; Type:{type(encrypt_message["name"])}\n\n')

    encoding = args.get('encoding', '')
    msg = ''
    client.smime.load_key(client.private_key_file, client.public_key_file)
    try:
        p7, data = SMIME.smime_load_pkcs7(encrypt_message['path'])
        decrypted_text = client.smime.decrypt(p7)
        out, msg = decode_str(decrypted_text, encoding)

    except SMIME.SMIME_Error as e:

        if str(e) == 'no content type':  # If no content type; see if we can process as DER format
            with open(encrypt_message['path'], "rb") as message_file:
                p7data = message_file.read()
            p7bio = BIO.MemoryBuffer(p7data)
            p7 = SMIME.load_pkcs7_bio_der(p7bio)
            decrypted_text = client.smime.decrypt(p7, flags=SMIME.PKCS7_NOVERIFY)
            out, msg = decode_str(decrypted_text, encoding)

        else:
            raise

    return CommandResults(
        readable_output=f'{msg}The decrypted message is: \n{out}',
        outputs_prefix='SMIME.Decrypted',
        outputs_key_field='Message',
        outputs=out,
    )


def sign_and_encrypt(client: Client, args: dict):

    message = args.get('message', '')
    sign = argToBoolean(args.get('signed', 'true'))
    encrypt = argToBoolean(args.get('encrypted', 'true'))
    sender = args.get('sender', '')
    subject = args.get('subject', '')
    # use_transport_encoding = argToBoolean(args.get('use_transport_encoding', 'false'))
    recipients = args.get('recipients', {})  # type: dict[str,str]
    cc = args.get('cc', {})  # type: dict[str,str]
    bcc = args.get('bcc', {})  # type: dict[str,str]
    attachment_ids = argToList(args.get('attachment_entry_id', ''))  # type: list[str]

    if type(recipients) != dict:
        raise DemistoException("Failed to parse recipients. (format `{'some@email':'pub_key', 'other@email':'other_key'}`)")
    if type(cc) != dict:
        raise DemistoException("Failed to parse cc , (format `{'some@email':'pub_key', 'other@email':'other_key'}`)")
    if type(bcc) != dict:
        raise DemistoException("Failed to parse bcc, (format `{'some@email':'pub_key', 'other@email':'other_key'}`)")

    # Prepare message
    msg = MIMEMultipart()
    # TODO: what to do for transport encoding?
    # cs = charset.Charset('utf-8')
    # if use_transport_encoding:
    #    cs.header_encoding = charset.QP
    #    cs.body_encoding = charset.QP
    #    msg.set_charset(cs)

    is_html = bool(re.search(r'<.*?>', message))
    if is_html:
        msg.attach(MIMEText(message, 'html'))
    else:
        msg.attach(MIMEText(message, 'plain'))

    # Add attachments to message
    for attach_id in attachment_ids:
        try:
            fp = demisto.getFilePath(attach_id)
            file_path = fp['path']
            attach_name = fp['name']
        except Exception as ex:
            raise Exception(f'Error while opening attachment id {attach_id}: {str(ex)}')
        if isinstance(attach_name, list):
            attach_name = attach_name[0]
        part = MIMEBase('application', 'octet-stream')
        with open(file_path, 'rb') as f:
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="%s"' % attach_name)
            msg.attach(part)

    msg_str = msg.as_string()
    demisto.debug(f'\n\nMessage:\n\n {msg_str} \n\nMessage end\n')

    msg_bio = BIO.MemoryBuffer(msg_str.encode('utf-8'))

    if sign:
        client.smime.load_key(client.private_key_file, client.public_key_file)
        p7 = client.smime.sign(msg_bio, algo='sha256')
        msg_bio = BIO.MemoryBuffer(msg_str.encode('utf-8'))  # Recreate since sign() has consumed it.

    if encrypt:
        pub_certs = [cert for dest in [recipients, cc, bcc] for cert in dest.values()]  # all keys are used the same
        sk = X509.X509_Stack()
        if not pub_certs:
            demisto.debug("No certs given, using instance cert")
            sk.push(X509.load_cert(client.public_key_file))
        for cert in pub_certs:
            if cert == 'instancePublicKey':
                sk.push(X509.load_cert(client.public_key_file))
                continue
            if ("-----BEGIN CERTIFICATE-----") not in cert:
                cert = create_pem_string(cert)

            with NamedTemporaryFile(delete=False) as public_key_file:
                public_key_file.write(bytes(cert, "utf-8"))
                public_key_file.close()
                sk.push(X509.load_cert(public_key_file.name))
                os.unlink(public_key_file.name)

        client.smime.set_x509_stack(sk)
        client.smime.set_cipher(SMIME.Cipher('aes_256_cbc'))
        tmp_bio = BIO.MemoryBuffer()
        if sign:
            client.smime.write(tmp_bio, p7)
        else:
            tmp_bio.write(msg_str)
        p7 = client.smime.encrypt(tmp_bio)

    out = BIO.MemoryBuffer()
    # Add email plain-text header
    current_time = datetime.now(pytz.timezone('UTC')).strftime("%a, %d %b %Y %H:%M:%S %z")
    out.write(f'Date: {current_time}\r\n')
    out.write(f'From: {sender}\r\n')
    out.write(f'To: {", ".join(recipients.keys())}\r\n')
    out.write(f'CC: {", ".join(cc.keys())}\r\n')
    out.write(f'BCC: {", ".join(bcc.keys())}\r\n')
    out.write(f'Subject: {subject}\r\n')

    if encrypt or sign:
        client.smime.write(out, p7)
    else:
        out.write(msg_str)

    msg = out.read().decode('utf-8')

    file_results = fileResult(filename=f'SMIME-{demisto.uniqueFile()[:8]}.p7', data=msg, file_type=EntryType.FILE)
    command_results = CommandResults(
        readable_output=msg,
        outputs_prefix='SMIME.SignedAndEncrypted',
        outputs={'Message': msg,
                 'Recipient Ids': [id for dest in [recipients, cc, bcc] for id in dest],
                 'File Name': file_results.get('File'),
                 }
    )
    # TODO: Get final output design from TPM
    return [command_results, file_results]


def test_module(client, *_):
    message_body = 'testing'
    try:
        encrypt_message = encrypt_email_body(client, {'message': message_body})
        if encrypt_message:
            test_file = NamedTemporaryFile(delete=False)
            test_file.write(bytes(encrypt_message[0], 'utf-8'))
            test_file.close()
            decrypt_message = decrypt_email_body(client, {}, file_path={'path': test_file.name})
            if decrypt_message:
                demisto.results('ok')
    except Exception:
        return_error('Verify that you provided valid keys.')
    finally:
        os.unlink(test_file.name)


def main():  # pragma: no cover

    public_key: str = demisto.params().get('public_key', '')
    private_key: str = demisto.params().get('private_key', '')

    client = Client(private_key, public_key)
    LOG(f'Command being called is {demisto.command()}')
    commands = {
        'test-module': test_module,
        'smime-sign-email': sign_email,
        'smime-encrypt-email-body': encrypt_email_body,
        'smime-verify-sign': verify,
        'smime-decrypt-email-body': decrypt_email_body,
        'smime-sign-and-encrypt': sign_and_encrypt
    }
    try:
        command = demisto.command()
        if command in commands:
            return_results(commands[command](client, demisto.args()))  # type: ignore

    except Exception as e:
        return_error(str(e))

    finally:
        if client.private_key_file:
            os.unlink(client.private_key_file)
        if client.public_key_file:
            os.unlink(client.public_key_file)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

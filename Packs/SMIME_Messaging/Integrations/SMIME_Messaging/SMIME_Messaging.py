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
from email import encoders, message_from_string
from email.message import Message
import pytz
import mimetypes
import uuid


''' HELPER FUNCTIONS '''


def makebuf(text):
    return BIO.MemoryBuffer(text)


def create_pem_string(base64_cert: str) -> str:
    """Converts a base64 encoded certificate string to a PEM format.

    Args:
        base64_cert (str): certificate string with no BEGIN or END markers

    Returns:
        pemstring (str): PEM-formatted certificate string
    """
    pem_header = '-----BEGIN CERTIFICATE-----\n'
    pem_footer = '-----END CERTIFICATE-----\n'

    # Split the base64 certificate into lines of 64 characters each
    pem_body = '\n'.join(base64_cert[i:i + 64] for i in range(0, len(base64_cert), 64))

    return f"{pem_header}{pem_body}\n{pem_footer}"


def handle_attachment(attachment_part: Message) -> None:
    """
    Extracts and saves the attachment file to the context.
    p7 files will be ignored.

    Args:
        attachment_part (Message): attachment message part

    """

    file_name = attachment_part.get_filename()
    if not file_name:
        demisto.debug('Got nameless attachment, generating file name')
        mime_type = attachment_part.get_content_type()
        extension = mimetypes.guess_extension(mime_type) or '.bin'
        file_name = f'attachment_{uuid.uuid4()}{extension}'

    # ignore p7 file types and subtypes (e.g. p7m)
    if (file_name.lower().endswith('.p7')
            or file_name.lower().endswith('.p7', 0, -1)):
        demisto.debug(f'Skipping p7 file: {file_name}')
        return
    # create the attachment
    file_result = fileResult(file_name, attachment_part.get_payload(decode=True))

    # check for error
    if file_result['Type'] == entryTypes['error']:
        raise Exception(file_result['Contents'])

    # return the attachment to war room
    return_results(file_result)


def handle_image(image_part: Message, payload: Any) -> tuple[str, str, str] | None:
    """
    Handles the payload for an image, extracting the cid and image data

    Args:
        image_part (Message): Image message part
        payload (Any): Message part payload

    Returns:
        (cid, content_type, image_data): Complete image data to allow embedding into the message, None if no cid is found

    """
    content_type = image_part.get_content_type()
    image_data_base64 = base64.b64encode(payload).decode('utf-8')

    cid = image_part.get('Content-Id')
    if not cid:
        return None

    # Remove angle brackets if present around CID
    cid = re.sub(r'<(.*?)>', r'\1', cid)

    return cid, content_type, image_data_base64


def extract_email_body(text_part: Message, payload: Any) -> tuple[str, str]:
    """
    Handles the payload for the email body part

    Args:
        text_part (Message): Text message part
        payload (Any): Message part payload

    Returns:
        (email_body, body_type): Strings containing the email body and the body type (text or html)

    """
    email_body = payload.decode(text_part.get_content_charset('utf-8'), errors='ignore')
    if text_part.get_content_type() == 'text/html':
        body_type = 'html'
        # Clean up whitespaces between </head> and <body> tags
        email_body = re.sub(r'</head>\s*<body>', '</head><body>', email_body)
    else:
        body_type = 'text'

    return email_body, body_type


def patch_cid_with_urls(email_body: str, images: list[tuple[str, str, str]]) -> str:
    """
    Replaces HTML image references with their data URLs

    Args:
        email_body (str): The html email message to patch
        images (list): List of images found in the message, each containing (cid, type, data)

    Returns:
        patched_body (str): email body with patched URLs

    """
    patched_body = email_body
    for cid, content_type, image_data_base64 in images:
        cid_reference = f'cid:{cid}'
        data_url = f'data:{content_type};base64,{image_data_base64}'
        patched_body = patched_body.replace(cid_reference, data_url)

    return patched_body


def parse_multipart_message(msg: str) -> tuple[str, str]:
    """
    Extracts the contents from a MIME message.
    Images (if any exist) will be added to the html email_body,
    attachments will be added to the context directly.

    Args:
        msg (str): Message to parse

    Returns:
        (email_body, body_type): Strings containing the parsed email, and the message type (text or html)

    """
    email_message = message_from_string(msg)
    if email_message.get_content_type() == 'multipart/signed':
        # The message is signed
        return ('', '')
    email_body = ''
    body_type = ''
    images: list[tuple[str, str, str]] = []

    for part in email_message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        if content_type in {'application/pkcs7-signature', 'application/pkcs7-mime', 'application/x-pkcs7-mime'}:
            # The message is signed
            return ('', '')

        if part.get_content_disposition() == 'attachment':
            handle_attachment(part)
            continue

        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            raise TypeError(f'Error in message.get_payload(decode=True), expected bytes, got: {type(payload)}')

        if part.get_content_maintype() == 'image':
            if image := handle_image(part, payload):
                images.append(image)

        elif part.get_content_maintype() == 'text' and body_type != 'html':
            email_body, body_type = extract_email_body(part, payload)

    if body_type == 'html':
        email_body = patch_cid_with_urls(email_body, images)

    return (email_body, body_type)


def create_message_with_attachments(message: str, attach_ids: list[str]) -> str:
    """
    Creates a MIMEMultipart formatted message with message body and attachments

    Args:
        message (str): Message body
        attach_ids (list): list of war room entries containing files to attach

    Returns:
        msg (str): Formatted mime message with attachments added

    """
    msg = MIMEMultipart()

    is_html = bool(re.search(r'<.*?>', message))
    if is_html:
        msg.attach(MIMEText(message, 'html'))
    else:
        msg.attach(MIMEText(message, 'plain'))

    # Add attachments to message
    for attach_id in attach_ids:
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
            part.add_header('Content-Disposition', f'attachment; filename={attach_name}')
            msg.attach(part)

    return msg.as_string()


def create_email_header(sender: str, subject: str, recipients: list[str], cc: list[str], bcc: list[str]) -> BIO.MemoryBuffer:
    """
    Creates a memory buffer with email headers

    Args:
        sender (str): Sender email
        subject (str): Email subject
        recipients (list): List of recipient emails
        cc (list): List of cc emails
        bcc (list): List of bcc emails

    Returns:
        header (MemoryBuffer): memory buffer containing email headers

    """
    header = BIO.MemoryBuffer()

    current_time = datetime.now(pytz.timezone('UTC')).strftime('%a, %d %b %Y %H:%M:%S %z')
    header.write(f'Date: {current_time}\r\n')
    if sender:
        header.write(f'From: {sender}\r\n')
    if recipients:
        header.write(f'To: {", ".join(recipients)}\r\n')
    if cc:
        header.write(f'CC: {", ".join(cc)}\r\n')
    if bcc:
        header.write(f'BCC: {", ".join(bcc)}\r\n')
    if subject:
        header.write(f'Subject: {subject}\r\n')

    return header


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


def set_encryption_params(client: Client, certs: list[str]) -> None:
    """
    Sets the smime cipher and X509 certificate stack

    Args:
        client: Client
        certs: List of recipient certificates to use for the encryption

    """
    client.smime.set_cipher(SMIME.Cipher('aes_256_cbc'))

    # Create and set certificate stack
    cert_stack = X509.X509_Stack()
    if not certs:
        demisto.debug('No certs given, using instance cert')
        cert_stack.push(X509.load_cert(client.public_key_file))
    for cert in certs:
        if cert == 'instancePublicKey':
            cert_stack.push(X509.load_cert(client.public_key_file))
            continue
        if ('-----BEGIN CERTIFICATE-----') not in cert:
            demisto.debug('No ---BEGIN CERTIFICATE--- tag, creating pem from cert')
            cert = create_pem_string(cert)

        with NamedTemporaryFile(delete=False) as public_key_file:
            public_key_file.write(bytes(cert, 'utf-8'))
            public_key_file.close()
            cert_stack.push(X509.load_cert(public_key_file.name))
            os.unlink(public_key_file.name)

    client.smime.set_x509_stack(cert_stack)


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

    return CommandResults(
        readable_output=signed,
        outputs_prefix='SMIME.Signed',
        outputs={'Message': signed,
                 'Headers': headers,
                 }
    )


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

    return CommandResults(
        readable_output=encrypted_message,
        outputs_prefix='SMIME.Encrypted',
        outputs={'Message': encrypted_message,
                 'Headers': new_headers,
                 }
    )


def verify(client: Client, args: dict) -> List[CommandResults]:
    """ Verify the signature

    Args:
        client (Client): The client instance.
        args (dict): The arguments for verification.

    """
    signed_message = demisto.getFilePath(args.get('signed_message'))
    cert = args.get('public_key', 'instancePublicKey')
    raw_output = argToBoolean(args.get('raw_output', 'false'))
    tags = argToList(args.get('tag', ''))

    sk = X509.X509_Stack()
    st = X509.X509_Store()
    if cert == 'instancePublicKey':
        sk.push(X509.load_cert(client.public_key_file))
        st.load_info(client.public_key_file)
    elif cert:
        with NamedTemporaryFile(delete=False) as public_key_file:
            public_key_file.write(cert.encode('utf-8'))
            public_key_file_name = public_key_file.name

        sk.push(X509.load_cert(public_key_file_name))
        st.load_info(public_key_file_name)
        os.unlink(public_key_file_name)

    client.smime.set_x509_stack(sk)
    client.smime.set_x509_store(st)
    try:
        result = SMIME.smime_load_pkcs7(signed_message['path'])
        if not isinstance(result, tuple):
            raise DemistoException('SMIME error while loading message')
        p7, data = result
        verified_data = client.smime.verify(p7, data, flags=SMIME.PKCS7_NOVERIFY)
        human_readable = f'The signature verified\n\n{verified_data}'

    except SMIME.SMIME_Error as e:

        if str(e) == 'no content type':
            demisto.debug('No content type found in message, testing if it is in DER format (binary)')
            with open(signed_message['path'], 'rb') as message_file:
                p7data = message_file.read()
            p7bio = BIO.MemoryBuffer(p7data)
            p7 = SMIME.load_pkcs7_bio_der(p7bio)
            verified_data = client.smime.verify(p7, flags=SMIME.PKCS7_NOVERIFY)
            return_results(fileResult(f'unwrapped-{signed_message["name"]}', verified_data))
            human_readable = 'The signature verified\n\n'
        else:
            raise e

    if not verified_data:
        raise ValueError('Unknown error: failed to verify message')
    msg = verified_data.decode('utf-8')
    msg_out = msg
    if not raw_output:  # Return message after parsing html/images/attachments
        demisto.debug(f'Parsing message:\n\n{msg}')
        msg_out, email_type = parse_multipart_message(msg)
        if email_type == 'html':
            human_readable = 'The signature verified'
        else:
            human_readable = f'### The signature verified, message is: \n ___ \n {msg_out}'

    results = [CommandResults(
        readable_output=human_readable,
        outputs_prefix='SMIME.Verified',
        outputs={'Message': msg_out},
        tags=tags,
    )]

    if email_type == 'html':
        results.append(CommandResults(
            raw_response=msg_out,
            content_format=EntryFormat.HTML,
            entry_type=EntryType.NOTE,
        ))

    return results


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


def decrypt_email_body(client: Client, args: dict) -> List[CommandResults]:
    """Decrypt the message

    Args:
        client (Client): The client instance.
        args (Dict): The arguments for decryption.
    """
    if 'test_file_path' in args:  # test module
        encrypt_message = {'path': args.get('test_file_path', '')}
    else:
        encrypt_message = demisto.getFilePath(args.get('encrypt_message', ''))
        demisto.debug(f'File Name:{encrypt_message["name"]}; Type:{type(encrypt_message["name"])}')

    encoding = args.get('encoding', '')
    raw_output = argToBoolean(args.get('raw_output', 'false'))
    tags = argToList(args.get('tag', ''))

    msg = ''
    client.smime.load_key(client.private_key_file, client.public_key_file)
    try:
        p7 = SMIME.smime_load_pkcs7(encrypt_message['path'])
        if isinstance(p7, tuple):
            p7 = p7[0]
        decrypted_text = client.smime.decrypt(p7)
        if not decrypted_text:
            raise ValueError('Unknown error: failed to decrypt message')
        out, msg = decode_str(decrypted_text, encoding)

    except SMIME.SMIME_Error as e:

        if str(e) == 'no content type':  # If no content type; see if we can process as DER format
            demisto.debug('No content type found in message, testing if it is in DER format (binary)')
            with open(encrypt_message['path'], 'rb') as message_file:
                p7data = message_file.read()
            p7bio = BIO.MemoryBuffer(p7data)
            p7 = SMIME.load_pkcs7_bio_der(p7bio)
            decrypted_text = client.smime.decrypt(p7, flags=SMIME.PKCS7_NOVERIFY)
            if not decrypted_text:
                raise ValueError('Unknown error: failed to decrypt message')
            out, msg = decode_str(decrypted_text, encoding)

        else:
            raise

    msg_out = out
    human_readable = f'{msg}The decrypted message is: \n{out}'
    if not raw_output:  # Return message after parsing html/images/attachments
        demisto.debug(f'parsing message:\n\n{out}')
        email_body, email_type = parse_multipart_message(out)
        if email_type == 'html':
            msg_out = email_body
            human_readable = f'{msg}Message decrypted successfully'
        elif email_type == 'text':
            msg_out = email_body
            human_readable = f'### {msg}The decrypted message is: \n ___ \n {msg_out}'
        else:
            human_readable = f'### {msg}The decrypted message is signed, verify to get the original message\n ___ \n{out}'

    results = [CommandResults(
        readable_output=human_readable,
        outputs_prefix='SMIME.Decrypted',
        outputs={'Message': msg_out},
        tags=tags,
    )]

    if email_type == 'html':
        results.append(CommandResults(
            raw_response=msg_out,
            content_format=EntryFormat.HTML,
            entry_type=EntryType.NOTE,
        ))

    return results


def sign_and_encrypt(client: Client, args: dict) -> CommandResults:
    """Sign and encrypt the message

    Args:
        client (Client): The client instance.
        args (Dict): The arguments for signing and encrypting.
    """
    message = args.get('message', '')
    sign = argToBoolean(args.get('signed', 'true'))
    encrypt = argToBoolean(args.get('encrypted', 'true'))
    sender = args.get('sender', '')
    subject = args.get('subject', '')
    create_file = argToBoolean(args.get('create_file_p7', 'false'))
    attachment_ids = argToList(args.get('attachment_entry_id', ''))  # type: list[str]

    recipients = safe_load_json(args.get('recipients', {}) or '{}')
    if not isinstance(recipients, dict):
        raise DemistoException('Failed to parse recipients. (format `{"recipient@email":"cert", "other@email":"cert"}`)')

    cc = safe_load_json(args.get('cc', {}) or '{}')
    if not isinstance(cc, dict):
        raise DemistoException('Failed to parse cc. (format `{"recipient@email":"cert", "other@email":"cert"}`)')

    bcc = safe_load_json(args.get('bcc', {}) or '{}')
    if not isinstance(bcc, dict):
        raise DemistoException('Failed to parse bcc. (format `{"recipient@email":"cert", "other@email":"cert"}`)')

    msg_str = create_message_with_attachments(message, attachment_ids)
    demisto.debug(f'\n\nMessage:\n\n {msg_str} \n\nMessage end\n')

    if sign:
        msg_bio = BIO.MemoryBuffer(msg_str.encode('utf-8'))
        client.smime.load_key(client.private_key_file, client.public_key_file)
        p7 = client.smime.sign(msg_bio, algo='sha256')

    if encrypt:
        pub_certs = [cert for dest in [recipients, cc, bcc] for cert in dest.values()]  # Consolidate all recipient certificates
        set_encryption_params(client, pub_certs)

        msg_bio = BIO.MemoryBuffer()
        if sign:
            client.smime.write(msg_bio, p7)
        else:
            msg_bio.write(msg_str)
        p7 = client.smime.encrypt(msg_bio)

    # Prepare output
    out_bio = create_email_header(sender, subject, list(recipients.keys()), list(cc.keys()), list(bcc.keys()))
    if encrypt or sign:
        client.smime.write(out_bio, p7)
    else:
        out_bio.write(msg_str)

    msg_out = out_bio.read().decode('utf-8')

    file_results = {}
    if create_file:
        file_results = fileResult(filename=f'SMIME-{demisto.uniqueFile()[:8]}.p7', data=msg_out, file_type=EntryType.FILE)
        return_results(file_results)

    return CommandResults(
        readable_output=msg_out,
        outputs_prefix='SMIME.SignedAndEncrypted',
        outputs={
            'Message': msg_out,
            'RecipientIds': {
                'to': list(recipients.keys()),
                'cc': list(cc.keys()),
                'bcc': list(bcc.keys()),
            },
            'FileName': file_results.get('File', ''),
        },
    )


def test_module(client, *_):
    message_body = 'testing'
    try:
        # Encrypt the message
        encrypted_out = sign_and_encrypt(client, {'message': message_body, 'signed': 'false'}).to_context()
        encrypted_msg = encrypted_out['EntryContext']['SMIME.SignedAndEncrypted']['Message']

        # Write the encrypted message to a temporary file
        with NamedTemporaryFile(delete=False) as test_file:
            test_file.write(bytes(encrypted_msg, 'utf-8'))
            test_file_name = test_file.name

        # Decrypt the message
        decrypt_out = decrypt_email_body(client, {'test_file_path': test_file_name})[0].to_context()
        decrypted_msg = decrypt_out['HumanReadable']
        if message_body in decrypted_msg:
            demisto.results('ok')
        else:
            raise Exception

    except Exception:
        return_error('''Failed to encrypt->decrypt using the provided credentials.
                     Verify that the provided keys are valid and matching.''')
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

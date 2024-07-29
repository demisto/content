import pytest
from SMIME_Messaging import Client, sign_email, encrypt_email_body, verify, decrypt_email_body, sign_and_encrypt, \
    decode_str
import demistomock as demisto
import json
import os


with open('./test_data/signer_key.pem') as f:
    private_key = f.read()
with open('./test_data/signer.pem') as file_:
    public_key = file_.read()

client = Client(private_key, public_key)
note_msg = 'Note: encoding detection ended with warning: Trying to detect encoding from a tiny portion'

test_data = [
    (
        b'Za\xbf\xf3\xb3\xe6 g\xea\xb6l\xb1 ja\xbc\xf1',
        'Zaæó³ę gź¶l± ja¼ń',
        '',
        ''
    ),
    (
        b'Za\xbf\xf3\xb3\xe6 g\xea\xb6l\xb1 ja\xbc\xf1',
        'Zażółć gęślą jaźń',
        '',
        'iso-8859-2'
    ),
    (b'\xe3\x81\x8c\xe3\x81\x84\xe3\x83\xa2',
     'がいモ',
     '',
     ''
     ),
    (b'\xd7\xa9\xd7\x9c\xd7\x95\xd7\x9d',
     'שלום',
     '',
     '')
]

with open('./test_data/recipient.pem') as file_:
    recipient_cert = file_.read()
with open('./test_data/recipient_key.pem') as file_:
    recipient_key = file_.read()
with open('./test_data/recipient2.pem') as file_:
    recipient2_cert = file_.read()
with open('./test_data/recipient2_key.pem') as file_:
    recipient2_key = file_.read()
recipient = {'to@email.com': recipient_cert, 'to2@email.com': recipient2_cert}
cc = {'cc@email.com': recipient_cert}
bcc = {'bcc@email.com': recipient2_cert}
attachments = 'attachment1.txt,attachment2.txt'

sign_and_encrypt_tests = [
    # (sign, encrypt, recipients, cc, bcc, create_file, attachments)
    ('', '', {}, {}, {}, '', ''),
    ('True', 'False', recipient, cc, bcc, 'False', ''),
    ('False', 'True', recipient, cc, bcc, 'False', ''),
    ('False', 'False', recipient, cc, bcc, 'False', ''),
    ('False', 'False', recipient, cc, bcc, 'False', attachments),
    ('False', 'False', recipient, cc, bcc, 'True', ''),
    ('True', 'False', recipient, cc, bcc, 'True', ''),
    ('True', 'True', recipient, cc, bcc, 'True', ''),
    ('True', 'True', recipient, cc, bcc, 'True', attachments),
]


def test_sign():
    message_body = 'text to check'

    sign = sign_email(client, {'message_body': message_body}).readable_output
    assert 'MIME-Version: 1.0\nContent-Type: multipart/signed; protocol="application/x-pkcs7-signature"; ' \
           'micalg="sha1";' in sign


def test_verify(mocker):

    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/signed.p7'})

    v = verify(client, {})[0].readable_output
    assert 'a sign of our times' in v


def test_encrypt(mocker):

    mocker.patch.object(demisto, 'args', return_value={'message': 'testing message'})
    encrypt = encrypt_email_body(client, {}).readable_output
    assert 'MIME-Version: 1.0\nContent-Disposition: attachment; filename="smime.p7m"\n' \
           'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n' \
           'Content-Transfer-Encoding: base64' in encrypt


def test_decrypt(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'name': 'encrypt.p7', 'path': './test_data/encrypt.p7'})

    decrypted = decrypt_email_body(client, {})[0].readable_output
    assert 'Hello world' in decrypted


@pytest.mark.parametrize('sign, encrypt, recipients, cc, bcc, create_file, attachments', sign_and_encrypt_tests)
def test_sign_and_encrypt(mocker, sign, encrypt, recipients, cc, bcc, create_file, attachments):
    mocker.patch.object(demisto, 'getFilePath',
                        side_effect=lambda file_name: {'name': file_name, 'path': f'./test_data/{file_name}'})
    mocker.patch.object(demisto, 'uniqueFile', return_value='outfile.txt')
    out_file_name = f'{demisto.investigation()["id"]}_outfile.txt'
    args = {
        'message': 'Sign and encrypt test message',
        'subject': 'Sign and encrypt test subject',
        'sender': 'sender@email.com',
        'encrypted': encrypt,
        'signed': sign,
        'recipients': json.dumps(recipients),
        'cc': json.dumps(cc),
        'bcc': json.dumps(bcc),
        'attachment_entry_id': attachments,
        'create_file_p7': create_file,
    }
    args = {k: v for k, v in args.items() if v != '' and v != '{}'}  # clean up empty args

    sign_encrypt_out = sign_and_encrypt(client, args).to_context()

    readable = sign_encrypt_out['HumanReadable']
    context = sign_encrypt_out['EntryContext']

    for recipient in [key for d in (recipients, cc, bcc) for key in d]:
        assert recipient in readable

    if encrypt != 'False':
        assert 'MIME-Version: 1.0\nContent-Disposition: attachment; filename="smime.p7m"\n' \
            'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n' in readable
    elif sign != 'False':
        assert 'smime-type=signed-data' in readable
    else:
        assert 'Sign and encrypt test message' in readable
        assert 'Sign and encrypt test subject' in readable
        for attach_name in attachments:
            assert attach_name in readable

    if create_file == 'True':
        try:
            with open(out_file_name) as file:
                # Ignore carriage return differences
                assert file.read().replace('\r\n', '\n') == context['SMIME.SignedAndEncrypted']['Message'].replace('\r\n', '\n')
        finally:
            os.unlink(out_file_name)


@pytest.mark.parametrize('decrypted_text_bytes, expected_output, error_msg, encoding', test_data)
def test_decode_using_chardet(decrypted_text_bytes, expected_output, error_msg, encoding):
    """
    Given:
        - Text in bytes to decode

    When:
        - searching for the right encoding code

    Then:
        - Using chardet to find the correct encoding. If confidence of the detected code is under 0.9
        message to note returned

    """
    out, msg = decode_str(decrypted_text_bytes, encoding)
    assert error_msg in msg
    assert out == expected_output


def test_test_module(mocker):
    from SMIME_Messaging import test_module
    mocker.patch.object(demisto, 'results')
    test_module(client)

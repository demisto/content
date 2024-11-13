import pytest
from SMIME_Messaging import Client, sign_email, encrypt_email_body, verify, decrypt_email_body, sign_and_encrypt, \
    decode_str
from CommonServerPython import EntryFormat, entryTypes
import demistomock as demisto
import json
import os


with open('./test_data/signer_key.pem') as f:
    private_key = f.read()
with open('./test_data/signer.pem') as file_:
    public_key = file_.read()

client = Client(private_key, public_key)
note_msg = 'Note: encoding detection ended with warning: Trying to detect encoding from a tiny portion'

test_decode_data = [
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
cc = {'cc@email.com': 'instancePublicKey'}
bcc = {'bcc@email.com': recipient2_cert}
test_attachments = 'attachment1.txt,attachment2.txt'

sign_and_encrypt_tests = [
    # (sign, encrypt, recipients, cc, bcc, create_file, attachments)
    ('', '', '', '', '', '', ''),
    ('True', 'False', recipient, cc, bcc, 'False', ''),
    ('False', 'True', recipient, cc, bcc, 'False', ''),
    ('False', 'False', recipient, cc, bcc, 'False', ''),
    ('False', 'False', recipient, cc, bcc, 'False', test_attachments),
    ('False', 'False', recipient, cc, bcc, 'True', ''),
    ('True', 'False', recipient, cc, bcc, 'True', ''),
    ('True', 'True', recipient, cc, bcc, 'True', ''),
    ('True', 'True', recipient, cc, bcc, 'True', test_attachments),
]

test_messages = [
    ('This is a plain-text test message', 'text'),
    ('<p style="font-weight: bold; font-size: 16px;">This is an html test message, in bold.</p>', 'html'),
]
test_multi_recipient_params = [
    (recipient, '', '', [(recipient_key, recipient_cert), (recipient2_key, recipient2_cert)]),
    (recipient, cc, '', [('instanceKey', 'instanceCert'), (recipient_key, recipient_cert), (recipient2_key, recipient2_cert)]),
    ('', cc, bcc, [('instanceKey', 'instanceCert'), (recipient2_key, recipient2_cert)]),
]


def mockFileResult(filename, data, file_type=None):
    if isinstance(data, str):
        data = data.encode('utf-8')
    if file_type is None:
        file_type = entryTypes['file']
    with open(filename, 'wb') as f:
        f.write(data)
    return {'Contents': '', 'ContentsFormat': 'text', 'Type': file_type, 'File': filename, 'FileID': 0}


def test_sign():
    """
    Given:
        - Client configured with valid key and certificate

    When:
        - Using sign_email

    Then:
        - A signed message is output

    """
    message_body = 'text to check'

    sign = sign_email(client, {'message_body': message_body}).readable_output
    assert 'MIME-Version: 1.0\nContent-Type: multipart/signed; protocol="application/x-pkcs7-signature"; ' \
           'micalg="sha1";' in sign


def test_verify(mocker):
    """
    Given:
        - File to verify in PEM format

    When:
        - Using verify
        - Some tag is provided

    Then:
        - The message will be verified successfully
        - Tag will be added to the war room output

    """

    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/signed.p7'})

    verify_out = verify(client, {'tag': 'test_tag'})[0].to_context()
    assert 'a sign of our times' in verify_out['HumanReadable']
    assert 'test_tag' in verify_out['Tags']


def test_verify_der(mocker):
    """
    Given:
        - File to verify in binary format (DER)

    When:
        - Using verify

    Then:
        - The message will be verified successfully

    """
    mocker.patch('SMIME_Messaging.fileResult', return_value={
        'Contents': '', 'ContentsFormat': 'text', 'Type': '', 'File': '', 'FileID': ''
    })
    mocker.patch.object(demisto, 'getFilePath', return_value={
        'name': 'signed-binary-format.p7m',
        'path': './test_data/signed-binary-format.p7m'
    })

    v = verify(client, {})[0].to_context()['HumanReadable']
    assert 'This is a test email 1, only signed' in v


def test_encrypt(mocker):
    """
    Given:
        - Client configured with valid key and certificate

    When:
        - Using encrypt_email_body

    Then:
        - An encrypted message is output

    """

    mocker.patch.object(demisto, 'args', return_value={'message': 'testing message'})
    encrypt = encrypt_email_body(client, {}).readable_output
    assert 'MIME-Version: 1.0\nContent-Disposition: attachment; filename="smime.p7m"\n' \
           'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n' \
           'Content-Transfer-Encoding: base64' in encrypt


def test_decrypt(mocker):
    """
    Given:
        - File to decrypt in PEM format
        - Client configured with key and certificate matching the cert used for encryption

    When:
        - Using decrypt_email_body
        - Some tag is provided

    Then:
        - The message will be decrypted correctly
        - Tag will be added to the war room output

    """
    mocker.patch.object(demisto, 'getFilePath', return_value={'name': 'encrypt.p7', 'path': './test_data/encrypt.p7'})

    decrypted_out = decrypt_email_body(client, {'tag': 'test_tag'})[0].to_context()
    assert 'Hello world' in decrypted_out['HumanReadable']
    assert 'test_tag' in decrypted_out['Tags']


def test_decrypt_der(mocker):
    """
    Given:
        - File to decrypt in binary format (DER)
        - Client configured with key and certificate matching the cert used for encryption

    When:
        - Using decrypt_email_body

    Then:
        - The message will be decrypted correctly

    """
    # Test decryption when file is in binary format
    mocker.patch.object(demisto, 'getFilePath', return_value={
        'name': 'encrypted-binary-format.p7m',
        'path': './test_data/encrypted-binary-format.p7m'
    })

    decrypted_out = decrypt_email_body(client, {})[0].to_context()
    assert 'This is a test email 2, only encrypted' in decrypted_out['HumanReadable']


@pytest.mark.parametrize('sign, encrypt, recipients, cc, bcc, create_file, attachments', sign_and_encrypt_tests)
def test_sign_and_encrypt(mocker, sign, encrypt, recipients, cc, bcc, create_file, attachments):
    """
    Given:
        - Client configured with valid key and certificate
        - Various command arguments for sign_and_encrypt

    When:
        - Using sign_and_encrypt with the given arguments

    Then:
        - The message will be signed/encrypted as requested
        - Recipient addresses will be included in the mail header
        - Attachments will be added to the email if included
        - Output will be saved to file if requested

    """
    mocker.patch.object(demisto, 'getFilePath',
                        side_effect=lambda file_name: {'name': file_name, 'path': f'./test_data/{file_name}'})
    # patch file result to known name to use for clean up
    mocker.patch.object(demisto, 'uniqueFile', return_value='outfile.txt')
    out_file_name = f'{demisto.investigation()["id"]}_outfile.txt'
    args = {
        'message': 'Sign and encrypt test message',
        'subject': 'Sign and encrypt test subject',
        'sender': 'sender@email.com',
        'encrypted': encrypt,
        'signed': sign,
        'attachment_entry_id': attachments,
        'create_file_p7': create_file,
    }
    if recipients:
        args['recipients'] = json.dumps(recipients)
    if cc:
        args['cc'] = json.dumps(cc)
    if bcc:
        args['bcc'] = json.dumps(bcc)
    args = {k: v for k, v in args.items() if v != ''}  # clean up empty args

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


@pytest.mark.parametrize('msg, msg_type', test_messages)
def test_encrypt_decrypt(mocker, msg, msg_type):
    """
    Given:
        - Client configured with valid key and certificate
        - Message to sign, in plain-text or html format

    When:
        - Using sign_and_encrypt to encrypt the message
        - Then using decrypt_message_body to decrypt the message

    Then:
        - The message will be decrypted successfully
        - For html, an html output entry will be included
        - attachments will be extracted

    """
    mocker.patch.object(demisto, 'getFilePath',
                        side_effect=lambda file_name: {'name': file_name, 'path': f'./test_data/{file_name}'})
    mocker.patch('SMIME_Messaging.fileResult', side_effect=mockFileResult)
    args = {
        'message': msg,
        'subject': 'Encrypt-Decrypt test subject',
        'sender': 'sender@email.com',
        'encrypted': 'True',
        'signed': 'False',
        'attachment_entry_id': test_attachments,
    }

    sign_encrypt_out = sign_and_encrypt(client, args).to_context()
    encrypted_msg = sign_encrypt_out['EntryContext']['SMIME.SignedAndEncrypted']['Message']

    with open('temp_encrypted.p7', 'wb') as f:
        f.write(encrypted_msg.encode('utf-8'))

    try:
        mocker.patch.object(demisto, 'getFilePath', return_value={'name': 'temp_encrypted.p7', 'path': './temp_encrypted.p7'})
        decrypted_out = decrypt_email_body(client, {})
        hr = decrypted_out[0].to_context()['HumanReadable']
        ctx = decrypted_out[0].to_context()['EntryContext']['SMIME.Decrypted']
        assert msg in ctx['Message']
        if msg_type == 'text':
            assert msg in hr

        if msg_type == 'html':
            html_out = decrypted_out[1].to_context()
            assert 'decrypted' in hr
            assert msg in html_out['Contents']
            assert html_out['ContentsFormat'] == EntryFormat.HTML

        for attach in test_attachments.split(','):
            with open(f'./{attach}') as f, open(f'./test_data/{attach}') as orig:
                assert f.read() == orig.read()

    finally:
        os.unlink('./temp_encrypted.p7')
        for attach in test_attachments.split(','):
            os.unlink(f'./{attach}')


@pytest.mark.parametrize('msg, msg_type', test_messages)
def test_sign_verify(mocker, msg, msg_type):
    """
    Given:
        - Client configured with valid key and certificate
        - Message to sign, in plain-text or html format

    When:
        - Using sign_and_encrypt to sign the message
        - Then using verify to check the signature and extract the message

    Then:
        - The message will be verified successfully
        - For html, an html output entry will be included
        - attachments will be extracted

    """
    mocker.patch.object(demisto, 'getFilePath',
                        side_effect=lambda file_name: {'name': file_name, 'path': f'./test_data/{file_name}'})
    mocker.patch('SMIME_Messaging.fileResult', side_effect=mockFileResult)
    args = {
        'message': msg,
        'subject': 'Sign-Verify test subject',
        'sender': 'sender@email.com',
        'encrypted': 'False',
        'signed': 'True',
        'attachment_entry_id': test_attachments,
    }

    sign_encrypt_out = sign_and_encrypt(client, args).to_context()
    signed_msg = sign_encrypt_out['EntryContext']['SMIME.SignedAndEncrypted']['Message']

    with open('temp_signed.p7', 'wb') as f:
        f.write(signed_msg.encode('utf-8'))

    try:
        mocker.patch.object(demisto, 'getFilePath', return_value={'name': 'temp_signed.p7', 'path': './temp_signed.p7'})
        verified_out = verify(client, {})
        hr = verified_out[0].to_context()['HumanReadable']
        ctx = verified_out[0].to_context()['EntryContext']['SMIME.Verified']
        assert msg in ctx['Message']
        assert 'The signature verified' in hr
        if msg_type == 'text':
            assert msg in hr

        if msg_type == 'html':
            html_out = verified_out[1].to_context()
            assert msg in html_out['Contents']
            assert html_out['ContentsFormat'] == EntryFormat.HTML

        for attach in test_attachments.split(','):
            with open(f'./{attach}') as f, open(f'./test_data/{attach}') as orig:
                assert f.read() == orig.read()

    finally:
        os.unlink('./temp_signed.p7')
        for attach in test_attachments.split(','):
            os.unlink(f'./{attach}')


def test_sign_encrypt_decrypt_verify(mocker):
    """
    Given:
        - Client configured with valid key and certificate

    When:
        - Using sign_and_encrypt to encrypt and sign a message
        - Then using decrypt_message_body followed by verify to reverse the action

    Then:
        - The message will decrypt and verify correctly
        - attachments will be extracted

    """
    mocker.patch.object(demisto, 'getFilePath',
                        side_effect=lambda file_name: {'name': file_name, 'path': f'./test_data/{file_name}'})
    mocker.patch('SMIME_Messaging.fileResult', side_effect=mockFileResult)
    args = {
        'message': 'Sign-Encrypt-Decrypt-Verify test message',
        'subject': 'Sign-Encrypt-Decrypt-Verify test subject',
        'sender': 'sender@email.com',
        'encrypted': 'True',
        'signed': 'True',
        'attachment_entry_id': test_attachments,
    }

    sign_encrypt_out = sign_and_encrypt(client, args).to_context()
    encrypted_signed_msg = sign_encrypt_out['EntryContext']['SMIME.SignedAndEncrypted']['Message']

    with open('temp_encrypted_signed.p7', 'wb') as f:
        f.write(encrypted_signed_msg.encode('utf-8'))

    try:
        mocker.patch.object(demisto, 'getFilePath', return_value={
            'name': 'temp_encrypted_signed.p7', 'path': './temp_encrypted_signed.p7'
        })
        decrypted_out = decrypt_email_body(client, {})[0].to_context()
        assert 'The decrypted message is signed' in decrypted_out['HumanReadable']
        assert 'smime-type=signed-data' in decrypted_out['HumanReadable']

    finally:
        os.unlink('./temp_encrypted_signed.p7')

    decrypted_out_msg = decrypted_out['EntryContext']['SMIME.Decrypted']['Message']
    with open('temp_decrypted_signed.p7', 'wb') as f:
        f.write(decrypted_out_msg.encode('utf-8'))

    try:
        mocker.patch.object(demisto, 'getFilePath', return_value={
            'name': 'temp_decrypted_signed.p7', 'path': './temp_decrypted_signed.p7'
        })
        verified_out = verify(client, {})[0].to_context()
        assert 'Sign-Encrypt-Decrypt-Verify test message' in verified_out['HumanReadable']
        assert 'The signature verified' in verified_out['HumanReadable']
        for attach in test_attachments.split(','):
            with open(f'./{attach}') as f, open(f'./test_data/{attach}') as orig:
                assert f.read() == orig.read()

    finally:
        os.unlink('temp_decrypted_signed.p7')
        for attach in test_attachments.split(','):
            os.unlink(f'./{attach}')


@pytest.mark.parametrize('to, cc, bcc, credentials', test_multi_recipient_params)
def test_multi_encrypt_decrypt(mocker, to, cc, bcc, credentials):
    """
    Given:
        - Client configured with valid key and certificate
        - Recipient lists (to, cc, bcc) and their credentials

    When:
        - Using sign_and_encrypt to encrypt a message to these recipients
        - Using decrypt_email_body to decrypt the encrypted message with each of the recipient keys

    Then:
        - The message will decrypt correctly using any one of the recipients private keys
        - The decryption will fail for a key not matching any recipient certificate

    """
    if to:
        to = json.dumps(to)
    if cc:
        cc = json.dumps(cc)
    if bcc:
        bcc = json.dumps(bcc)
    args = {
        'message': 'Multi decrypt test message',
        'sender': 'sender@email.com',
        'signed': 'False',
        'recipients': to,
        'cc': cc,
        'bcc': bcc,
    }

    sign_encrypt_out = sign_and_encrypt(client, args).to_context()
    encrypted_msg = sign_encrypt_out['EntryContext']['SMIME.SignedAndEncrypted']['Message']

    with open('temp_encrypted.p7', 'wb') as f:
        f.write(encrypted_msg.encode('utf-8'))
    mocker.patch.object(demisto, 'getFilePath', return_value={'name': 'temp_encrypted.p7', 'path': './temp_encrypted.p7'})

    try:
        for key, cert in credentials:
            decrypt_client = client
            if key != 'instanceKey':
                decrypt_client = Client(key, cert)

            decrypted_out = decrypt_email_body(decrypt_client, {})
            hr = decrypted_out[0].to_context()['HumanReadable']
            assert 'Multi decrypt test message' in hr

        if 'instanceKey' not in [key for key, _cert in credentials]:
            with pytest.raises(Exception):
                decrypt_email_body(client, {})  # should fail, wrong credentials

    finally:
        os.unlink('temp_encrypted.p7')


@pytest.mark.parametrize('decrypted_text_bytes, expected_output, error_msg, encoding', test_decode_data)
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
    """
    Given:
        - Client was configured with a valid key and certificate pair

    When:
        - Using test module

    Then:
        - Test module will finish successfully

    """
    from SMIME_Messaging import test_module
    mocker.patch.object(demisto, 'results')
    test_module(client)


def test_test_module_fail(mocker):
    """
    Given:
        - Client is configured using non-matching key and certificate

    When:
        - Using test module

    Then:
        - Test module will fail

    """
    from SMIME_Messaging import test_module
    mocker.patch.object(demisto, 'results')
    mocker.patch('SMIME_Messaging.return_error', side_effect=Exception())
    with pytest.raises(Exception):
        test_module(Client(recipient_key, recipient2_cert))

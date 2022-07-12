import pytest

from SMIME_Messaging import Client, sign_email, encrypt_email_body, verify, decrypt_email_body, sign_and_encrypt,\
    decode_str
import demistomock as demisto


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


def test_sign():
    message_body = 'text to check'

    sign, _ = sign_email(client, {'message_body': message_body})
    assert 'MIME-Version: 1.0\nContent-Type: multipart/signed; protocol="application/x-pkcs7-signature"; ' \
           'micalg="sha1";' in sign


def test_verify(mocker):

    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/signed.p7'})

    v, _ = verify(client, {})
    assert 'a sign of our times' in v


def test_encrypt(mocker):

    mocker.patch.object(demisto, 'args', return_value={'message': 'testing message'})
    encrypt, _ = encrypt_email_body(client, {})
    assert 'MIME-Version: 1.0\nContent-Disposition: attachment; filename="smime.p7m"\n' \
           'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n' \
           'Content-Transfer-Encoding: base64' in encrypt


def test_decrypt(mocker):
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': './test_data/encrypt.p7'})

    decrypted, _ = decrypt_email_body(client, {})
    assert 'Hello world' in decrypted


def test_sign_and_encrypt(mocker):

    mocker.patch.object(demisto, 'args', return_value={'message': 'testing message'})
    sign_encrypt, _ = sign_and_encrypt(client, {})
    assert 'MIME-Version: 1.0\nContent-Disposition: attachment; filename="smime.p7m"\n' \
           'Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\n' \
           'Content-Transfer-Encoding: base64' in sign_encrypt


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

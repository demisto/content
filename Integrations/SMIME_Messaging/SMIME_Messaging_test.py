from SMIME_Messaging import Client, sign_email, encrypt_email_body, verify, decrypt_email_body, test_module
import demistomock as demisto


with open('./test_data/signer_key.pem') as f:
    private_key = f.read()
with open('./test_data/signer.pem') as file_:
    public_key = file_.read()

client = Client(private_key, public_key)


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


def test_test_module(mocker):
    mocker.patch.object(demisto, 'results')
    response = test_module(client)
    assert 'Hello World' in response

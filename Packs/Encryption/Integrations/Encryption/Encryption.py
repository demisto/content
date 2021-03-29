import rsa

from CommonServerPython import *
import demistomock as demisto


def test_module():
    return 'ok'


def get_public_key():
    with open('pub.pem', 'rb') as f:
        content = f.read()

    return rsa.PublicKey.load_pkcs1(content)


def get_private_key():
    with open('priv.pem', 'rb') as f:
        content = f.read()

    return rsa.PrivateKey.load_pkcs1(content)


def encrypt(cipher_base64) -> bytes:
    # nedpq = get_public_key()
    # public_key = rsa.PublicKey(*nedpq)
    public_key = get_public_key()
    cipher_base64 = cipher_base64.encode('utf-8')
    try:
        # cipher_text = base64.b64decode(cipher_base64)
        plain_text = rsa.encrypt(cipher_base64, public_key)
        return plain_text
    except Exception as e:
        raise DemistoException(f'Could not encrypt\n{e}')


def decrypt(cipher_base64) -> bytes:
    # nedpq = get_private_key()
    # private_key = rsa.PrivateKey(*nedpq)
    private_key = get_private_key()
    try:
        # cipher_text = base64.b64decode(cipher_base64)
        plain_text = rsa.decrypt(cipher_base64, private_key)
        return plain_text.decode('utf-8')
    except Exception as e:
        raise DemistoException(f'Could not decrypt\n{e}')


def main() -> None:
    params = demisto.params()

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        if demisto.command() == 'test-module':
            test_module()

        if demisto.command() == 'encryption-encrypt':
            cipher_base64 = params.get('cipher_text')
            return_results(encrypt(cipher_base64))

        if demisto.command() == 'encryption-decrypt':
            cipher_base64 = params.get('cipher_text')
            return_results(decrypt(cipher_base64))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    # main()
    s = 'timor'
    x = encrypt(s)
    print(x)
    y = decrypt(x)
    print(y)

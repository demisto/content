import rsa

from CommonServerPython import *
import demistomock as demisto


def test_module():
    return 'ok'


def encrypt(cipher_base64) -> bytes:
    nedpq = get_key_values()
    public_key = rsa.PublicKey(*nedpq)
    try:
        cipher_text = base64.b64decode(cipher_base64)
        plain_text = rsa.encrypt(cipher_text, public_key)
        return plain_text
    except Exception:
        raise DemistoException('Could not encrypt')


def decrypt(cipher_base64) -> bytes:
    nedpq = get_key_values()
    private_key = rsa.PrivateKey(*nedpq)
    try:
        cipher_text = base64.b64decode(cipher_base64)
        plain_text = rsa.decrypt(cipher_text, private_key)
        return plain_text
    except Exception:
        raise DemistoException('Could not decrypt')


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
    main()

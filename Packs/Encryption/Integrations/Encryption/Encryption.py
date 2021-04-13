import rsa

from CommonServerPython import *
import demistomock as demisto


def test_module(params):
    params_public_key = params.get('public_key')
    params_private_key = params.get('private_key')

    if any([params_public_key, params_private_key]):
        return 'ok'

    try:
        get_public_key()
    except Exception:
        return_error('You can either enter public and/or private key in the instance configuration or run the '
                     '"encryption-create-keys" to create the keys for the instance.')

    return 'ok'


def get_public_key() -> rsa.PublicKey:
    params = demisto.params()
    params_public_key = params.get('public_key')

    if params_public_key:
        return params_public_key

    integration_context = get_integration_context()
    public_key = integration_context.get('public_key')

    if not public_key:
        raise DemistoException('Public key is not defined.')

    public_key = public_key.encode('utf-8')

    return rsa.PublicKey.load_pkcs1(public_key)


def get_private_key() -> rsa.PrivateKey:
    params = demisto.params()
    params_private_key = params.get('private_key')

    if params_private_key:
        return params_private_key

    integration_context = get_integration_context()
    private_key = integration_context.get('private_key')

    if not private_key:
        raise DemistoException('Private key is not defined.')

    private_key = private_key.encode('utf-8')

    return rsa.PrivateKey.load_pkcs1(private_key)


def create_keys(params, args):
    params_public_key = params.get('public_key')
    params_private_key = params.get('private_key')

    if any([params_public_key, params_private_key]):
        raise DemistoException(
            'Public key or Private key are provided in the instance configuration. Skipping new keys creation.')

    override_keys = argToBoolean(args.get('override_keys', False))
    if get_public_key() and not override_keys:
        raise DemistoException(
            'Keys have already been generated. You can use the "override_keys=true" argument in order to '
            'override the current generated keys.'
        )

    try:
        public_key, private_key = rsa.key.newkeys(512)

        integration_context = {
            'public_key': public_key.save_pkcs1().decode('utf-8'),
            'private_key': private_key.save_pkcs1().decode('utf-8'),
        }

        set_integration_context(integration_context)
    except Exception as e:
        raise DemistoException(f'Failed to generate new RSA keys.\n{e}')

    return_results('Keys created successfully.')


def encrypt_text(args) -> str:
    text_to_encrypt = args.get('text_to_encrypt').encode('utf-8')
    public_key = get_public_key()

    if not public_key:
        raise DemistoException('No public key has been provided or generated.')

    try:
        encrypted_bytes = rsa.encrypt(text_to_encrypt, public_key)
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        raise DemistoException(f'Could not encrypt text.\n{e}')


def decrypt_text(args) -> str:
    base64_to_decrypt = args.get('base64_to_decrypt')
    private_key = get_private_key()

    if not private_key:
        raise DemistoException('No private key has been provided or generated.')

    try:
        encrypted_bytes = base64.b64decode(base64_to_decrypt)
        decrypted_bytes = rsa.decrypt(encrypted_bytes, private_key)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise DemistoException(f'Could not decrypt text.\n{e}')


def encrypt_file(args) -> None:
    entry_id = args.get('entry_id')

    try:
        file_entry = demisto.getFilePath(entry_id)
        file_path = file_entry['path']
        file_name = file_entry['name']

        with open(file_path, 'r') as file:
            file_content = file.read()

        base64_encrypted_content = encrypt_text({
            'text_to_encrypt': file_content,
        })

        demisto.results(fileResult(file_name, base64_encrypted_content))
    except Exception as e:
        raise DemistoException(f'Could not encrypt file.\n{e}')


def decrypt_file(args) -> None:
    entry_id = args.get('entry_id')

    try:
        file_entry = demisto.getFilePath(entry_id)
        file_path = file_entry['path']
        file_name = file_entry['name']

        with open(file_path, 'r') as file:
            file_content = file.read()

        decrypted_content = decrypt_text({
            'base64_to_decrypt': file_content,
        })

        demisto.results(fileResult(file_name, decrypted_content))
    except Exception as e:
        raise DemistoException(f'Could not decrypt file.\n{e}')


def main() -> None:
    params = demisto.params()
    args = demisto.args()

    commands = {
        'encryption-encrypt-text': encrypt_text,
        'encryption-decrypt-text': decrypt_text,
        'encryption-encrypt-file': encrypt_file,
        'encryption-decrypt-file': decrypt_file,
    }

    command = demisto.command()
    demisto.debug(f'Command being called is "{command}".')

    try:
        if command == 'test-module':
            test_module(params)

        if command == 'encryption-create-keys':
            create_keys(params, args)

        elif command in commands:
            return_results(commands[command](args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

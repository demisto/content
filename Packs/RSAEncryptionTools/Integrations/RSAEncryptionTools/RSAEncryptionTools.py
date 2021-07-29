import os.path
from typing import Tuple

import rsa

from CommonServerPython import *
import demistomock as demisto

PREFIX = '-----BEGIN RSA PRIVATE KEY-----'  # guardrails-disable-line
SUFFIX = '-----END RSA PRIVATE KEY-----'  # guardrails-disable-line


def test_module():
    try:
        get_public_key()
    except Exception:
        try:
            get_private_key()
        except Exception:
            raise DemistoException('You must provide valid public and/or private keys.')

    return 'ok'


def get_public_key() -> rsa.PublicKey:
    """Gets the public key from the instance configuration.

    Returns:
        rsa.PublicKey. The public key to be used with the integration.
    """
    params = demisto.params()
    params_public_key = params.get('public_key')

    if params_public_key:
        return rsa.PublicKey.load_pkcs1(params_public_key)

    raise DemistoException('Public key is not defined.')


def get_private_key() -> rsa.PrivateKey:
    """Gets the private key from the instance configuration.

    Returns:
        rsa.PrivateKey. The private key to be used with the integration.
    """
    params = demisto.params()
    params_private_key = params.get('private_key')

    if params_private_key:
        return rsa.PrivateKey.load_pkcs1(params_private_key.encode('utf-8'))

    raise DemistoException('Private key is not defined.')


def encrypt(text_to_encrypt: str) -> str:
    """Encrypts a string using the public key.

    Args:
        text_to_encrypt (str): The text to encrypt.

    Returns:
        str: The encrypted base64 string.
    """
    public_key = get_public_key()

    if not public_key:
        raise DemistoException('No public key has been provided or generated.')

    try:
        encrypted_bytes = rsa.encrypt(text_to_encrypt.encode('utf-8'), public_key)
        encrypted_value = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_value
    except Exception as e:
        raise DemistoException(f'Could not encrypt data.\n{e}')


def encrypt_text(args) -> CommandResults:
    """Encrypts text into base64 string.

    Args:
        args:
            - text_to_encrypt (str): The string to encrypt.

    Returns:
        str. The encrypted base64 string.
    """
    text_to_encrypt = args.get('text_to_encrypt')
    encrypted_value = encrypt(text_to_encrypt)

    return CommandResults(
        outputs_prefix='EncryptionTools',
        outputs={'Value': encrypted_value},
        readable_output=f'### Encrypted Text:\n{encrypted_value}',
    )


def decrypt_text(args) -> str:
    """Decrypts a base64 text.

    Args:
        args:
            - base64_to_decrypt (str): The base64 string to decrypt.

    Returns:
        str. The decrypted text.
    """
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


def get_file_name_and_extension(full_file_name: str) -> Tuple[str, str]:
    """Splits the full file name to file name and file extension.

    Args:
        full_file_name (str): The full file name.

    Returns:
        Tuple[str, str]. File name and file extension.
    """
    return os.path.splitext(full_file_name)


def encrypt_file(args) -> Dict:
    """Encrypts a file and creates a war-room file entry with the encrypted content.

    Args:
        args:
            - entry_id (str): The entry ID of the file to encrypt.

    Returns:
        Dict. fileResult object.
    """
    entry_id = args.get('entry_id')

    try:
        file_entry = demisto.getFilePath(entry_id)
        file_path = file_entry['path']
        file_name = file_entry['name']

        with open(file_path, 'r') as file:
            file_content = file.read()

        base64_encrypted_content = encrypt(text_to_encrypt=file_content)

        file_name, file_extension = get_file_name_and_extension(file_name)
        return fileResult(
            f'{file_name}-xsoar-encrypted{file_extension}',
            base64_encrypted_content,
            EntryType.ENTRY_INFO_FILE,
        )

    except DemistoException:
        raise

    except Exception as e:
        raise DemistoException(f'Could not encrypt file.\n{e}')


def decrypt_file(args) -> Union[Dict, str]:
    """Decrypts a file and creates a war-room file entry with the decrypted content.

    Args:
        args:
            - entry_id (str): The entry ID of the file to decrypt.
            - output_as_file(bool): Whether to output the decrypted data to file or to the war room.

    Returns:
        One of:
            - Dict. fileResult object.
            - str. The decrypted file content.
    """
    entry_id = args.get('entry_id')
    output_as_file = argToBoolean(args.get('output_as_file', False))

    try:
        file_entry = demisto.getFilePath(entry_id)
        file_path = file_entry['path']
        file_name = file_entry['name']

        with open(file_path, 'r') as file:
            file_content = file.read()

        decrypted_content = decrypt_text({
            'base64_to_decrypt': file_content,
        })

        if not output_as_file:
            return decrypted_content

        file_name, file_extension = get_file_name_and_extension(file_name)
        return fileResult(
            f'{file_name}-xsoar-decrypted{file_extension}',
            decrypted_content,
            EntryType.ENTRY_INFO_FILE,
        )

    except DemistoException:
        raise

    except Exception as e:
        raise DemistoException(f'Could not decrypt file.\n{e}\n{file_content}')


def export_public_key(args):
    """Exports the public key to file.

    Args:
        args:
            - output_file_name (str): The name of the output file.

    Returns:
        Dict. fileResult object.
    """
    public_key = get_public_key()

    output_file_name = args['output_file_name']
    return fileResult(
        output_file_name,
        public_key.save_pkcs1().decode('utf-8'),
        EntryType.ENTRY_INFO_FILE,
    )


def main() -> None:
    args = demisto.args()

    commands = {
        'rsa-encryption-tools-encrypt-text': encrypt_text,
        'rsa-encryption-tools-decrypt-text': decrypt_text,
        'rsa-encryption-tools-encrypt-file': encrypt_file,
        'rsa-encryption-tools-decrypt-file': decrypt_file,
        'rsa-encryption-tools-export-public-key': export_public_key,
    }

    command = demisto.command()
    demisto.debug(f'Command being called is "{command}".')

    try:
        if command == 'test-module':
            return_results(test_module())

        elif command in commands:
            return_results(commands[command](args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

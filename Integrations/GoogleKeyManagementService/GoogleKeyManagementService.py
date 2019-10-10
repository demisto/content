import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
from google.cloud import kms_v1
from google.cloud.kms_v1 import enums
import requests
import urllib3
from json import JSONDecodeError
import base64
from typing import Any, Dict, Tuple, List

INTEGRATION_NAME = 'Google Key Management System'
# lowercase with `-` dividers
INTEGRATION_COMMAND_NAME = 'google-kms-'
# No dividers
INTEGRATION_CONTEXT_NAME = 'GoogleKMS'

DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S'
RFC3339_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class Client:
    def __init__(self, params: Dict[str, Any]):
        self.project = params.get('project')
        self.location = params.get('location')
        self.key_ring = params.get('key_ring')
        self.service_account = params.get('service_account')
        self.role = params.get('role')
        if params.get('insecure'):
            disable_tls_verification()

        handle_proxy()
        # Creates an API client for the KMS API.
        try:
            self.kms_client = self._init_kms_client()

        except JSONDecodeError:
            raise Exception("Service Account json is not formatted well please re-enter it.")

    def _init_kms_client(self):
        """Creates the Python API client for Google Cloud KMS.
        """
        cur_directory_path = os.getcwd()
        credentials_file_name = demisto.uniqueFile() + '.json'
        credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)

        with open(credentials_file_path, 'w') as creds_file:
            json_object = json.loads(self.service_account)
            json.dump(json_object, creds_file)

        return kms_v1.KeyManagementServiceClient.from_service_account_json(credentials_file_path)


"""HELPER FUNCTIONS"""


def disable_tls_verification() -> None:
    """Disables TLS verification allowing Insecure session.

    """
    original_method = requests.Session.merge_environment_settings

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        settings = original_method(self, url, proxies, stream, verify, cert)
        settings['verify'] = False
        return settings

    # noinspection PyTypeHints
    requests.Session.merge_environment_settings = merge_environment_settings  # type: ignore

    urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)


def arg_dict_creator(string: str) -> Dict:
    """Creates a Dict from a CSV string.

    Args:
        string(str): CSV string - formatted as 'field1:value1,field2:value2'.

    Returns:
        Dict from string representation.
    """
    if string is None or len(string) == 0:
        return None
    split_string = string.split(',')
    arg_dict = {}
    for section in split_string:
        key, value = section.split(':')
        arg_dict[key] = value

    return arg_dict


def key_context_creation(res: Any) -> Dict:
    """Creates GoogleKMS.CryptoKey context.

    Args:
        res(Any): `~google.cloud.kms_v1.types.CryptoKey` instance.

    Returns:
        Dict representing GoogleKMS.CryptoKey context.
    """
    key_context = {
        'Name': res.name,
        'Purpose': enums.CryptoKey.CryptoKeyPurpose(res.purpose).name,
        'CreationTime': datetime.fromtimestamp(int(res.create_time.seconds)).strftime(DEMISTO_DATETIME_FORMAT),
        'NextRotationTime': datetime.fromtimestamp(int(res.next_rotation_time.seconds)).strftime(DEMISTO_DATETIME_FORMAT),
        'RotationPeriod': f'{str(res.rotation_period.seconds)}s',
        'Labels': arg_dict_creator(str(res.labels)[1:-1]),
        'VersionTemplate': {
            'ProtectionLevel': enums.ProtectionLevel(res.version_template.protection_level).name,
            'Algorithm': enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm(res.version_template.algorithm).name,
        }
    }
    if res.primary:
        key_context['PrimaryCryptoKeyVersion'] = {
            'Name': res.primary.name,
            'State': enums.CryptoKeyVersion.CryptoKeyVersionState(res.primary.state).name,
            'CreationTime': datetime.fromtimestamp(int(res.primary.create_time.seconds)).strftime(DEMISTO_DATETIME_FORMAT),
            'ProtectionLevel': enums.ProtectionLevel(res.primary.protection_level).name,
            'Algorithm': enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm(res.primary.algorithm).name,
            'GenerateTime': datetime.fromtimestamp(int(res.primary.generate_time.seconds)).strftime(DEMISTO_DATETIME_FORMAT)
        }

    return key_context


def crypto_key_to_json(crypto_key: Any) -> Dict:
    """Creates a json dict from `~google.cloud.kms_v1.types.CryptoKey` instance to use as raw response.

    Args:
        crypto_key(Any): `~google.cloud.kms_v1.types.CryptoKey` instance.

    Returns:
        A json Dict containing the raw response.
    """
    key_json = {
        'name': crypto_key.name,
        'purpose': enums.CryptoKey.CryptoKeyPurpose(crypto_key.purpose).name,
        'create_time': {
            'seconds': crypto_key.create_time.seconds,
            'nanos': crypto_key.create_time.nanos

        },
        'next_rotation_time': {
            'seconds': crypto_key.next_rotation_time.seconds,
            'nanos': crypto_key.next_rotation_time.nanos
        },
        'rotation_period': {
            'seconds': crypto_key.rotation_period.seconds
        },
        'labels': arg_dict_creator(str(crypto_key.labels)[1:-1]),
        'version_template': {
            'protection_level': enums.ProtectionLevel(crypto_key.version_template.protection_level).name,
            'algorithm': enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm(crypto_key.version_template.algorithm).name,
        }
    }
    if crypto_key.primary:
        key_json['primary'] = {
            'name': crypto_key.primary.name,
            'state': enums.CryptoKeyVersion.CryptoKeyVersionState(crypto_key.primary.state).name,
            'create_time': {
                'seconds': crypto_key.primary.create_time.seconds,
                'nanos': crypto_key.primary.create_time.nanos
            },
            'protection_level': enums.ProtectionLevel(crypto_key.primary.protection_level).name,
            'algorithm': enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm(crypto_key.primary.algorithm).name,
            'generate_time': {
                'seconds': crypto_key.primary.generate_time.seconds,
                'nanos': crypto_key.primary.generate_time.nanos
            }
        }

    return key_json


def demisto_args_extract(client: Client, args: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Extracts IDs to use for KMS functions.

    Args:
        args(dict): Demisto arguments.
        client(Client): User Client.

    Returns:
        A tuple containing strings representing the required IDs.
    """
    project_id = client.project

    location_id = args.get('location_id')
    if location_id == 'default':
        location_id = client.location

    key_ring_id = args.get('key_ring_id')
    if key_ring_id == 'default':
        key_ring_id = client.key_ring

    crypto_key_id = args.get('crypto_key_id')
    return project_id, location_id, key_ring_id, crypto_key_id


def count_rings(key_ring_iterable: Any) -> int:
    """ Counts the amount of key rings given from the iterable given.

    Args:
        key_ring_iterable: An iterable of :class:`~google.cloud.kms_v1.types.KeyRing` instances.

    Returns:
        The number of key rings in the project.
    """
    return sum(1 for ring in key_ring_iterable)


def get_update_mask(args: Dict[str, Any]) -> Dict:
    """ Creates the 'updateMask' parameter for the command
    which is a comma separated list of fields to update.

    Args:
        args(dict): Demisto args indicating which field to update.

    Returns:
        A Dict to use as the params for update command.
    """
    update_mask = []
    if args.get('labels') is not None:
        update_mask.append('labels')

    if args.get('next_rotation_time') is not None:
        update_mask.append('next_rotation_time')

    if args.get('purpose') is not None:
        update_mask.append('purpose')

    if args.get('rotation_period') is not None:
        update_mask.append('rotation_period')

    if args.get('attestation') is not None:
        update_mask.append('primary.attestation')

    if args.get('state') is not None:
        update_mask.append('primary.state')

    if args.get('algorithm') is not None:
        update_mask.append('version_template.algorithm')

    if args.get('protection_level') is not None:
        update_mask.append('version_template.protection_level')

    return {
        'paths': update_mask
    }


def init_dict(body: Dict[str, Any], parent: str, key: str, value: Any):
    """Creates a new dictionary to be used in update command body.

    Args:
        body(dict): The update command body dict.
        parent(str): The key in the body.
        key(str): The inner key of the sub-dictionary.
        value(Any): The value to put in the sub-dictionary.

    """
    body[parent] = {
        key: value
    }


def get_update_command_body(args: Dict[str, Any], update_mask: List) -> Dict:
    """Creates update command request body, in accordance with the updateMask.

    Args:
        args(Dict): Demisto arguments containing the updated values.
        update_mask(List): List of fields to update.

    Returns:
        Dict to be used as body for update command
    """
    body = {}  # type:Dict[str,Any]
    for field in update_mask:
        if '.' in field:
            split_field = field.split('.')
            if split_field[1] == 'attestation':
                if split_field[0] in body.keys():
                    body[split_field[0]][split_field[1]] = arg_dict_creator(args.get(split_field[1]))

                else:
                    init_dict(body, split_field[0], split_field[1], arg_dict_creator(args.get(split_field[1])))

            elif split_field[1] == 'state':
                if split_field[0] in body.keys():
                    val = enums.CryptoKeyVersion.CryptoKeyVersionState[args.get('state')].value
                    body[split_field[0]][split_field[1]] = val

                else:
                    init_dict(body, split_field[0], split_field[1],
                              enums.CryptoKeyVersion.CryptoKeyVersionState[args.get('state')].value)

            elif split_field[1] == 'algorithm':
                if split_field[0] in body.keys():
                    val = enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm[args.get('algorithm')].value
                    body[split_field[0]][split_field[1]] = val

                else:
                    init_dict(body, split_field[0], split_field[1],
                              enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm[args.get('algorithm')].value)

            elif split_field[1] == 'protection_level':
                if split_field[0] in body.keys():
                    body[split_field[0]][split_field[1]] = enums.ProtectionLevel[args.get('protection_level')].value

                else:
                    init_dict(body, split_field[0], split_field[1],
                              enums.ProtectionLevel[args.get('protection_level')].value)

            else:
                if split_field[0] in body.keys():
                    body[split_field[0]][split_field[1]] = args.get(split_field[1])

                else:
                    init_dict(body, split_field[0], split_field[1], args.get(split_field[1]))
        else:
            if field == 'labels':
                body[field] = arg_dict_creator(args.get('labels'))

            elif field == 'next_rotation_time':
                body[field] = {'seconds': int(datetime.strptime(args.get('next_rotation_time'),
                                                                RFC3339_DATETIME_FORMAT).timestamp())}
            elif field == 'rotation_period':
                body[field] = {'seconds': int(args.get('rotation_period'))}

            elif field == 'purpose':
                body[field] = enums.CryptoKey.CryptoKeyPurpose[args.get('purpose')].value

            else:
                body[field] = args.get(field)

    return body


"""GENERAL FUNCTIONS"""


def create_crypto_key_command(client: Client, args: Dict[str, Any]) -> Tuple[str, Dict, Dict]:
    """Create a new CryptoKey.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)
    # Creates an API client for the KMS API.

    # The resource name of the KeyRing associated with the CryptoKey.
    key_ring_name = client.kms_client.key_ring_path(project_id, location_id, key_ring_id)
    if args.get('next_rotation_time'):
        next_rotation_time = {
            'seconds': int(datetime.strptime(args.get('next_rotation_time'), RFC3339_DATETIME_FORMAT).timestamp())
        }

    else:
        next_rotation_time = {
            'seconds': int((datetime.now() + timedelta(days=90)).timestamp())
        }

    # Create the CryptoKey object template
    crypto_key = {
        'purpose': enums.CryptoKey.CryptoKeyPurpose[args.get('purpose')].value,
        'next_rotation_time': next_rotation_time,
        'labels': arg_dict_creator(args.get('labels')),
        'rotation_period': {
            'seconds': int(args.get('rotation_period'))
        },
    }
    # Additional info in case CryptoKeyVersion is created
    if not args.get('skip_initial_version_creation') == 'true':
        crypto_key['primary'] = {
            'state': enums.CryptoKeyVersion.CryptoKeyVersionState[args.get('state')].value,
            'attestation': arg_dict_creator(args.get('attestation'))
        }
        crypto_key['version_template'] = {
            'algorithm': enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm[args.get('algorithm')].value,
            'protection_level': enums.ProtectionLevel[args.get('protection_level')].value
        }

    # Create a CryptoKey for the given KeyRing.
    response = client.kms_client.create_crypto_key(key_ring_name, crypto_key_id, crypto_key,
                                                   args.get('skip_initial_version_creation') == 'true')

    context = key_context_creation(response)

    return (
        tableToMarkdown("Google KMS CryptoKey info:", context, removeNull=True),
        {
            f'{INTEGRATION_CONTEXT_NAME}.CryptoKey(val.Name == obj.Name)': context,
        },
        crypto_key_to_json(response)
    )


def encrypt_key_command(client: Client, args: Dict[str, Any]) -> str:
    """Encrypt plaintext to ciphertext.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.

    Returns:
        The encrypted ciphertext.
    """
    if args.get('use_base64') == 'false':
        plaintext = base64.b64encode(bytes(args.get('plaintext'), 'utf-8'))

    else:
        plaintext = base64.b64decode(args.get('plaintext'))

    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    additional_authenticated_data = None
    if args.get('additional_authenticated_data'):
        additional_authenticated_data = base64.b64decode(args.get('additional_authenticated_data'))

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path_path(project_id, location_id, key_ring_id, crypto_key_id)

    # Use the KMS API to encrypt the data.
    response = client.kms_client.encrypt(crypto_key_name, plaintext,
                                         additional_authenticated_data=additional_authenticated_data)

    return str(base64.b64encode(response.ciphertext))[2:-1]


def decrypt_key_command(client: Client, args: Dict[str, Any]) -> str:
    """Decrypt ciphertext to plaintext.

    Args:
        client(Client): User Client.
        args(Dict): Demisto agruments.

    Returns:
        The decrypted text.
    """
    ciphertext = base64.b64decode(args.get('ciphertext'))
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    additional_authenticated_data = None
    if args.get('additional_authenticated_data'):
        additional_authenticated_data = base64.b64decode(args.get('additional_authenticated_data'))

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path_path(project_id, location_id, key_ring_id, crypto_key_id)
    # Use the KMS API to decrypt the data.
    response = client.kms_client.decrypt(crypto_key_name, ciphertext,
                                         additional_authenticated_data=additional_authenticated_data)
    if args.get('use_base64') == 'true':
        return str(base64.b64encode(response.plaintext))[2:-1]

    else:
        return str(base64.b64decode(response.plaintext))[2:-1]


def get_key_command(client: Client, args: Dict[str, Any]) -> Tuple[str, Dict, Dict]:
    """Gets a CryptoKey.

    Args:
        client(Client): User Client.
        args(Dict): Demisto Arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)

    # Get CryptoKey info.
    response = client.kms_client.get_crypto_key(crypto_key_name)

    context = key_context_creation(response)

    return (
        tableToMarkdown("Google KMS CryptoKey info:", context, removeNull=True),
        {
            f'{INTEGRATION_CONTEXT_NAME}.CryptoKey(val.Name == obj.Name)': context,
        },
        crypto_key_to_json(response)
    )


def disable_key_version_command(client: Client, args: Dict[str, Any]) -> None:
    """Disable a given CryptoKeyVersion.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)
    crypto_key_version = args.get('crypto_key_version')
    # Construct the resource name of the CryptoKeyVersion.
    crypto_key_version_name = client.kms_client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                                                        crypto_key_id, crypto_key_version)

    # Use the KMS API to disable the CryptoKeyVersion.
    new_state = enums.CryptoKeyVersion.CryptoKeyVersionState.DISABLED
    version = {'name': crypto_key_version_name, 'state': new_state}
    update_mask = {'paths': ["state"]}

    # Print results
    response = client.kms_client.update_crypto_key_version(version, update_mask)
    demisto.results(f'CryptoKeyVersion {crypto_key_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}.')


def enable_key_version_command(client: Client, args: Dict[str, Any]) -> None:
    """Enable a CryptoKeyVersion.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)
    crypto_key_version = args.get('crypto_key_version')
    # Construct the resource name of the CryptoKeyVersion.
    crypto_key_version_name = client.kms_client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                                                        crypto_key_id, crypto_key_version)

    # Use the KMS API to disable the CryptoKeyVersion.
    new_state = enums.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
    version = {'name': crypto_key_version_name, 'state': new_state}
    update_mask = {'paths': ["state"]}

    # Print results
    response = client.kms_client.update_crypto_key_version(version, update_mask)
    demisto.results(f'CryptoKeyVersion {crypto_key_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}.')


def destroy_key_version_command(client: Client, args: Dict[str, Any]) -> None:
    """Schedule the destruction of a given CryptoKeyVersion.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)
    crypto_key_version = args.get('crypto_key_version')

    # Construct the resource name of the CryptoKeyVersion.
    crypto_key_version_name = client.kms_client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                                                        crypto_key_id, crypto_key_version)

    # Use the KMS API to mark the CryptoKeyVersion for destruction.
    response = client.kms_client.destroy_crypto_key_version(crypto_key_version_name)

    # Print results
    demisto.results(f'CryptoKeyVersion {crypto_key_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}, it will be destroyed in 24h.')


def restore_key_version_command(client: Client, args: Dict[str, Any]) -> None:
    """Restores a CryptoKeyVersion scheduled for destruction.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)
    crypto_key_version = args.get('crypto_key_version')

    # Construct the resource name of the CryptoKeyVersion.
    crypto_key_version_name = client.kms_client.crypto_key_version_path(project_id, location_id, key_ring_id,
                                                                        crypto_key_id, crypto_key_version)

    # Use the KMS API to restore the CryptoKeyVersion.
    response = client.kms_client.restore_crypto_key_version(crypto_key_version_name)

    # Print results
    demisto.results(f'CryptoKeyVersion {crypto_key_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}.')


def update_key_command(client: Client, args: Dict[str, Any]) -> Tuple[str, Dict, Dict]:
    """Update a given CryptoKey.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.
    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)

    update_mask = get_update_mask(args)

    crypto_key = get_update_command_body(args=args, update_mask=update_mask['paths'])
    crypto_key['name'] = crypto_key_name

    response = client.kms_client.update_crypto_key(crypto_key=crypto_key, update_mask=update_mask)

    context = key_context_creation(response)
    return (
        tableToMarkdown("Google KMS CryptoKey info:", context, removeNull=True),
        {
            f'{INTEGRATION_CONTEXT_NAME}.CryptoKey(val.Name == obj.Name)': context,
        },
        crypto_key_to_json(response)
    )


def list_keys_command(client: Client, args: Dict[str, Any]) -> Tuple[str, Dict, List]:
    """List All keys in a KeyRing.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.

    """
    project_id, location_id, key_ring_id, _ = demisto_args_extract(client, args)

    key_ring_name = client.kms_client.key_ring_path(project_id, location_id, key_ring_id)

    filter_state = args.get('key_state', None)

    response = client.kms_client.list_crypto_keys(key_ring_name, filter_=filter_state)

    overall_context = []  # type: List
    overall_raw = []  # type: List
    for crypto_key in response:
        overall_context.append(key_context_creation(crypto_key))
        overall_raw.append(crypto_key_to_json(crypto_key))

    return (
        tableToMarkdown("CryptoKeys:", overall_context, removeNull=True),
        {
            f'{INTEGRATION_CONTEXT_NAME}.CryptoKey(val.Name == obj.Name)': overall_context,
        },
        overall_raw
    )


def disable_key_command(client: Client, args: Dict[str, Any]) -> None:
    """Disable the primary CryptoKeyVersion of a given CryptoKey.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.

    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)

    crypto_key = client.kms_client.get_crypto_key(crypto_key_name)
    crypto_key_primary_version_name = crypto_key.primary.name

    # Use the KMS API to disable the CryptoKeyVersion.
    new_state = enums.CryptoKeyVersion.CryptoKeyVersionState.DISABLED
    version = {'name': crypto_key_primary_version_name, 'state': new_state}
    update_mask = {'paths': ["state"]}

    # Print results
    response = client.kms_client.update_crypto_key_version(version, update_mask)
    demisto.results(f'CryptoKeyVersion {crypto_key_primary_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}.')


def enable_key_command(client: Client, args: Dict[str, Any]) -> None:
    """Enables the primary CroptoKeyVersion of a given CryptoKey.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.

    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)

    crypto_key = client.kms_client.get_crypto_key(crypto_key_name)
    crypto_key_primary_version_name = crypto_key.primary.name

    # Use the KMS API to disable the CryptoKeyVersion.
    new_state = enums.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
    version = {'name': crypto_key_primary_version_name, 'state': new_state}
    update_mask = {'paths': ["state"]}

    # Print results
    response = client.kms_client.update_crypto_key_version(version, update_mask)
    demisto.results(f'CryptoKeyVersion {crypto_key_primary_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}.')


def destroy_key_command(client: Client, args: Dict[str, Any]) -> None:
    """Destroy the primary CryptoKeyVersion of a given CryptoKey.

    Args:
        client(Client): User Client.
        args(Dict): Demisto arguments.

    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)

    crypto_key = client.kms_client.get_crypto_key(crypto_key_name)
    crypto_key_primary_version_name = crypto_key.primary.name

    # Use the KMS API to mark the CryptoKeyVersion for destruction.
    response = client.kms_client.destroy_crypto_key_version(crypto_key_primary_version_name)

    # Print results
    demisto.results(f'CryptoKeyVersion {crypto_key_primary_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}, it will be destroyed in 24h.')


def restore_key_command(client: Client, args: Dict[str, Any]) -> None:
    """Restore the primary CryptoKeyVersion of a given CryptoKey scheduled for destruction.

    Args:
        client(Client): User Client
        args(Dict): Demisto arguments.

    """
    project_id, location_id, key_ring_id, crypto_key_id = demisto_args_extract(client, args)

    # The resource name of the CryptoKey.
    crypto_key_name = client.kms_client.crypto_key_path(project_id, location_id, key_ring_id, crypto_key_id)

    crypto_key = client.kms_client.get_crypto_key(crypto_key_name)
    crypto_key_primary_version_name = crypto_key.primary.name

    # Use the KMS API to restore the CryptoKeyVersion.
    response = client.kms_client.restore_crypto_key_version(crypto_key_primary_version_name)

    # Print results
    demisto.results(f'CryptoKeyVersion {crypto_key_primary_version_name}\'s state has been set to '
                    f'{enums.CryptoKeyVersion.CryptoKeyVersionState(response.state).name}.')


def test_function(client: Client) -> None:
    """Test's user's input:
        for Encrypter, Decrypter, Encrypter/Decrypter Roles - checks Service account json formatting only.
        for Project-Admin and KMS-Admin Roles - checks the Service account json formatting and connection to project.

    Args:
        client(Client): User Client.
    """
    if client.role in ['Project-Admin', 'KMS-Admin']:
        location_path = client.kms_client.location_path(client.project, client.location)
        response = client.kms_client.list_key_rings(location_path)
        if count_rings(response) == 0:
            return_error("No response - please check Project in Google Cloud KMS and Default Location")


def main():
    command = demisto.command()
    LOG(f'{INTEGRATION_NAME}: command is {command}')
    try:
        client = Client(demisto.params())

        if command == 'test-module':
            test_function(client)
            demisto.results('ok')
            sys.exit(0)

        elif command == f'{INTEGRATION_COMMAND_NAME}create-key' and client.role in ['Project-Admin', 'KMS-Admin']:
            results = create_crypto_key_command(client, demisto.args())
            return_outputs(*results)

        elif command == f'{INTEGRATION_COMMAND_NAME}decrypt' and client.role in ['Decrypter', 'Encrypter/Decrypter',
                                                                                 'Project-Admin']:
            results = decrypt_key_command(client, demisto.args())
            demisto.results(f"The text has been decrypted.\nPlaintext: {results}")

        elif command == f'{INTEGRATION_COMMAND_NAME}encrypt' and client.role in ['Encrypter', 'Encrypter/Decrypter',
                                                                                 'Project-Admin']:
            results = encrypt_key_command(client, demisto.args())
            demisto.results(f"The text has been encrypted.\nCiphertext: {results}")

        elif command == f'{INTEGRATION_COMMAND_NAME}get-key':
            results = get_key_command(client, demisto.args())
            return_outputs(*results)

        elif command == f'{INTEGRATION_COMMAND_NAME}update-key' and client.role in ['Project-Admin', 'KMS-Admin']:
            results = update_key_command(client, demisto.args())
            return_outputs(*results)

        elif command == f'{INTEGRATION_COMMAND_NAME}destroy-key-version' and client.role in ['Project-Admin', 'KMS-Admin']:
            destroy_key_version_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}restore-key-version'and client.role in ['Project-Admin', 'KMS-Admin']:
            restore_key_version_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}disable-key-version' and client.role in ['Project-Admin', 'KMS-Admin']:
            disable_key_version_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}enable-key-version' and client.role in ['Project-Admin', 'KMS-Admin']:
            enable_key_version_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}destroy-key' and client.role in ['Project-Admin', 'KMS-Admin']:
            destroy_key_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}restore-key' and client.role in ['Project-Admin', 'KMS-Admin']:
            restore_key_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}disable-key' and client.role in ['Project-Admin', 'KMS-Admin']:
            disable_key_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}enable-key' and client.role in ['Project-Admin', 'KMS-Admin']:
            enable_key_command(client, demisto.args())

        elif command == f'{INTEGRATION_COMMAND_NAME}list-keys' and client.role in ['Project-Admin', 'KMS-Admin']:
            results = list_keys_command(client, demisto.args())
            return_outputs(*results)

        else:
            raise Exception(f"Your Service Account Role does not permit the use of {command} command.")

    except Exception as e:
        return_error(f'{INTEGRATION_NAME}: {str(e)}', e)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

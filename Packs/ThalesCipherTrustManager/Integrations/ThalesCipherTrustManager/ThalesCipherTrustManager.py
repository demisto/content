""" IMPORTS """

import urllib3
from urllib.parse import quote
import demistomock as demisto
import pyzipper

from CommonServerPython import *

from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DATE_FORMAT_NO_MS = '%Y-%m-%dT%H:%M:%SZ'
DATE_FORMAT_HR = '%d %b %Y, %H:%M'

CONTEXT_OUTPUT_PREFIX = "CipherTrust."

GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CACertificate"
EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}ExternalCA"
CSR_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CSR"
AUTHENTICATION_URL_SUFFIX = '/auth/tokens'
CHANGE_PASSWORD_URL_SUFFIX = '/auth/changepw'
USER_MANAGEMENT_GROUPS_URL_SUFFIX = '/usermgmt/groups/'
USER_MANAGEMENT_USERS_URL_SUFFIX = '/usermgmt/users/'
LOCAL_CAS_URL_SUFFIX = '/ca/local-cas/'
EXTERNAL_CAS_URL_SUFFIX = '/ca/external-cas/'
CA_CSR_URL_SUFFIX = '/ca/csr'

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 2000
DEFAULT_LIMIT = 50

PAGE = 'page'
PAGE_SIZE = 'page_size'
LIMIT = 'limit'
GROUP_NAME = 'group_name'
NEW_GROUP_NAME = 'new_group_name'
USER_ID = 'user_id'
CONNECTION = 'connection'
CLIENT_ID = 'client_id'
NAME = 'name'
DESCRIPTION = 'description'
FORCE = 'force'
USERNAME = 'username'
EMAIL = 'email'
GROUPS = 'groups'
EXCLUDE_GROUPS = 'exclude_groups'
AUTH_DOMAIN_NAME = 'auth_domain_name'
ACCOUNT_EXPIRED = 'account_expired'
ALLOWED_AUTH_METHODS = 'allowed_auth_methods'
ALLOWED_CLIENT_TYPES = 'allowed_client_types'
PASSWORD_POLICY = 'password_policy'
RETURN_GROUPS = 'return_groups'
CERTIFICATE_SUBJECT_DN = 'certificate_subject_dn'
EXPIRES_AT = 'expires_at'
IS_DOMAIN_USER = 'is_domain_user'
PREVENT_UI_LOGIN = 'prevent_ui_login'
PASSWORD_CHANGE_REQUIRED = 'password_change_required'
PASSWORD = 'password'
FAILED_LOGINS_COUNT = 'failed_logins_count'
NEW_PASSWORD = 'new_password'
AUTH_DOMAIN = 'auth_domain'
CN = 'cn'
ALGORITHM = 'algorithm'
COPY_FROM_CA = 'copy_from_ca'
DNS_NAMES = 'dns_names'
IP = 'ip'
NAME_FIELDS_RAW_JSON = 'name_fields_raw_json'
NAME_FIELDS_JSON_ENTRY_ID = 'name_fields_json_entry_id'
SIZE = 'size'
SUBJECT = 'subject'
LOCAL_CA_ID = 'local_ca_id'
CHAINED = 'chained'
ISSUER = 'issuer'
STATE = 'state'
CERT = 'cert'
CERT_ENTRY_ID = 'cert_entry_id'
ALLOW_CLIENT_AUTHENTICATION = 'allow_client_authentication'
ALLOW_USER_AUTHENTICATION = 'allow_user_authentication'
DURATION = 'duration'
NOT_AFTER = 'not_after'
NOT_BEFORE = 'not_before'
PARENT_ID = 'parent_id'
CA_ID = 'ca_id'
CSR = 'csr'
CSR_ENTRY_ID = 'csr_entry_id'
PURPOSE = 'purpose'
ID = 'id'
CERT_ID = 'cert_id'
REASON = 'reason'
PARENT = 'parent'
EXTERNAL_CA_ID = 'external_ca_id'
SERIAL_NUMBER = 'serial_number'
EXTERNAL_CERT_ID = 'external_cert_id'
ENCRYPTION_ALGO = 'encryption_algo'
KEY_SIZE = 'key_size'
PRIVATE_KEY_BYTES = 'private_key_bytes'
ENCRYPTION_PASSWORD = 'encryption_password'
PRIVATE_KEY_FILE_PASSWORD = 'private_key_file_password'

GROUP_LIST_KEYS = ['name', 'app_metadata', 'users_count', 'description']
PENDING_LOCAL_CA_KEYS = ['id', 'createdAt', 'name', 'csr', 'subject', 'sha1Fingerprint',
                         'sha256Fingerprint', 'sha512Fingerprint']
LOCAL_CA_KEYS = ['id', 'uri', 'createdAt', 'updatedAt', 'name', 'state', 'serialNumber', 'subject', 'issuer',
                 'notBefore', 'notAfter', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint']
GROUP_LIST_KEYS_HEADERS_MAPPING = {'name': 'Name',
                                   'app_metadata': 'Defined By',
                                   'users_count': 'No. of members',
                                   'description': 'Description'}
GROUP_LIST_KEYS_VALUE_MAPPING = {'app_metadata': lambda x: 'System' if isinstance(x, dict) and x.get(
    'system') else 'User'}

LOCAL_CA_LIST_ACTIVE_KEYS = ['name', 'subject', 'serialNumber', 'notBefore', 'notAfter',
                             'purpose_client_authentication', 'purpose_user_authentication']
LOCAL_CA_LIST_OTHER_KEYS = ['name', 'subject', 'createdAt', 'sha1Fingerprint']
LOCAL_CA_LIST_KEYS_HEADERS_MAPPING = {'name': 'Name', 'subject': 'Subject', 'serialNumber': 'Serial #', 'notBefore': 'Activation',
                                      'notAfter': 'Expiration',
                                      'purpose_client_authentication': 'Client Auth', 'purpose_user_authentication': 'User Auth',
                                      'createdAt': 'Created',
                                      'sha1Fingerprint': 'Fingerprint'}

CERTIFICATE_LIST_KEYS = ['id', 'uri', 'createdAt', 'updatedAt', 'name', 'ca', 'revoked_reason',
                         'revoked_at', 'state', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint', 'serialNumber',
                         'subject', 'issuer', 'notBefore', 'notAfter']

EXTERNAL_CA_KEYS = ['id', 'uri', 'createdAt', 'updatedAt', 'name', 'serialNumber', 'subject', 'issuer',
                    'notBefore', 'notAfter', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint']

EXTERNAL_CA_LIST_KEYS = ['name', 'subject', 'serialNumber', 'notBefore', 'notAfter',
                         'purpose_client_authentication', 'purpose_user_authentication']
EXTERNAL_CA_LIST_KEYS_HEADERS_MAPPING = {'name': 'Name', 'subject': 'Subject', 'serialNumber': 'Serial #',
                                         'notBefore': 'Activation',
                                         'notAfter': 'Expiration',
                                         'purpose_client_authentication': 'Client Auth',
                                         'purpose_user_authentication': 'User Auth',
                                         }

'''CLIENT CLASS'''


class CipherTrustClient(BaseClient):
    """ A client class to interact with the Thales CipherTrust API """

    def __init__(self, username: str, password: str, server_url: str, proxy: bool, verify: bool):
        base_url = urljoin(server_url, '/api/v1')
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        res = self.create_auth_token(username, password)
        self._headers = {'Authorization': f'Bearer {res.get("jwt")}', 'accept': 'application/json'}

    def create_auth_token(self, username: str, password: str):
        return self._http_request(
            method='POST',
            url_suffix=AUTHENTICATION_URL_SUFFIX,
            json_data={
                'grant_type': 'password',
                'username': username,
                'password': password
            },
        )

    def get_group_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            params=params,
        )

    def create_group(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_GROUPS_URL_SUFFIX,
            json_data=request_data,
        )

    def delete_group(self, group_name: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
            return_empty_response=True,
        )

    def update_group(self, group_name: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name)),
            json_data=request_data,
        )

    def add_user_to_group(self, group_name: str, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name))}/users/{user_id}',
        )

    def remove_user_from_group(self, group_name: str, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=f'{urljoin(USER_MANAGEMENT_GROUPS_URL_SUFFIX, quote(group_name))}/users/{user_id}',
            return_empty_response=True,
        )

    def get_users_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=USER_MANAGEMENT_USERS_URL_SUFFIX,
            params=params,
        )

    def get_user(self, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
        )

    def create_user(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=USER_MANAGEMENT_USERS_URL_SUFFIX,
            json_data=request_data,
        )

    def update_user(self, user_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
            json_data=request_data,
        )

    def delete_user(self, user_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(USER_MANAGEMENT_USERS_URL_SUFFIX, user_id),
            return_empty_response=True,
        )

    def change_current_user_password(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=CHANGE_PASSWORD_URL_SUFFIX,
            json_data=request_data,
            return_empty_response=True,
        )

    def create_local_ca(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=LOCAL_CAS_URL_SUFFIX,
            json_data=request_data,
        )

    def get_local_ca_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=LOCAL_CAS_URL_SUFFIX,
            params=params,
        )

    def get_local_ca(self, local_ca_id: str, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            params=params,
        )

    def update_local_ca(self, local_ca_id: str, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            params=params,
        )

    def delete_local_ca(self, local_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id),
            return_empty_response=True,
        )

    def self_sign_local_ca(self, local_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id)}/self-sign',
            json_data=request_data,
        )

    def install_local_ca(self, local_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, local_ca_id)}/install',
            json_data=request_data,
        )

    def issue_certificate(self, ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs',
            json_data=request_data,
        )

    def get_certificates_list(self, ca_id: str, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs',
            params=params,
        )

    def delete_certificate(self, ca_id: str, local_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{local_ca_id}',
            return_empty_response=True,
        )

    def revoke_certificate(self, ca_id: str, cert_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{cert_id}/revoke',
            json_data=request_data,
        )

    def resume_certificate(self, ca_id: str, cert_id: str) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=f'{urljoin(LOCAL_CAS_URL_SUFFIX, ca_id)}/certs/{cert_id}/resume',
        )

    def upload_external_ca(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=EXTERNAL_CAS_URL_SUFFIX,
            json_data=request_data,
        )

    def delete_external_ca(self, external_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
            return_empty_response=True,
        )

    def update_external_ca(self, external_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
            json_data=request_data,
        )

    def get_external_ca_list(self, params: dict) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=EXTERNAL_CAS_URL_SUFFIX,
            params=params,
        )

    def get_external_ca(self, external_ca_id: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
        )

    def create_csr(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=CA_CSR_URL_SUFFIX,
            json_data=request_data,
        )


''' HELPER FUNCTIONS '''


def derive_skip_and_limit_for_pagination(limit_str: Optional[str], page_str: Optional[str], page_size_str: Optional[str]) -> \
        tuple[int, int]:
    """
    Derive the skip and limit values for pagination from the provided arguments, according to Demisto's pagination logic.
    If page is provided, the skip value is calculated as (page - 1) * page_size and the limit value is the page_size.
    Otherwise, the skip value is 0 and the limit value is the provided limit or the default limit if not provided.
    Args:
        limit_str: The limit argument string.
        page_str: The page argument string.
        page_size_str: The page_size argument string.

    Returns:
        A tuple of the skip and limit values.

    Raises:
        ValueError: If the provided page number is invalid or if the page size exceeds the maximum page size.
    """
    if page_str:
        page_from_arg = arg_to_number(page_str)
        if page_from_arg is None:
            raise ValueError(f'Invalid page number: {page_str}')
        page_size_from_arg = arg_to_number(page_size_str)
        page_size: int = page_size_from_arg if page_size_from_arg is not None else DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return (int(page_from_arg) - 1) * page_size, page_size
    limit_from_arg = arg_to_number(limit_str)
    limit: int = limit_from_arg if limit_from_arg is not None else DEFAULT_LIMIT
    return 0, limit


def optional_arg_to_bool(arg: Optional[str]) -> Optional[bool]:
    """
    Convert an optional argument string to a boolean value.
    Args:
        arg: The argument string.
    Returns:
        The boolean value or None if the argument is None.
    """
    return argToBoolean(arg) if arg is not None else arg


def optional_arg_to_datetime_string(arg: Optional[str], date_format: str = DATE_FORMAT) -> Optional[str]:
    """
    Convert an optional argument string to a datetime string.
    Args:
        arg: The argument string.
        date_format: The date format to use.
    Returns:
        The datetime string or None if the argument is None.
    """
    datetime_object = arg_to_datetime(arg)
    return datetime_object.strftime(date_format) if datetime_object is not None else datetime_object


def add_empty_date_param(request_data: dict, argument_value: Optional[str], param_name: str,
                         empty_arg_value: str = "empty"):
    """
    Add an empty date parameter to the request data if the argument value is the agreed upon empty value.
    Args:
        request_data: The request data dictionary.
        argument_value: The argument value.
        param_name: The parameter name.
        empty_arg_value: The value that represents an empty argument.
    """
    if argument_value is not None:
        request_data[param_name] = "" if argument_value == empty_arg_value else optional_arg_to_datetime_string(argument_value)


def add_empty_list_param(request_data: dict, argument_value: Optional[str], param_name: str,
                         empty_arg_value: str = "empty"):
    """
    Add an empty list parameter to the request data if the argument value is the agreed upon empty value.
    Args:
        request_data: The request data dictionary.
        argument_value: The argument value.
        param_name: The parameter name.
        empty_arg_value: The value that represents an empty argument.
    """
    if argument_value is not None:
        request_data[param_name] = [] if argument_value == empty_arg_value else argToList(argument_value)


def add_login_flags(request_data: dict, argument_value: Optional[bool], flag_name: str):
    """
    Add a login flag parameter to the request data in the expected format.
    Args:
        request_data: The request data dictionary.
        argument_value: The argument value.
        flag_name: The flag name.
    """
    if argument_value is None:
        return
    if 'login_flags' not in request_data:
        request_data['login_flags'] = {}
    request_data['login_flags'][flag_name] = argument_value


def optional_safe_load_json(raw_json_string: Optional[str], json_entry_id: Optional[str]) -> dict:
    """
    Load a JSON object from a raw JSON string or a JSON file entry ID.
    Args:
        raw_json_string: The raw JSON string.
        json_entry_id: The JSON file entry ID.
    Returns:
        The JSON object.
    Raises:
        ValueError: If both the raw JSON string and the JSON file entry ID are provided.
    """
    if raw_json_string and json_entry_id:
        raise ValueError('Only one of raw json string or json file entry id should be provided.')
    json_object = json_entry_id if json_entry_id else raw_json_string
    if json_object:
        return safe_load_json(json_object)
    return {}


def load_content_from_file(entry_id: str) -> str:
    """
    Load the content of a file from the entry ID.
    Args:
        entry_id: The entry
    Returns:
        The content of the file.
    Raises:
        ValueError: If the file could not be loaded.
    """
    try:
        path = demisto.getFilePath(entry_id)
        with open(path.get('path')) as file:
            return file.read().replace('\\n', '\n')
    except Exception as e:
        raise ValueError(f'Failed to load the file {entry_id}: {str(e)}')


def format_pem_string(pem_str: str | bytes):
    """
    Format a PEM certificate string by ensuring each line ends with a newline character.

    Args:
    pem_str (str): A PEM formatted certificate string without explicit newlines.

    Returns:
    str: A properly formatted PEM certificate with newlines.
    """
    # lines = pem_str.split('\n')
    # formatted_pem = '\n'.join(line for line in lines if line) + '\n'
    # print
    #
    # return formatted_pem
    return pem_str


def return_file_results(data: list[str] | str | bytes, filenames: list[str] | str, is_pem=True):
    """
    Return the file results to the context.
    Args:
        data: The file data.
        filenames: The file names.
    Raises:
        ValueError: If the filenames and data are not of the same type and length.
    """
    if isinstance(data, list) and isinstance(filenames, list) and len(data) == len(filenames):
        file_results = []
        for idx, file_data in enumerate(data):
            if not file_data:
                continue
            if is_pem:
                file_data = format_pem_string(file_data)
            file_results.append(fileResult(filenames[idx], file_data, EntryType.ENTRY_INFO_FILE))
        return_results(file_results)

    elif isinstance(data, str) or isinstance(data, bytes) and isinstance(filenames, str):
        return_results(fileResult(filenames, format_pem_string(data) if is_pem else data, EntryType.ENTRY_INFO_FILE))
    else:
        raise ValueError('filenames and data should be of the same type and length.')


def remove_key_from_outputs(outputs: dict[str, Any], keys: list[str] | str) -> tuple[dict[str, Any], list[str] | str]:
    """
    Remove a key or a list of keys from the outputs dictionary.
    Args:
        outputs: The outputs dictionary.
        keys: The key or list of keys to remove.
    Returns:
        A tuple of the new outputs dictionary and the removed values.
    """
    new_outputs = outputs.copy()
    if isinstance(keys, list):
        removed_values = []
        for _idx, key in enumerate(keys):
            removed_values.append(new_outputs.pop(key, ''))
    else:
        removed_values = new_outputs.pop(keys, None)

    return new_outputs, removed_values


def zip_file_with_password(input_file_path: str, password: str, output_file_path: str):
    """
    Zip a file with a password.
    Args:
        input_file_path: The input file path.
        password: The password.
        output_file_path: The output file path.
    """
    compression = pyzipper.ZIP_DEFLATED
    encryption = pyzipper.WZ_AES
    with pyzipper.AESZipFile(output_file_path, mode='w', compression=compression, encryption=encryption) as zf:
        zf.pwd = bytes(password, 'utf-8')
        zf.write(output_file_path)
    zf.close()


def create_zip_protected_file(zip_filename: str, filename: str, data: str, password: str):
    """
    Create a zip file with a password.
    Args:
        zip_filename: The zip file name.
        filename: The file name.
        data: The data to write to the file.
        password: The password.
    """
    with open(filename, 'wb') as f:
        f.write(data.encode('utf-8'))
    zip_file_with_password(filename, password, zip_filename)
    os.remove(filename)


def return_password_protected_zip_file_result(zip_filename: str, filename: str, data: str, password: str):
    """
    Return a password protected zip file result to the context.
    Args:
        zip_filename: The zip file name.
        filename: The file name.
        data: The data to write to the file.
        password: The password.
    """
    zip_filename = f'{zip_filename}.zip'
    create_zip_protected_file(zip_filename, filename, data, password)
    with open(zip_filename, 'rb') as f:
        file_data = f.read()
    return_file_results(file_data, zip_filename)


def hr_skip_limit_to_markdown(skip: int, limit: int, total: int, name: str) -> str:
    """
    Create a human-readable string for the skip, limit, and total values.
    Args:
        skip: The skip value.
        limit: The limit value.
        total: The total value.
        name: The name of the resource.
    Returns:
        The human-readable string.
    """
    start = skip + 1
    to_bring = skip + limit
    end = to_bring if to_bring < total else total
    return f'{start} to {end} of {total} {name}'


def date_to_markdown(iso_date: Optional[str], empty_value: str = '') -> str:
    """
    Convert an ISO date to a human-readable date string.
    Args:
        iso_date: The ISO date.
        empty_value: The value to return if the date is empty.
    Returns:
        The human-readable date string.

    """
    if not iso_date:
        return empty_value
    try:
        return datetime.strptime(iso_date, DATE_FORMAT).strftime(DATE_FORMAT_HR)
    except ValueError:
        return datetime.strptime(iso_date, DATE_FORMAT_NO_MS).strftime(DATE_FORMAT_HR)


def ciphertrust_table_to_markdown_transform_data(data: dict, keys: list[str], keys_headers_mapping: dict,
                                                 keys_value_mapping: dict) -> dict:
    """
    Transform the data for the table to markdown function.
    Args:
        data: The data dictionary.
        keys: The keys to include.
        keys_headers_mapping: The keys headers mapping.
        keys_value_mapping: The keys value mapping.
    Returns:
        The transformed data dictionary.
    """
    transformed_data = {}
    for k in keys:
        v = data.get(k, '')
        transform_func = keys_value_mapping.get(k)
        if transform_func:
            transformed_data[k] = transform_func(v)
        if k in keys_headers_mapping:
            transformed_data[keys_headers_mapping.get(k, '')] = transformed_data.pop(k, v)
        else:
            transformed_data[k] = transformed_data.pop(k, v)
    return transformed_data


def ciphertrust_table_to_markdown(title: str, data: list[dict] | dict, keys: list[str],
                                  keys_headers_mapping: dict, keys_value_mapping: dict) -> str:
    """
    Create a markdown table from the data.
    Args:
        title: The title of the table.
        data: The data dictionary or list of dictionaries.
        keys: The keys to include.
        keys_headers_mapping: The keys headers mapping.
        keys_value_mapping: The keys value mapping.
    Returns:
        The markdown table string.
    """
    resources = []
    if isinstance(data, dict):
        if resources := data.get('resources', []):
            skip_limit_total_hr = hr_skip_limit_to_markdown(
                data.get('skip', 0), data.get('limit', 0), data.get('total', 0), title)
            transformed_data = [ciphertrust_table_to_markdown_transform_data(d, keys, keys_headers_mapping, keys_value_mapping)
                                for d in resources]
            t = tableToMarkdown(title, transformed_data, headerTransform=underscoreToCamelCase, sort_headers=False)
        else:
            t = tableToMarkdown(title, ciphertrust_table_to_markdown_transform_data(data, keys, keys_headers_mapping,
                                                                                    keys_value_mapping),
                                headerTransform=underscoreToCamelCase, sort_headers=False)
    else:
        transformed_data = [ciphertrust_table_to_markdown_transform_data(d, keys, keys_headers_mapping, keys_value_mapping) for d
                            in data]
        t = tableToMarkdown(title, transformed_data, headerTransform=underscoreToCamelCase, sort_headers=False)
    if resources:
        return t + '\n' + skip_limit_total_hr
    return t


def hr_local_ca(raw_response: dict[str, Any]) -> str:
    """
    Create a human-readable string for a local CA.
    Args:
        raw_response: The raw response.
    Returns:
        The human-readable string.

    """
    state = raw_response.get('state', '')
    keys = {
        'active': LOCAL_CA_KEYS,
        'pending': PENDING_LOCAL_CA_KEYS
    }.get(state, LOCAL_CA_LIST_OTHER_KEYS)
    hr_title = raw_response.get('subject', '')
    return ciphertrust_table_to_markdown(hr_title, data=raw_response, keys=keys, keys_headers_mapping={}, keys_value_mapping={})


def hr_external_ca_list(raw_response: dict[str, Any]) -> str:
    """
    Create a human-readable string for a list of external CAs.
    Args:
        raw_response: The raw response.
    Returns:
        The human-readable string.
    """
    keys_value_mapping = {'notBefore': date_to_markdown,
                          'notAfter': date_to_markdown,
                          'purpose_user_authentication': lambda x: 'Enabled' if x else 'Disabled',
                          'purpose_client_authentication': lambda x: 'Enabled' if x else 'Disabled'}
    for ca in raw_response.get('resources', []):
        ca_copy = ca.copy()
        if purpose := ca_copy.pop('purpose', {}):
            ca_copy['purpose_user_authentication'] = purpose.get('user_authentication')
            ca_copy['purpose_client_authentication'] = purpose.get('client_authentication')
    return ciphertrust_table_to_markdown('External Certificate Authorities', data=raw_response,
                                         keys=EXTERNAL_CA_LIST_KEYS,
                                         keys_headers_mapping=EXTERNAL_CA_LIST_KEYS_HEADERS_MAPPING,
                                         keys_value_mapping=keys_value_mapping)


def hr_local_ca_list(raw_response: dict[str, Any]) -> str:
    """
    Create a human-readable string for a list of local CAs.
    Args:
        raw_response: The raw response.
    Returns:
        The human-readable string.
    """

    keys_value_mapping = {'notBefore': date_to_markdown,
                          'notAfter': date_to_markdown,
                          'createdAt': date_to_markdown,
                          'purpose_user_authentication': lambda x: 'Enabled' if x else 'Disabled',
                          'purpose_client_authentication': lambda x: 'Enabled' if x else 'Disabled'}

    active_cas, pending_cas, expired_cas = [], [], []
    for ca in raw_response.get('resources', []):
        ca_copy = ca.copy()
        if purpose := ca_copy.pop('purpose', {}):
            ca_copy['purpose_user_authentication'] = purpose.get('user_authentication')
            ca_copy['purpose_client_authentication'] = purpose.get('client_authentication')
        if ca_copy.get('state') == 'active':
            active_cas.append(ca_copy)
        elif ca_copy.get('state') == 'pending':
            pending_cas.append(ca_copy)
        elif ca_copy.get('state') == 'expired':
            expired_cas.append(ca_copy)

    hr_title = '### Local Certificate Authorities \n'
    hr_skip_limit_title = hr_skip_limit_to_markdown(raw_response.get('skip', 0), raw_response.get('limit', 0),
                                                    raw_response.get('total', 0), 'Local '
                                                                                  'CAs')
    active_cas_hr = ciphertrust_table_to_markdown(
        'Active CAs', active_cas, LOCAL_CA_LIST_ACTIVE_KEYS, LOCAL_CA_LIST_KEYS_HEADERS_MAPPING, keys_value_mapping)
    pending_cas_hr = ciphertrust_table_to_markdown('Pending CAs', pending_cas, LOCAL_CA_LIST_OTHER_KEYS,
                                                   LOCAL_CA_LIST_KEYS_HEADERS_MAPPING,
                                                   keys_value_mapping)
    expired_cas_hr = ciphertrust_table_to_markdown('Expired CAs', expired_cas, LOCAL_CA_LIST_OTHER_KEYS,
                                                   LOCAL_CA_LIST_KEYS_HEADERS_MAPPING,
                                                   keys_value_mapping)

    return f'{hr_title}{active_cas_hr}\n{pending_cas_hr}\n{expired_cas_hr}\n{hr_skip_limit_title}'


''' COMMAND FUNCTIONS '''


def test_module(client: CipherTrustClient) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``CipherTrustClient``
    :param client: CipherTrust client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    client.get_group_list(params={})
    return 'ok'


def group_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    skip, limit = derive_skip_and_limit_for_pagination(args.get(LIMIT),
                                                       args.get(PAGE),
                                                       args.get(PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        name=args.get(GROUP_NAME),
        users=args.get(USER_ID),
        connection=args.get(CONNECTION),
        clients=args.get(CLIENT_ID)
    )
    raw_response = client.get_group_list(params=params)
    keys_value_mapping = {'app_metadata': lambda x: 'System' if isinstance(x, dict) and x.get('system') else 'User'}
    hr = ciphertrust_table_to_markdown('Groups', data=raw_response,
                                       keys=GROUP_LIST_KEYS,
                                       keys_headers_mapping=GROUP_LIST_KEYS_HEADERS_MAPPING,
                                       keys_value_mapping=keys_value_mapping,
                                       )

    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response.get('resources'),
        raw_response=raw_response,
        readable_output=hr
    )


def group_create_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(name=args.get(NAME),
                                 description=args.get(DESCRIPTION))
    raw_response = client.create_group(request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=f'{args.get(NAME)} has been created successfully!'
    )


def group_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(force=optional_arg_to_bool(args.get(FORCE)))
    client.delete_group(group_name=args.get(GROUP_NAME, ''),
                        request_data=request_data)
    return CommandResults(
        readable_output=f'{args.get(GROUP_NAME)} has been deleted successfully!'
    )


def group_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(description=args.get(DESCRIPTION),
                                 name=args.get(NEW_GROUP_NAME))
    raw_response = client.update_group(
        group_name=args.get(GROUP_NAME, ''),
        request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=f'{args.get(GROUP_NAME)} has been updated successfully!'
    )


def user_to_group_add_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    raw_response = client.add_user_to_group(group_name=args.get(GROUP_NAME, ''),
                                            user_id=args.get(USER_ID, ''))
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=f'{args.get(USER_ID)} has been added successfully to {args.get(GROUP_NAME)}'
    )


def user_to_group_remove_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.remove_user_from_group(group_name=args.get(GROUP_NAME, ''),
                                  user_id=args.get(USER_ID, ''))
    return CommandResults(
        readable_output=f'{args.get(USER_ID)} has been deleted successfully from '
                        f'{args.get(GROUP_NAME)}'
    )


def users_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if user_id := args.get(USER_ID):
        raw_response = client.get_user(user_id=user_id)
        outputs = raw_response
        hr_title = outputs.get('username', '')

    else:
        skip, limit = derive_skip_and_limit_for_pagination(args.get(LIMIT),
                                                           args.get(PAGE),
                                                           args.get(PAGE_SIZE))
        params = assign_params(
            skip=skip,
            limit=limit,
            name=args.get(NAME),
            username=args.get(USERNAME),
            email=args.get(EMAIL),
            groups=args.get(GROUPS),
            exclude_groups=args.get(EXCLUDE_GROUPS),
            auth_domain_name=args.get(AUTH_DOMAIN_NAME),
            account_expired=optional_arg_to_bool(args.get(ACCOUNT_EXPIRED)),
            allowed_auth_methods=args.get(ALLOWED_AUTH_METHODS),
            allowed_client_types=args.get(ALLOWED_CLIENT_TYPES),
            password_policy=args.get(PASSWORD_POLICY),
            return_groups=optional_arg_to_bool(args.get(RETURN_GROUPS)), )
        raw_response = client.get_users_list(params=params)
        outputs = raw_response.get('resources', [])
        hr_title = 'Users'
    hr = ciphertrust_table_to_markdown(hr_title, data=raw_response,
                                       keys=['username', 'name', 'email', 'created_at', 'updated_at', 'expires_at', 'user_id',
                                             'last_login', 'logins_count', 'last_failed_login_at', 'password_changed_at',
                                             'password_change_required'],
                                       keys_headers_mapping={'username': 'Username',
                                                             'name': 'Full Name',
                                                             'email': 'Email',
                                                             'created_at': 'Created',
                                                             'updated_at': 'Updated',
                                                             'expires_at': 'Expires', 'user_id': 'ID', 'last_login': 'Last Login',
                                                             'logins_count': 'Logins',
                                                             'last_failed_login_at': 'Last Failed Login',
                                                             'password_changed_at': 'Password Changed',
                                                             'password_change_required': 'Password Change Required'},

                                       keys_value_mapping={'expires_at': lambda x: date_to_markdown(x, 'Never'),
                                                           'last_login': lambda x: date_to_markdown(x,
                                                                                                    'Never Logged In'),
                                                           'last_failed_login_at':
                                                               lambda x: date_to_markdown(x, 'Never Failed A Login'),
                                                           'password_changed_at': date_to_markdown,
                                                           'created_at': date_to_markdown,
                                                           'updated_at': date_to_markdown,
                                                           }
                                       )

    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def user_create_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        certificate_subject_dn=args.get(CERTIFICATE_SUBJECT_DN),
        connection=args.get(CONNECTION),
        email=args.get(EMAIL),
        is_domain_user=optional_arg_to_bool(args.get(IS_DOMAIN_USER)),
        name=args.get(NAME),
        password=args.get(PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(PASSWORD_POLICY),
        user_id=args.get(USER_ID),
        username=args.get(USERNAME),
    )
    add_empty_date_param(request_data, args.get(EXPIRES_AT), "expires_at")
    add_empty_list_param(request_data, args.get(ALLOWED_AUTH_METHODS), "allowed_auth_methods")
    add_empty_list_param(request_data, args.get(ALLOWED_CLIENT_TYPES), "allowed_client_types")
    add_login_flags(request_data, optional_arg_to_bool(args.get(PREVENT_UI_LOGIN)), "prevent_ui_login")
    raw_response = client.create_user(request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=f'{args.get(USERNAME)} has been created successfully!'
    )


def user_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        certificate_subject_dn=args.get(CERTIFICATE_SUBJECT_DN),
        email=args.get(EMAIL),
        failed_logins_count=arg_to_number(args.get(FAILED_LOGINS_COUNT)),
        name=args.get(NAME),
        password=args.get(PASSWORD),
        password_change_required=optional_arg_to_bool(args.get(PASSWORD_CHANGE_REQUIRED)),
        password_policy=args.get(PASSWORD_POLICY),
        username=args.get(USERNAME),
    )
    add_empty_date_param(request_data, args.get(EXPIRES_AT), "expires_at")
    add_empty_list_param(request_data, args.get(ALLOWED_AUTH_METHODS), "allowed_auth_methods")
    add_empty_list_param(request_data, args.get(ALLOWED_CLIENT_TYPES), "allowed_client_types")
    add_login_flags(request_data, optional_arg_to_bool(args.get(PREVENT_UI_LOGIN)), "prevent_ui_login")
    raw_response = client.update_user(user_id=args.get(USER_ID, ''),
                                      request_data=request_data)
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=f'{args.get(USER_ID)} has been updated successfully!'
    )


def user_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_user(user_id=args.get(USER_ID, ''))
    return CommandResults(
        readable_output=f'{args.get(USER_ID)} has been deleted successfully!'
    )


def user_password_change_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        new_password=args.get(NEW_PASSWORD),
        password=args.get(PASSWORD),
        username=args.get(USERNAME),
        auth_domain=args.get(AUTH_DOMAIN)
    )
    client.change_current_user_password(request_data=request_data)
    return CommandResults(
        readable_output=f'Password has been changed successfully for {args.get(USERNAME)}!'
    )


def local_ca_create_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        cn=args.get(CN),
        algorithm=args.get(ALGORITHM),
        copy_from_ca=args.get(COPY_FROM_CA),
        dnsNames=argToList(args.get(DNS_NAMES)),
        emailAddresses=argToList(args.get(EMAIL)),
        ipAddresses=argToList(args.get(IP)),
        name=args.get(NAME),
        names=optional_safe_load_json(args.get(NAME_FIELDS_RAW_JSON),
                                      args.get(NAME_FIELDS_JSON_ENTRY_ID)),
        size=arg_to_number(args.get(SIZE)),
    )
    raw_response = client.create_local_ca(request_data=request_data)
    outputs, csr = remove_key_from_outputs(raw_response, 'csr')
    return_file_results(csr, 'CSR.pem')

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'Pending Local CA {args.get(CN)} has been created successfully!'
    )


def local_ca_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if args.get(CHAINED) is not None and args.get(LOCAL_CA_ID) is None:
        raise ValueError('The "chained" argument can only be used with the "local_ca_id" argument.')

    if local_ca_id := args.get(
            LOCAL_CA_ID):  # filter by local_ca_id if provided, in other words - get a single local CA
        params = assign_params(
            chained=optional_arg_to_bool(args.get(CHAINED)),
        )
        raw_response = client.get_local_ca(local_ca_id=local_ca_id, params=params)
        outputs, removed_values = remove_key_from_outputs(raw_response, ['csr', 'cert'])
        return_file_results(removed_values, ['CSR.pem', 'Certificate.pem'])
        return CommandResults(
            outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
            outputs=outputs,
            raw_response=raw_response,
            readable_output=hr_local_ca(raw_response),
        )

    skip, limit = derive_skip_and_limit_for_pagination(args.get(LIMIT),
                                                       args.get(PAGE),
                                                       args.get(PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        subject=args.get(SUBJECT),
        issuer=args.get(ISSUER),
        state=args.get(STATE),
        cert=args.get(CERT),
    )
    raw_response = client.get_local_ca_list(params=params)

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=[remove_key_from_outputs(local_ca_entry, ['csr', 'cert'])[0] for local_ca_entry in
                 raw_response.get('resources', [])],
        raw_response=raw_response,
        readable_output=hr_local_ca_list(raw_response),
    )


def local_ca_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    params = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_local_ca(local_ca_id=args.get(LOCAL_CA_ID, ''),
                                          params=params)
    outputs, removed_values = remove_key_from_outputs(raw_response, ['csr', 'cert'])
    return_file_results(removed_values, ['CSR.pem', 'Certificate.pem'])

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(LOCAL_CA_ID)} has been updated successfully!'

    )


def local_ca_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_local_ca(local_ca_id=args.get(LOCAL_CA_ID, ''))
    return CommandResults(
        readable_output=f'{args.get(LOCAL_CA_ID)} has been deleted successfully!'
    )


def local_ca_self_sign_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if args.get(NOT_AFTER) is None and args.get(DURATION) is None:
        raise ValueError('Either the "not_after" or "duration" argument must be provided.')
    request_data = assign_params(
        duration=arg_to_number(args.get(DURATION)),
        notAfter=optional_arg_to_datetime_string(args.get(NOT_AFTER)),
        notBefore=optional_arg_to_datetime_string(args.get(NOT_BEFORE)),
    )
    raw_response = client.self_sign_local_ca(local_ca_id=args.get(LOCAL_CA_ID, ''),
                                             request_data=request_data)
    outputs, removed_values = remove_key_from_outputs(raw_response, ['csr', 'cert'])
    return_file_results(removed_values, ['CSR.pem', 'Certificate.pem'])

    return CommandResults(
        outputs_prefix=CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(LOCAL_CA_ID)} has been self-signed successfully!'
    )


def local_ca_install_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    cert = load_content_from_file(args.get(CERT_ENTRY_ID, ''))
    request_data = assign_params(
        cert=cert,
        parentId=args.get(PARENT_ID),
    )
    raw_response = client.install_local_ca(
        local_ca_id=args.get(LOCAL_CA_ID, ''),
        request_data=request_data)
    outputs, removed_values = remove_key_from_outputs(raw_response, ['csr', 'cert'])
    return_file_results(removed_values, ['CSR.pem', 'Certificate.pem'])

    return CommandResults(
        outputs_prefix=CA_INSTALL_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(LOCAL_CA_ID)} has been installed successfully!'
    )


def certificate_issue_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if args.get(NOT_AFTER) is None and args.get(DURATION) is None:
        raise ValueError('Either the "not_after" or "duration" argument must be provided.')
    csr = load_content_from_file(args.get(CSR_ENTRY_ID, ''))
    request_data = assign_params(
        csr=csr,
        purpose=args.get(PURPOSE),
        duration=arg_to_number(args.get(DURATION)),
        name=args.get(NAME),
        notAfter=optional_arg_to_datetime_string(args.get(NOT_AFTER)),
        notBefore=optional_arg_to_datetime_string(args.get(NOT_BEFORE)),
    )
    raw_response = client.issue_certificate(ca_id=args.get(CA_ID, ''),
                                            request_data=request_data)
    outputs, cert = remove_key_from_outputs(raw_response, 'cert')
    return_file_results(cert, 'Certificate.pem')
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{raw_response.get(NAME)} has been issued successfully!'
    )


def certificate_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    skip, limit = derive_skip_and_limit_for_pagination(args.get(LIMIT),
                                                       args.get(PAGE),
                                                       args.get(PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        subject=args.get(SUBJECT),
        issuer=args.get(ISSUER),
        cert=args.get(CERT),
        id=args.get(ID),
    )
    raw_response = client.get_certificates_list(ca_id=args.get(CA_ID, ''),
                                                params=params)
    if args.get(ID):
        issued_certificate_dict = raw_response.get('resources', [])[0] if raw_response.get('resources', []) else {}
        outputs, removed_values = remove_key_from_outputs(issued_certificate_dict, ['csr', 'cert'])
        return_file_results(removed_values[1], 'Certificate.pem')
    else:
        outputs = [remove_key_from_outputs(certificate, ['csr', 'cert'])[0] for certificate in
                   raw_response.get('resources', [])]

    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=ciphertrust_table_to_markdown(title=f'Certificates issued by {args.get(CA_ID, "")}',
                                                      data=raw_response,
                                                      keys=CERTIFICATE_LIST_KEYS,
                                                      keys_headers_mapping={},
                                                      keys_value_mapping={}),
    )


def local_certificate_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_certificate(ca_id=args.get(CA_ID, ''),
                              local_ca_id=args.get(LOCAL_CA_ID, ''))
    return CommandResults(
        readable_output=f'{args.get(LOCAL_CA_ID)} has been deleted successfully!'
    )


def certificate_revoke_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        reason=args.get(REASON),
    )
    raw_response = client.revoke_certificate(ca_id=args.get(CA_ID, ''),
                                             cert_id=args.get(CERT_ID, ''),
                                             request_data=request_data)
    outputs, cert = remove_key_from_outputs(raw_response, 'cert')
    return_file_results(cert, 'Certificate.pem')

    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(CERT_ID)} has been revoked'
    )


def certificate_resume_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    raw_response = client.resume_certificate(ca_id=args.get(CA_ID, ''),
                                             cert_id=args.get(CERT_ID, ''))
    outputs, cert = remove_key_from_outputs(raw_response, 'cert')
    return_file_results(cert, 'Certificate.pem')
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(CERT_ID)} has been resumed'
    )


def external_ca_upload_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    cert = load_content_from_file(args.get(CERT_ENTRY_ID, ''))
    request_data = assign_params(
        cert=cert,
        name=args.get(NAME),
        parent=args.get(PARENT),
    )
    raw_response = client.upload_external_ca(request_data=request_data)
    outputs, cert = remove_key_from_outputs(raw_response, 'cert')
    return_file_results(cert, 'Certificate.pem')
    print(f'{args.get(NAME)} has been uploaded successfully!')
    print(outputs)
    return CommandResults(
        outputs_prefix=EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{raw_response.get(NAME)} has been uploaded successfully!'
    )


def external_ca_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_external_ca(external_ca_id=args.get(EXTERNAL_CA_ID, ''))
    return CommandResults(
        readable_output=f'{args.get(EXTERNAL_CA_ID)} has been deleted successfully!'
    )


def external_ca_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_external_ca(external_ca_id=args.get(EXTERNAL_CA_ID, ''),
                                             request_data=request_data)
    outputs, cert = remove_key_from_outputs(raw_response, 'cert')
    return_file_results(cert, 'Certificate.pem')
    return CommandResults(
        outputs_prefix=EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(EXTERNAL_CA_ID)} has been updated successfully!'
    )


def external_ca_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if external_ca_id := args.get(EXTERNAL_CA_ID):
        raw_response = client.get_external_ca(external_ca_id=external_ca_id)
        outputs, cert = remove_key_from_outputs(raw_response, 'cert')
        return_file_results(cert, 'Certificate.pem')
        return CommandResults(
            outputs_prefix=EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX,
            outputs=outputs,
            raw_response=raw_response,
            readable_output=ciphertrust_table_to_markdown(raw_response.get('subject', ''),
                                                          data=raw_response,
                                                          keys=EXTERNAL_CA_KEYS,
                                                          keys_headers_mapping={},
                                                          keys_value_mapping={}),
        )

    skip, limit = derive_skip_and_limit_for_pagination(args.get(LIMIT),
                                                       args.get(PAGE),
                                                       args.get(PAGE_SIZE))
    params = assign_params(
        skip=skip,
        limit=limit,
        subject=args.get(SUBJECT),
        issuer=args.get(ISSUER),
        serialNumber=args.get(SERIAL_NUMBER),
        cert=args.get(CERT),
    )

    raw_response = client.get_external_ca_list(params=params)

    return CommandResults(
        outputs_prefix=EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=[remove_key_from_outputs(external_ca_entry, ['cert'])[0]
                 for external_ca_entry in raw_response.get('resources', [])],
        raw_response=raw_response,
        readable_output=hr_external_ca_list(raw_response),
    )


def csr_generate_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if not args.get(ENCRYPTION_PASSWORD) and not args.get(PRIVATE_KEY_FILE_PASSWORD):
        raise ValueError('Either the "encryption_password" or "private_key_file_password" argument must be provided. '
                         'The private key must be stored securely on the client side')
    request_data = assign_params(
        cn=args.get(CN),
        algorithm=args.get(ALGORITHM),
        dnsNames=argToList(args.get(DNS_NAMES)),
        emailAddresses=argToList(args.get(EMAIL)),
        encryptionAlgo=args.get(ENCRYPTION_ALGO),
        ipAddresses=argToList(args.get(IP)),
        name=args.get(NAME),
        names=optional_safe_load_json(args.get(NAME_FIELDS_RAW_JSON),
                                      args.get(NAME_FIELDS_JSON_ENTRY_ID)),
        password=args.get(ENCRYPTION_PASSWORD),
        privateKeyBytes=args.get(PRIVATE_KEY_BYTES),
        size=arg_to_number(args.get(KEY_SIZE)),
    )
    raw_response = client.create_csr(request_data=request_data)
    outputs, csr = remove_key_from_outputs(raw_response, 'csr')
    return_file_results(csr, 'CSR.pem')
    if private_key_file_password := args.get(PRIVATE_KEY_FILE_PASSWORD):
        return_password_protected_zip_file_result('privateKey', 'privateKey.pem', outputs.pop('key', ''),
                                                  private_key_file_password)
    else:
        _, private_key = remove_key_from_outputs(raw_response, 'key')
        return_file_results(private_key, 'privateKey.pem')

    return CommandResults(
        outputs_prefix=CSR_CONTEXT_OUTPUT_PREFIX,
        readable_output=f'CSR and its corresponding private key have been generated successfully for {args.get(CN)}.',
    )


''' MAIN FUNCTION '''


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get('server_url')

    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    verify = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    commands = {
        'ciphertrust-group-list': group_list_command,
        'ciphertrust-group-create': group_create_command,
        'ciphertrust-group-delete': group_delete_command,
        'ciphertrust-group-update': group_update_command,
        'ciphertrust-user-to-group-add': user_to_group_add_command,
        'ciphertrust-user-to-group-remove': user_to_group_remove_command,
        'ciphertrust-users-list': users_list_command,
        'ciphertrust-user-create': user_create_command,
        'ciphertrust-user-update': user_update_command,
        'ciphertrust-user-delete': user_delete_command,
        'ciphertrust-user-password-change': user_password_change_command,
        'ciphertrust-local-ca-create': local_ca_create_command,
        'ciphertrust-local-ca-list': local_ca_list_command,
        'ciphertrust-local-ca-update': local_ca_update_command,
        'ciphertrust-local-ca-delete': local_ca_delete_command,
        'ciphertrust-local-ca-self-sign': local_ca_self_sign_command,
        'ciphertrust-local-ca-install': local_ca_install_command,
        'ciphertrust-certificate-issue': certificate_issue_command,
        'ciphertrust-certificate-list': certificate_list_command,
        'ciphertrust-local-certificate-delete': local_certificate_delete_command,
        'ciphertrust-certificate-revoke': certificate_revoke_command,
        'ciphertrust-certificate-resume': certificate_resume_command,
        'ciphertrust-external-ca-upload': external_ca_upload_command,
        'ciphertrust-external-ca-delete': external_ca_delete_command,
        'ciphertrust-external-ca-update': external_ca_update_command,
        'ciphertrust-external-ca-list': external_ca_list_command,
        'ciphertrust-csr-generate': csr_generate_command,
    }

    try:
        client = CipherTrustClient(
            username=username,
            password=password,
            server_url=server_url,
            verify=verify,
            proxy=proxy)

        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
        demisto.error(traceback.format_exc())
        return_error(message=msg, error=str(e))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

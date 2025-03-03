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

CONTEXT_OUTPUT_PREFIX = "CipherTrust"

GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.CACertificate"
EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.ExternalCA"
CSR_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}.CSR"
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


def derive_skip_and_limit_for_pagination(limit: Optional[str], page: Optional[str], page_size: Optional[str]) -> tuple[int, int]:
    """
    Derive the skip and limit values for pagination from the provided arguments, according to Demisto's pagination logic.
    If page is provided, the skip value is calculated as (page - 1) * page_size and the limit value is the page_size.
    Otherwise, the skip value is 0 and the limit value is the provided limit or the default limit if not provided.
    Args:
        limit (str): The limit argument.
        page (str): The page argument.
        page_size (str): The page_size argument.

    Returns:
        A tuple of the skip and limit values.

    Raises:
        ValueError: If the provided page number is invalid or if the page size exceeds the maximum page size.
    """
    if page:
        page_from_arg = arg_to_number(page)
        if page_from_arg is None:
            raise ValueError(f'Invalid page number: {page}')
        page_size_from_arg = arg_to_number(page_size)
        size = page_size_from_arg if page_size_from_arg is not None else DEFAULT_PAGE_SIZE
        if size > MAX_PAGE_SIZE:
            raise ValueError(f'Page size cannot exceed {MAX_PAGE_SIZE}')
        return (int(page_from_arg) - 1) * size, size
    limit_from_arg = arg_to_number(limit)
    return 0, limit_from_arg if limit_from_arg is not None else DEFAULT_LIMIT


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


def add_empty_date_param(request_data: dict, argument_value: Optional[str], param_name: str):
    """
    Add an empty date parameter to the request data if the argument value is the agreed upon empty value.
    Args:
        request_data: The request data dictionary.
        argument_value: The argument value.
        param_name: The parameter name.
    """
    if argument_value is not None:
        request_data[param_name] = "" if argument_value == "never" else optional_arg_to_datetime_string(argument_value)


def add_empty_list_param(request_data: dict, argument_value: Optional[str], param_name: str):
    """
    Add an empty list parameter to the request data if the argument value is the agreed upon empty value.
    Args:
        request_data: The request data dictionary.
        argument_value: The argument value.
        param_name: The parameter name.
    """
    if argument_value is not None:
        request_data[param_name] = [] if argument_value == "none" else argToList(argument_value)


def add_prevent_ui_login(request_data: dict, argument_value: Optional[bool]):
    """
    Add a login flag parameter to the request data in the expected format.
    Args:
        request_data: The request data dictionary.
        argument_value: The argument value.
    """
    if argument_value is not None:
        request_data['login_flags'] = {}
        request_data['login_flags']['prevent_ui_login'] = argument_value


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
            # Since the file is read as a string, and the '\n' is escaped as '\\n'
            return file.read().replace('\\n', '\n')
    except Exception as e:
        raise ValueError(f'Failed to load the file {entry_id}: {str(e)}')


def remove_key_from_outputs(outputs: dict[str, Any], keys: list[str] | str) -> tuple[dict[str, Any], list[str | Any] | str | Any]:
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
        for key in keys:
            removed_values.append(new_outputs.pop(key, ''))
    else:
        removed_values = new_outputs.pop(keys, '')

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
        zf.write(input_file_path)


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
    return_results(fileResult(zip_filename, file_data, EntryType.ENTRY_INFO_FILE))


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


def local_ca_markdown(raw_response: dict[str, Any]) -> str:
    """
    Create a human-readable string for a local CA.
    Args:
        raw_response: The raw response.
    Returns:
        The human-readable string.

    """
    state = raw_response.get('state', '')
    keys = {
        'active': ['id', 'uri', 'createdAt', 'updatedAt', 'name', 'state', 'serialNumber', 'subject', 'issuer',
                   'notBefore', 'notAfter', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint'],
        'pending': ['id', 'createdAt', 'name', 'csr', 'subject', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint']
    }.get(state, ['name', 'subject', 'createdAt', 'sha1Fingerprint'])

    return tableToMarkdown(raw_response.get('subject', ''), {key: raw_response.get(key, '') for key in keys},
                           headerTransform=underscoreToCamelCase, sort_headers=False)


'''MARKDOWN FUNCTIONS'''


def group_list_markdown(data: dict) -> str:
    skip_limit_total_hr = hr_skip_limit_to_markdown(data.get('skip', 0),
                                                    data.get('limit', 0),
                                                    data.get('total', 0),
                                                    'Groups')

    transformed_data = [{
        'Name': group.get('name', ''),
        'Defined By': 'System' if group.get('app_metadata', {}).get('system') else 'User',
        'No. of members': group.get('users_count', ''),
        'Description': group.get('description', '')
    } for group in data.get('resources', [])]

    return tableToMarkdown('Groups', transformed_data, headerTransform=underscoreToCamelCase,
                           sort_headers=False) + '\n' + skip_limit_total_hr


def local_ca_list_markdown(raw_response: dict[str, Any]) -> str:
    """
    Create a human-readable string for a list of local CAs.
    Args:
        raw_response: The raw response.
    Returns:
        The human-readable string.
    """

    active_cas = tableToMarkdown(
        'Active CAs',
        [
            {
                'Name': ca.get('name', ''),
                'Subject': ca.get('subject', ''),
                'Serial #': ca.get('serialNumber', ''),
                'Activation': date_to_markdown(ca.get('notBefore', '')),
                'Expiration': date_to_markdown(ca.get('notAfter', '')),
                'Client Auth': 'Enabled' if ca.get('purpose', {}).get('client_authentication') else 'Disabled',
                'User Auth': 'Enabled' if ca.get('purpose', {}).get('user_authentication') else 'Disabled'
            }
            for ca in raw_response.get('resources', [])
            if ca.get('state') == 'active'
        ],
        headerTransform=underscoreToCamelCase,
        sort_headers=False
    )

    pending_cas = tableToMarkdown(
        'Pending CAs',
        [
            {
                'Name': ca.get('name', ''),
                'Subject': ca.get('subject', ''),
                'Created': date_to_markdown(ca.get('createdAt', '')),
                'Fingerprint': ca.get('sha1Fingerprint', '')
            }
            for ca in raw_response.get('resources', [])
            if ca.get('state') == 'pending'
        ],
        headerTransform=underscoreToCamelCase,
        sort_headers=False
    )

    expired_cas = tableToMarkdown(
        'Expired CAs',
        [
            {
                'Name': ca.get('name', ''),
                'Subject': ca.get('subject', ''),
                'Created': date_to_markdown(ca.get('createdAt', '')),
                'Fingerprint': ca.get('sha1Fingerprint', '')
            }
            for ca in raw_response.get('resources', [])
            if ca.get('state') == 'expired'
        ],
        headerTransform=underscoreToCamelCase,
        sort_headers=False
    )

    hr_title = '### Local Certificate Authorities \n'
    hr_skip_limit_title = hr_skip_limit_to_markdown(raw_response.get('skip', 0), raw_response.get('limit', 0),
                                                    raw_response.get('total', 0), 'Local '
                                                                                  'CAs')

    return f'{hr_title}{active_cas}\n{pending_cas}\n{expired_cas}\n{hr_skip_limit_title}'


def certificate_list_markdown(data: dict, title: str) -> str:
    CERTIFICATE_LIST_KEYS = [
        'id', 'uri', 'createdAt', 'updatedAt', 'name', 'ca', 'revoked_reason', 'revoked_at',
        'state', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint', 'serialNumber',
        'subject', 'issuer', 'notBefore', 'notAfter'
    ]
    skip_limit_total_hr = hr_skip_limit_to_markdown(data.get('skip', 0), data.get('limit', 0), data.get('total', 0), title)
    transformed_data = [{key: certificate.get(key, '') for key in CERTIFICATE_LIST_KEYS} for certificate in
                        data.get('resources', [])]
    t = tableToMarkdown(title, transformed_data, headerTransform=underscoreToCamelCase, sort_headers=False)
    return t + '\n' + skip_limit_total_hr


def external_ca_list_markdown(data: dict) -> str:
    skip_limit_total_hr = hr_skip_limit_to_markdown(data.get('skip', 0), data.get('limit', 0), data.get('total', 0),
                                                    'External Certificate Authorities')
    transformed_data = [
        {
            'Name': ca.get('name', ''),
            'Subject': ca.get('subject', ''),
            'Serial #': ca.get('serialNumber', ''),
            'Activation': date_to_markdown(ca.get('notBefore', '')),
            'Expiration': date_to_markdown(ca.get('notAfter', '')),
            'Client Auth': 'Enabled' if ca.get('purpose', {}).get('client_authentication') else 'Disabled',
            'User Auth': 'Enabled' if ca.get('purpose', {}).get('user_authentication') else 'Disabled'
        } for ca in data.get('resources', [])
    ]
    t = tableToMarkdown('External Certificate Authorities', transformed_data, headerTransform=underscoreToCamelCase,
                        sort_headers=False)
    return t + '\n' + skip_limit_total_hr


def external_ca_markdown(data: dict) -> str:
    EXTERNAL_CA_KEYS = ['id', 'uri', 'createdAt', 'updatedAt', 'name', 'serialNumber', 'subject', 'issuer',
                        'notBefore', 'notAfter', 'sha1Fingerprint', 'sha256Fingerprint', 'sha512Fingerprint']
    transformed_ca = {key: data.get(key, '') for key in EXTERNAL_CA_KEYS}

    return tableToMarkdown(data.get('subject', ''), transformed_ca, headerTransform=underscoreToCamelCase, sort_headers=False)


def users_list_markdown(data: dict) -> str:
    skip_limit_total_hr = hr_skip_limit_to_markdown(data.get('skip', 0), data.get('limit', 0), data.get('total', 0), 'Users')
    transformed_data = [
        {
            'Username': user.get('username', ''),
            'Full Name': user.get('name', ''),
            'Email': user.get('email', ''),
            'Created': date_to_markdown(user.get('created_at', '')),
            'Updated': date_to_markdown(user.get('updated_at', '')),
            'Expires': date_to_markdown(user.get('expires_at'), 'Never'),
            'ID': user.get('user_id', ''),
            'Last Login': date_to_markdown(user.get('last_login'), 'Never Logged In'),
            'Logins': user.get('logins_count', ''),
            'Last Failed Login': date_to_markdown(user.get('last_failed_login_at'), 'Never Failed A Login'),
            'Password Changed': date_to_markdown(user.get('password_changed_at', '')),
            'Password Change Required': user.get('password_change_required', '')
        } for user in data.get('resources', [])
    ]
    t = tableToMarkdown('Users', transformed_data, headerTransform=underscoreToCamelCase, sort_headers=False)
    return t + '\n' + skip_limit_total_hr


def user_markdown(data: dict) -> str:
    transformed_user = {
        'Username': data.get('username', ''),
        'Full Name': data.get('name', ''),
        'Email': data.get('email', ''),
        'Created': date_to_markdown(data.get('created_at', '')),
        'Updated': date_to_markdown(data.get('updated_at', '')),
        'Expires': date_to_markdown(data.get('expires_at'), 'Never'),
        'ID': data.get('user_id', ''),
        'Last Login': date_to_markdown(data.get('last_login'), 'Never Logged In'),
        'Logins': data.get('logins_count', ''),
        'Last Failed Login': date_to_markdown(data.get('last_failed_login_at'), 'Never Failed A Login'),
        'Password Changed': date_to_markdown(data.get('password_changed_at', '')),
        'Password Change Required': data.get('password_change_required', '')
    }
    return tableToMarkdown(data.get('username', ''), transformed_user, headerTransform=underscoreToCamelCase, sort_headers=False)


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
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response.get('resources'),
        raw_response=raw_response,
        readable_output=group_list_markdown(raw_response)
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
        hr = user_markdown(raw_response)

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
        hr = users_list_markdown(raw_response)

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
    add_prevent_ui_login(request_data, optional_arg_to_bool(args.get(PREVENT_UI_LOGIN)))
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
    add_prevent_ui_login(request_data, optional_arg_to_bool(args.get(PREVENT_UI_LOGIN)))
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
    return_results(fileResult('CSR.pem', csr, EntryType.ENTRY_INFO_FILE))

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'Pending Local CA {args.get(CN)} has been created successfully!'
    )


def local_ca_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if args.get(CHAINED) is not None and args.get(LOCAL_CA_ID) is None:
        raise ValueError('The "chained" argument can only be used with the "local_ca_id" argument.')

    if local_ca_id := args.get(LOCAL_CA_ID):  # filter by local_ca_id if provided, in other words - get a single local CA
        params = assign_params(
            chained=optional_arg_to_bool(args.get(CHAINED)),
        )
        raw_response = client.get_local_ca(local_ca_id=local_ca_id, params=params)
        outputs, removed_values = remove_key_from_outputs(raw_response, ['csr', 'cert'])
        for (data, filename) in zip(removed_values, ['CSR.pem', 'Certificate.pem']):
            return_results(fileResult(filename, data, EntryType.ENTRY_INFO_FILE))
        outputs = [outputs]
        hr = local_ca_markdown(raw_response)
    else:

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
        outputs = [remove_key_from_outputs(local_ca_entry, ['csr', 'cert'])[0] for local_ca_entry in
                   raw_response.get('resources', [])]
        hr = local_ca_list_markdown(raw_response)

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def local_ca_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    params = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_local_ca(local_ca_id=args.get(LOCAL_CA_ID, ''),
                                          params=params)
    outputs, removed_values = remove_key_from_outputs(raw_response, ['csr', 'cert'])
    for (data, filename) in zip(removed_values, ['CSR.pem', 'Certificate.pem']):
        return_results(fileResult(filename, data, EntryType.ENTRY_INFO_FILE))

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
    for (data, filename) in zip(removed_values, ['CSR.pem', 'Certificate.pem']):
        return_results(fileResult(filename, data, EntryType.ENTRY_INFO_FILE))

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
    for (data, filename) in zip(removed_values, ['CSR.pem', 'Certificate.pem']):
        return_results(fileResult(filename, data, EntryType.ENTRY_INFO_FILE))

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
    return_results(fileResult('Certificate.pem', cert, EntryType.ENTRY_INFO_FILE))
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
        issued_crtfct_dict = raw_response.get('resources', [])[0] if raw_response.get('resources', []) else {}
        outputs, removed_values = remove_key_from_outputs(issued_crtfct_dict, ['csr', 'cert'])
        for (data, filename) in zip(removed_values, ['CSR.pem', 'Certificate.pem']):
            return_results(fileResult(filename, data, EntryType.ENTRY_INFO_FILE))
        outputs = [outputs]

    else:
        outputs = [remove_key_from_outputs(certificate, ['csr', 'cert'])[0] for certificate in
                   raw_response.get('resources', [])]

    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=certificate_list_markdown(data=raw_response, title=f'Certificates issued by {args.get(CA_ID, "")}')
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
    return_results(fileResult('Certificate.pem', cert, EntryType.ENTRY_INFO_FILE))

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
    return_results(fileResult('Certificate.pem', cert, EntryType.ENTRY_INFO_FILE))
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
    return_results(fileResult('Certificate.pem', cert, EntryType.ENTRY_INFO_FILE))
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
    return_results(fileResult('Certificate.pem', cert, EntryType.ENTRY_INFO_FILE))
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
        return_results(fileResult('Certificate.pem', cert, EntryType.ENTRY_INFO_FILE))
        outputs = [outputs]
        hr = external_ca_markdown(raw_response)

    else:

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
        outputs = [remove_key_from_outputs(external_ca_entry, ['cert'])[0]
                   for external_ca_entry in raw_response.get('resources', [])]
        hr = external_ca_list_markdown(raw_response)

    return CommandResults(
        outputs_prefix=EXTERNAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
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
    return_results(fileResult('CSR.pem', csr, EntryType.ENTRY_INFO_FILE))

    if private_key_file_password := args.get(PRIVATE_KEY_FILE_PASSWORD):
        return_password_protected_zip_file_result('privateKey', 'privateKey.pem', outputs.pop('key', ''),
                                                  private_key_file_password)
    else:
        _, private_key = remove_key_from_outputs(raw_response, 'key')
        return_results(fileResult('privateKey.pem', private_key, EntryType.ENTRY_INFO_FILE))

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

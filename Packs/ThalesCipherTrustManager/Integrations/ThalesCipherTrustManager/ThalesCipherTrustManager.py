""" IMPORTS """

import urllib3
from urllib.parse import quote
import demistomock as demisto
from CommonServerPython import *

from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

CONTEXT_OUTPUT_PREFIX = "CipherTrust."

GROUP_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Group"
USERS_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}Users"
LOCAL_CA_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}LocalCA"
CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CASelfSign"
CA_INSTALL_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CAInstall"
CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}CACertificate"
EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX = f"{CONTEXT_OUTPUT_PREFIX}ExternalCertificate"

AUTHENTICATION_URL_SUFFIX = '/auth/tokens'
CHANGE_PASSWORD_URL_SUFFIX = '/auth/changepw'
USER_MANAGEMENT_GROUPS_URL_SUFFIX = '/usermgmt/groups/'
USER_MANAGEMENT_USERS_URL_SUFFIX = '/usermgmt/users/'
LOCAL_CAS_URL_SUFFIX = '/ca/local-cas/'
EXTERNAL_CAS_URL_SUFFIX = '/ca/external-cas/'

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

'''CLIENT CLASS'''


class CipherTrustClient(BaseClient):
    """ A client class to interact with the Thales CipherTrust API """

    def __init__(self, username: str, password: str, server_url: str, proxy: bool, verify: bool):
        base_url = urljoin(server_url, 'api/v1')
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

    def upload_external_certificate(self, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix=EXTERNAL_CAS_URL_SUFFIX,
            json_data=request_data,
        )

    def delete_external_certificate(self, external_cert_id: str) -> dict[str, Any]:
        return self._http_request(
            method='DELETE',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_cert_id),
            return_empty_response=True,
        )

    def update_external_certificate(self, external_ca_id: str, request_data: dict) -> dict[str, Any]:
        return self._http_request(
            method='PATCH',
            url_suffix=urljoin(EXTERNAL_CAS_URL_SUFFIX, external_ca_id),
            json_data=request_data,
        )

    def get_external_certificates_list(self, params: dict) -> dict[str, Any]:
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


''' HELPER FUNCTIONS '''


def derive_skip_and_limit_for_pagination(limit_str: Optional[str], page_str: Optional[str], page_size_str: Optional[str]) -> \
        tuple[int, int]:
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
    return argToBoolean(arg) if arg is not None else arg


def optional_arg_to_datetime_string(arg: Optional[str], date_format: str = DATE_FORMAT) -> Optional[str]:
    datetime_object = arg_to_datetime(arg)
    return datetime_object.strftime(date_format) if datetime_object is not None else datetime_object


def add_empty_date_param(request_data: dict, argument_value: Optional[str], param_name: str,
                         empty_arg_value: str = "empty") -> None:
    if argument_value is not None:
        request_data[param_name] = "" if argument_value == empty_arg_value else optional_arg_to_datetime_string(argument_value)


def add_empty_list_param(request_data: dict, argument_value: Optional[str], param_name: str,
                         empty_arg_value: str = "empty") -> None:
    if argument_value is not None:
        request_data[param_name] = [] if argument_value == empty_arg_value else argToList(argument_value)


def add_login_flags(request_data: dict, argument_value: Optional[bool], flag_name: str) -> None:
    if argument_value is None:
        return
    if 'login_flags' not in request_data:
        request_data['login_flags'] = {}
    request_data['login_flags'][flag_name] = argument_value


def optional_safe_load_json(raw_json_string: Optional[str], json_entry_id: Optional[str]) -> dict:
    if raw_json_string and json_entry_id:
        raise ValueError('Only one of raw json string or json file entry id should be provided.')
    json_object = json_entry_id if json_entry_id else raw_json_string
    if json_object:
        return safe_load_json(json_object)
    return {}


def load_content_from_file(entry_id: str) -> str:
    try:
        path = demisto.getFilePath(entry_id)
        with open(path.get('path')) as file:
            return file.read()
    except Exception as e:
        raise ValueError(f'Failed to load the file {entry_id}: {str(e)}')


def remove_key_from_outputs(outputs: dict[str, Any], keys: list[str] | str, file_names: Optional[list[str] | str] = None) -> dict[
        str, Any]:
    new_outputs = outputs.copy()
    if isinstance(keys, list):
        if (file_names and not isinstance(file_names, list)) or (file_names and len(file_names) != len(keys)):
            raise ValueError('file_names argument must be a list of the same length if keys argument is a list')
        files_results = []
        for idx, key in enumerate(keys):
            value = new_outputs.pop(key, '')
            if file_names and value:
                files_results.append(fileResult(file_names[idx], value, EntryType.ENTRY_INFO_FILE))
        if file_names:
            return_results(files_results)
    else:
        value = new_outputs.pop(keys, None)
        if file_names:
            if not isinstance(file_names, str):
                raise ValueError('file_names argument must be a string if keys argument is a string')
            if value:
                return_results(fileResult(file_names, value, EntryType.ENTRY_INFO_FILE))
    return new_outputs


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
        readable_output=tableToMarkdown('group', raw_response.get('resources'))
    )


def group_create_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(name=args.get(NAME),
                                 description=args.get(DESCRIPTION))
    raw_response = client.create_group(request_data=request_data)
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
    )


def group_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(force=args.get(FORCE))
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
        raw_response=raw_response
    )


def user_to_group_add_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    raw_response = client.add_user_to_group(group_name=args.get(GROUP_NAME, ''),
                                            user_id=args.get(USER_ID, ''))
    return CommandResults(
        outputs_prefix=GROUP_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response,
        raw_response=raw_response
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
    return CommandResults(
        outputs_prefix=USERS_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown(name='users list',
                                        t=raw_response.get('resources') if raw_response.get('resources') else raw_response),
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
        raw_response=raw_response
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
    outputs = remove_key_from_outputs(raw_response, 'csr', 'CSR.pem')

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response
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
        outputs: object = remove_key_from_outputs(raw_response, ['csr', 'cert'], ['CSR.pem', 'Certificate.pem'])

    else:  # get a list of local CAs with optional filtering
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
        outputs = [remove_key_from_outputs(local_ca_entry, ['csr', 'cert']) for local_ca_entry in
                   raw_response.get('resources', [])]

    return CommandResults(
        outputs_prefix=LOCAL_CA_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown('local CAs', outputs),
    )


def local_ca_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    params = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_local_ca(local_ca_id=args.get(LOCAL_CA_ID, ''),
                                          params=params)
    outputs = remove_key_from_outputs(raw_response, ['csr', 'cert'], ['CSR.pem', 'Certificate.pem'])

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
    outputs = remove_key_from_outputs(raw_response, ['csr', 'cert'], ['CSR.pem', 'Certificate.pem'])

    return CommandResults(
        outputs_prefix=CA_SELF_SIGN_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response
    )


def local_ca_install_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    cert = load_content_from_file(args.get(CERT_ENTRY_ID, ''))
    request_data = assign_params(
        cert=cert,
        parent_id=args.get(PARENT_ID),
    )
    raw_response = client.install_local_ca(
        local_ca_id=args.get(LOCAL_CA_ID, ''),
        request_data=request_data)
    outputs = remove_key_from_outputs(raw_response, ['csr', 'cert'], ['CSR.pem', 'Certificate.pem'])

    return CommandResults(
        outputs_prefix=CA_INSTALL_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response
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
    outputs = remove_key_from_outputs(raw_response, 'cert', 'Certificate.pem')
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response
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
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=raw_response.get('resources'),
        raw_response=raw_response,
        readable_output=tableToMarkdown('certificates',
                                        raw_response.get('resources')),
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
    outputs = remove_key_from_outputs(raw_response, 'cert', 'Certificate.pem')

    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(CERT_ID)} has been revoked'
    )


def certificate_resume_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    raw_response = client.resume_certificate(ca_id=args.get(CA_ID, ''),
                                             cert_id=args.get(CERT_ID, ''))
    outputs = remove_key_from_outputs(raw_response, 'cert', 'Certificate.pem')
    return CommandResults(
        outputs_prefix=CA_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=f'{args.get(CERT_ID)} has been resumed'
    )


def external_certificate_upload_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    cert = load_content_from_file(args.get(CERT_ENTRY_ID, ''))
    request_data = assign_params(
        cert=cert,
        name=args.get(NAME),
        parent=args.get(PARENT),
    )
    raw_response = client.upload_external_certificate(request_data=request_data)
    outputs = remove_key_from_outputs(raw_response, 'cert', 'Certificate.pem')
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=outputs
    )


def external_certificate_delete_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    client.delete_external_certificate(external_cert_id=args.get(EXTERNAL_CERT_ID, ''))
    return CommandResults(
        readable_output=f'{args.get(EXTERNAL_CERT_ID)} has been deleted successfully!'
    )


def external_certificate_update_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    request_data = assign_params(
        allow_client_authentication=optional_arg_to_bool(args.get(ALLOW_CLIENT_AUTHENTICATION)),
        allow_user_authentication=optional_arg_to_bool(args.get(ALLOW_USER_AUTHENTICATION))
    )
    raw_response = client.update_external_certificate(external_ca_id=args.get(EXTERNAL_CA_ID, ''),
                                                      request_data=request_data)
    outputs = remove_key_from_outputs(raw_response, 'cert', 'Certificate.pem')
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response
    )


def external_certificate_list_command(client: CipherTrustClient, args: dict[str, Any]) -> CommandResults:
    if external_ca_id := args.get(EXTERNAL_CA_ID):
        raw_response = client.get_external_ca(external_ca_id=external_ca_id)
        outputs : object = remove_key_from_outputs(raw_response, ['cert'], ['Certificate.pem'])
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

        raw_response = client.get_external_certificates_list(params=params)

        outputs = [remove_key_from_outputs(external_ca_entry, ['cert']) for external_ca_entry in
                   raw_response.get('resources', [])]
    return CommandResults(
        outputs_prefix=EXTERNAL_CERTIFICATE_CONTEXT_OUTPUT_PREFIX,
        outputs=outputs,
        raw_response=raw_response,
        readable_output=tableToMarkdown('external certificates',
                                        outputs),
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

    # todo: pass credentials to the client without opening them up
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
        'ciphertrust-external-certificate-upload': external_certificate_upload_command,
        'ciphertrust-external-certificate-delete': external_certificate_delete_command,
        'ciphertrust-external-certificate-update': external_certificate_update_command,
        'ciphertrust-external-certificate-list': external_certificate_list_command,
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

    except Exception as e:
        msg = f"Exception thrown calling command '{demisto.command()}' {e.__class__.__name__}: {e}"
        demisto.error(traceback.format_exc())
        return_error(message=msg, error=str(e))


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

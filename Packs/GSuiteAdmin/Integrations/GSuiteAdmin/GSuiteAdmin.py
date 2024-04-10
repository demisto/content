from CommonServerPython import *
''' IMPORTS '''

import urllib.parse
import urllib3
import hashlib
import copy
from typing import Any, NamedTuple
from collections.abc import Callable
from GSuiteApiModule import *  # noqa: E402
# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 50

MESSAGES: dict[str, str] = {
    'TEST_FAILED_ERROR': 'Test connectivity failed. Check the configuration parameters provided.',
    'TEST_CONFIGURE_ERROR': ('In order for the test_module to run, an admin_email is required, '
                             'if it is not configured, then each command can receive an admin_email '
                             'argument as an optional argument.'),
    'BOOLEAN_ERROR': 'The argument {} must be either true or false.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'REQUIRED_ARGS_CUSTOM_SCHEMA': 'Argument field_raw_json or field_json_entry_id is required.',
    'CUSTOM_SCHEMA_UPDATE_REQUIRED_ARGS': 'Argument schema_id or schema_name is required.',
    'UNEXPECTED_ERROR': 'An unexpected error occurred.',
    'DATATRANSFER_MISSING_ARGUMENT': 'The argument application_id or applications_raw_json'
                                     ' or application_raw_json_entry_id is required.',
    'DATATRANSFER_TRANSFER_PARAM_FORMAT_ERROR': 'application_transfer_params argument not in expected format. Please '
                                                'provide a comma separated string of format "key1:val;key2:val1,val2"',
    'INVALID_ADMIN_EMAIL': 'Invalid value of argument/parameter Admin Email.',
    'INVALID_RESOURCE_CUSTOMER_ID_ERROR': 'Please check the resource_id and the customer_id arguments.',
    'INVALID_RESOURCE_ID_ERROR': 'Please check the resource_id argument.',
    'INVALID_ORG_UNIT_PATH': 'Please insert a valid organization unit path (org_unit_path)',
    'INVALID_PAGINATION_ARGS_SUPPLIED': ('In order to use pagination, please supply either the argument limit,'
                                         ' or the argument page_token, or the arguments page_token and page_size together.'),
    'EXCEEDED_MAX_PAGE_SIZE_ERROR': f'The maximum page size is {MAX_PAGE_SIZE}',
    'LIMIT_ARG_INVALID_ERROR': 'The limit argument can\'t be negative or equal to zero.',
}

HR_MESSAGES: dict[str, str] = {
    'MOBILE_UPDATE_SUCCESS': 'Mobile device with resource id - {} updated.',
    'MOBILE_DELETE_SUCCESS': 'Mobile device with resource id - {} deleted.',
    'USER_CREATE': 'User Details',
    'LIST_COMMAND_SUCCESS': 'Total Retrieved {}: {}',
    'ALIAS_ADD_SUCCESS': 'Added alias "{}" to user key "{}".',
    'GROUP_CREATE_SUCCESS': 'A new group named "{}" created.',
    'GROUP_GET_SUCCESS': 'Found group named "{}" .',
    'ROLE_ASSIGNMENT_CREATE': 'Role Assignment Details',
    'ROLE_CREATE_PRIVILEGES_INCORRECT_FORMAT': 'role_privileges argument missing or not in expected format. Please '
                                               'provide a comma separated string of form "PrivilegeName1:ServiceId1,'
                                               'PrivilegeName2:ServiceId2".',
    'ROLE_CREATE_SUCCESS': 'A new role created.',
    'TOKEN_REVOKE_SUCCESS': 'All access tokens deleted for {}.',
    'NO_RECORDS': 'No {} found for the given argument(s).',
    'CUSTOM_USER_SCHEMA_CREATE': 'Custom User Schema Details',
    'CUSTOM_USER_SCHEMA_FIELD_DETAILS': 'Field Details',
    'CUSTOM_USER_SCHEMA_UPDATE': 'Updated Custom User Schema Details',
    'DATATRANSFER_REQUEST_CREATE_SUCCESS': 'Data Transfer Details',
    'NOT_FOUND': 'No {} found.',
    'USER_DELETE': 'User with user key {} deleted successfully.',
    'USER_UPDATE': 'Updated User Details',
    'USER_GET': 'Retrieved details for user {}',
    'MOBILE_DEVICES_LIST_SUCCESS': 'Google Workspace Admin - Mobile Devices List',
    'CHROMEOS_DEVICES_LIST_SUCCESS': 'Google Workspace Admin - ChromeOS Devices List',
    'CHROMEOS_DEVICE_ACTION_SUCCESS': 'ChromeOS device with resource id - {} updated.',
    'USER_SIGNOUT_SESSIONS': 'Signs a {} out of all web and device sessions and reset their sign-in cookies.',
    'POLICY_LIST': 'Policy Schemas List',
    'CHROME_BROWSER_LIST': 'Chrome Browser Device List',
    'POLICY_RESOLVE': 'Resolved Policies'
}

URL_SUFFIX: dict[str, str] = {
    'DATA_TRANSFER': 'admin/datatransfer/v1/transfers',
    'USER': 'admin/directory/v1/users',
    'MOBILE_UPDATE': 'admin/directory/v1/customer/{}/devices/mobile/{}/action',
    'MOBILE_DELETE': 'admin/directory/v1/customer/{}/devices/mobile/{}',
    'USER_ALIAS': 'admin/directory/v1/users/{}/aliases',
    'GROUP_CREATE': 'admin/directory/v1/groups',
    'GROUP_GET': 'admin/directory/v1/groups/{}',
    'ROLE_ASSIGNMENT': 'admin/directory/v1/customer/{}/roleassignments',
    'ROLE_CREATE': 'admin/directory/v1/customer/{}/roles',
    'TOKEN_REVOKE': 'admin/directory/v1/users/{}/tokens/{}',
    'CUSTOM_USER_SCHEMA': 'admin/directory/v1/customer/{}/schemas',
    'DATA_TRANSFER_CREATE': 'admin/datatransfer/v1/transfers',
    'MOBILE_DEVICES_LIST': 'admin/directory/v1/customer/{}/devices/mobile',
    'CHROMEOS_DEVICE_ACTION': 'admin/directory/v1/customer/{}/devices/chromeos/{}/action',
    'CHROMEOS_DEVICES_LIST': 'admin/directory/v1/customer/{}/devices/chromeos',
    'USER_SIGN_OUT': 'admin/directory/v1/users/{}/signOut',

}
SCOPES: dict[str, list[str]] = {
    'DIRECTORY_USER': ['https://www.googleapis.com/auth/admin.directory.user'],
    'DEVICE_MOBILE': ['https://www.googleapis.com/auth/admin.directory.device.mobile'],
    'GROUP': ['https://www.googleapis.com/auth/admin.directory.group'],
    'ROLE_MANAGEMENT': ['https://www.googleapis.com/auth/admin.directory.rolemanagement'],
    'USER_SECURITY': ['https://www.googleapis.com/auth/admin.directory.user.security'],
    'DATA_TRANSFER': ['https://www.googleapis.com/auth/admin.datatransfer'],
    'CUSTOM_USER_SCHEMA': ['https://www.googleapis.com/auth/admin.directory.userschema'],
    'CHROME_BROWSERS': ['https://www.googleapis.com/auth/admin.directory.device.chromebrowsers'],
    'POLICY_MANAGEMENT': ['https://www.googleapis.com/auth/chrome.management.policy'],

}

COMMAND_SCOPES: dict[str, list[str]] = {
    'DATA_TRANSFER_LIST': ['https://www.googleapis.com/auth/admin.datatransfer.readonly', *SCOPES['DATA_TRANSFER']],
    'MOBILE_UPDATE': ['https://www.googleapis.com/auth/admin.directory.device.mobile.action'],
    'USER_ALIAS_ADD': ['https://www.googleapis.com/auth/admin.directory.user.alias',
                       'https://www.googleapis.com/auth/admin.directory.user'],
    'ROLE_ASSIGNMENT': ['https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly',
                        *SCOPES['ROLE_MANAGEMENT']],
    'MOBILE_DEVICES_LIST': ['https://www.googleapis.com/auth/admin.directory.device.mobile.readonly'],
    'CHROMEOS_DEVICE_ACTION': ['https://www.googleapis.com/auth/admin.directory.device.chromeos'],
    'CHROMEOS_DEVICES_LIST': ['https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly'],
}

OUTPUT_PREFIX: dict[str, str] = {
    'CREATE_USER': 'GSuite.User',
    'ADD_ALIAS': 'GSuite.UserAlias',
    'GROUP': 'GSuite.Group',
    'ROLE_ASSIGNMENT_LIST': 'GSuite.RoleAssignment(val.roleAssignmentId == obj.roleAssignmentId)',
    'ROLE_ASSIGNMENT_LIST_PAGE_TOKEN': 'GSuite.PageToken.RoleAssignment',
    'ROLE_ASSIGNMENT_CREATE': 'GSuite.RoleAssignment',
    'ROLE': 'GSuite.Role',
    'DATA_TRANSFER_LIST': 'GSuite.DataTransfer(val.id == obj.id)',
    'DATA_TRANSFER_REQUEST_CREATE': 'GSuite.DataTransfer',
    'DATA_TRANSFER_LIST_PAGE_TOKEN': 'GSuite.PageToken.DataTransfer',
    'CUSTOM_USER_SCHEMA': 'GSuite.UserSchema',
    'MOBILE_DEVICES_LIST': 'GSuite.MobileDevices',
    'CHROMEOS_DEVICES_LIST': 'GSuite.ChromeOSDevices',
    'POLICY SCHEMAS': 'GSuite.PolicySchema',
    'CHROME_BROWSERS': 'GSuite.ChromeBrowserDevices',
    'POLICY_RESOLVE': 'GSuite.Policy'
}


# New Classes and Named Tuples
class DevicesCommandConfig(NamedTuple):
    table_headers: list[str]
    table_title: str
    response_devices_list_key: str
    outputs_prefix: str


MobileDevicesConfig = DevicesCommandConfig(table_headers=['Serial Number', 'User Names', 'Model Name', 'OS', 'Type', 'Status'],
                                           table_title=HR_MESSAGES.get('MOBILE_DEVICES_LIST_SUCCESS', ''),
                                           response_devices_list_key='mobiledevices',
                                           outputs_prefix=OUTPUT_PREFIX.get('MOBILE_DEVICES_LIST', ''),
                                           )

ChromeOSDevicesConfig = DevicesCommandConfig(table_headers=['Serial Number', 'User Name', 'Model Name', 'OS', 'Status'],
                                             table_title=HR_MESSAGES.get('CHROMEOS_DEVICES_LIST_SUCCESS', ''),
                                             response_devices_list_key='chromeosdevices',
                                             outputs_prefix=OUTPUT_PREFIX.get('CHROMEOS_DEVICES_LIST', ''),
                                             )


class Client(GSuiteClient):
    '''
        This class is in charge of calling the set_authorized_http function of the GSuiteClient with the required scopes
        and subject (admin_email, which can be as a command argument or integration parameter)
    '''

    def __init__(self, service_account_dict: dict[str, Any], proxy: bool, verify: bool, headers: Optional[dict[str, str]] = None,
                 base_url: str = '', admin_email: str = ''):
        super().__init__(service_account_dict=service_account_dict,
                         base_url=base_url, verify=verify, proxy=proxy,
                         headers=headers)
        self.admin_email = admin_email

    def set_authorized_http(self, scopes: list[str], subject: Optional[str] = None, timeout: int = 60) -> None:
        if not subject:
            subject = self.admin_email
        super().set_authorized_http(scopes=scopes, subject=subject, timeout=timeout)


def return_customer_id(args):
    if not (customer_id := args.get('customer_id') or demisto.params().get('customer_id')):
        raise DemistoException("Missing required customer ID - either provide as an argument or set a parameter")
    return customer_id


def return_file_from_entry_id(entry_id):  # pragma: no cover
    try:
        file_info = demisto.getFilePath(entry_id)

    except Exception as e:
        return_error(f"Failed to get the file path for entry: {entry_id} the error message was {str(e)}")

    file_path = file_info.get("path")

    # Open file and read data
    with open(file_path) as f:  # type: ignore
        dict_list = json.load(f)
    return dict_list


def prepare_output_user_alias_add(alias: dict[str, Any]) -> list[dict[str, Any]]:
    """
    To create context output for gsuite-user-alias-add.

    :param alias: dictionary containing alias information.
    :return: context output list.
    """
    return GSuiteClient.remove_empty_entities({
        'kind': alias.get('kind', ''),
        'id': alias.get('id', ''),
        'etag': alias.get('etag', ''),
        'alias': alias.get('alias', '')
    })


def prepare_args_for_user(args: dict[str, str]) -> dict[str, Any]:
    """
    Prepares and maps argument for gsuite-user-create and gsuite-user-update command.

    :param args: Command arguments.

    :return: Prepared argument dictionary for filter create API.
    """
    GSuiteClient.validate_set_boolean_arg(args, 'is_address_primary')
    GSuiteClient.validate_set_boolean_arg(args, 'is_phone_number_primary')
    GSuiteClient.validate_set_boolean_arg(args, 'suspended')
    GSuiteClient.validate_set_boolean_arg(args, 'archived')
    GSuiteClient.validate_set_boolean_arg(args, 'is_ip_white_listed')
    return GSuiteClient.remove_empty_entities({
        'name': {'familyName': args.get('last_name'),
                 'givenName': args.get('first_name')
                 },
        'password': hashlib.md5(args['password'].encode()).hexdigest() if args.get('password') else None,  # nosec
        'hashFunction': 'MD5' if args.get('password') else None,
        'primaryEmail': args.get('primary_email'),
        'addresses': [{
            'country': args.get('country'),
            'type': args.get('address_type'),
            'postalCode': args.get('postal_code'),
            'primary': args.get('is_address_primary'),
            'extendedAddress': args.get('extended_address'),
            'region': args.get('region', ''),
            'streetAddress': args.get('street_address')
        }],
        'emails': [{
            'address': args.get('secondary_email_address'),
            'type': args.get('secondary_email_type')
        }],
        'gender': {
            'type': args.get('gender')
        },
        'ipWhitelisted': args.get('is_ip_white_listed', ''),
        'notes': {
            'contentType': args.get('notes_content_type', ''),
            'value': args.get('notes_value', ''),
        },
        'phones': [{
            'value': args.get('phone_number'),
            'type': args.get('phone_number_type'),
            'primary': args.get('is_phone_number_primary'),

        }],
        'recoveryEmail': args.get('recovery_email'),
        'recoveryPhone': args.get('recovery_phone'),
        'suspended': args.get('suspended'),
        'archived': args.get('archived'),
        'orgUnitPath': args.get('org_unit_path')
    })


def prepare_output_for_user_command(response: dict[str, Any]) -> dict[str, Any]:
    """
    Prepares output for gsuite-user commands.

    :param response: response from API.

    :return: Prepared output dictionary.
    """
    outputs = {
        'firstName': response.get('name', {}).pop('givenName', ''),
        'fullName': response.get('name', {}).pop('fullName', ''),
        'lastName': response.get('name', {}).pop('familyName', ''),
        'gender': response.pop('gender', {}).get('type', ''),
        'notesValue': response.get('notes', {}).pop('value', ''),
        'notesContentType': response.get('notes', {}).pop('contentType', '')
    }
    outputs.update(response)

    return GSuiteClient.remove_empty_entities(outputs)


def prepare_markdown_from_dictionary(data: dict[str, Any], ignore_fields: list[str] = []) -> str:
    """
    Prepares markdown from dictionary.

    :param data: data directory.
    :param ignore_fields: fields to ignore while preparing mark-down from dictionary.

    :return: data in markdown format.
    """
    hr_cell_info: list[str] = []
    for key, value in data.items():
        if key not in ignore_fields:
            hr_cell_info.append(
                '{}: {}'.format(pascalToSpace(key), ', '.join(value) if isinstance(value, list) else value))
    return '\n'.join(hr_cell_info)


def prepare_readable_output_for_user_command(outputs):
    """
    Prepares readable output for gsuite-user commands.

    :param outputs: output context.

    :return: Prepared readable output dictionary.
    """

    readable_outputs = {
        'addressDetails': prepare_markdown_from_dictionary(
            outputs.pop('addresses', [])[0] if outputs.get('addresses', []) else {}),
        'secondaryEmailDetails': prepare_markdown_from_dictionary(
            outputs.pop('emails', [])[0] if outputs.get('emails', []) else {}),
        'phoneDetails': prepare_markdown_from_dictionary(
            outputs.pop('phones', [])[0] if outputs.get('phones', []) else {}),
    }
    readable_outputs.update(outputs)
    return readable_outputs


def prepare_args_for_role_assignment_list(args: dict[str, str]) -> dict[str, str]:
    """
    Prepares arguments for gsuite-role-assignment-list command.

    :param args: Command arguments.

    :return: Prepared arguments.
    """
    return GSuiteClient.remove_empty_entities({
        'pageToken': args.get('page_token'),
        'roleId': args.get('role_id'),
        'userKey': args.get('user_key'),
        'maxResults': GSuiteClient.validate_get_int(args.get('max_results'),
                                                    MESSAGES['INTEGER_ERROR'].format('max_results'))
    })


def prepare_output_for_role_assignment_list(response: dict[str, Any]) -> dict[str, Any]:
    """
    prepares context output for gsuite-role-assignment-list.

    :param response: API response.

    :return: output dictionary.
    """
    return GSuiteClient.remove_empty_entities({
        OUTPUT_PREFIX['ROLE_ASSIGNMENT_LIST']: response.get('items', []),
        OUTPUT_PREFIX['ROLE_ASSIGNMENT_LIST_PAGE_TOKEN']: {
            'nextPageToken': response['nextPageToken']
        } if response.get('nextPageToken', '') else {}
    })


def prepare_args_for_role_assignment_create(args: dict[str, str]) -> dict[str, str]:
    """
    Prepares arguments for gsuite-role-assignment-create command.

    :param args: Command arguments.

    :return: Prepared arguments.
    """
    return GSuiteClient.remove_empty_entities({
        'orgUnitId': args.get('org_unit_id'),
        'roleId': args.get('role_id'),
        'assignedTo': args.get('assigned_to'),
        'scopeType': args.get('scope_type'),
    })


def get_privileges_list_from_string(privileges: str) -> list[dict[str, str]]:
    """
    Converts string of form privilegeName:serviceId to a list of object containing privilegeName and serviceId keys
    :param privileges: privileges string
    :return: list of privilege objects

    :raises ValueError: if the passed string is empty or not in expected format.
    """
    if privileges and len(privileges) > 2 and ':' in privileges:
        privileges_list = []
        for privilege in privileges.split(','):
            privilege_items = privilege.split(':')
            privileges_list.append({'privilegeName': privilege_items[0], 'serviceId': privilege_items[1]})
        return privileges_list
    else:
        raise ValueError(HR_MESSAGES['ROLE_CREATE_PRIVILEGES_INCORRECT_FORMAT'])


def prepare_args_for_datatransfer_list(args: dict[str, str]) -> dict[str, str]:
    """
    Prepares arguments for gsuite-datatransfer-list command.

    :param args: Command arguments.

    :return: Prepared arguments.
    """
    customer_id = return_customer_id(args)
    return GSuiteClient.remove_empty_entities({
        'customerId': customer_id,
        'maxResults': GSuiteClient.validate_get_int(args.get('max_results'),
                                                    MESSAGES['INTEGER_ERROR'].format('max_results')),
        'newOwnerUserId': args.get('new_owner_user_id'),
        'oldOwnerUserId': args.get('old_owner_user_id'),
        'pageToken': args.get('page_token'),
        'status': args.get('status'),
    })


def prepare_output_for_datatransfer_list(response: dict[str, Any]) -> dict[str, Any]:
    """
    prepares context output for gsuite-datatransfer-list.

    :param response: API response.

    :return: output dictionary.
    """
    return GSuiteClient.remove_empty_entities({
        OUTPUT_PREFIX['DATA_TRANSFER_LIST']: response.get('dataTransfers', []),
        OUTPUT_PREFIX['DATA_TRANSFER_LIST_PAGE_TOKEN']: {
            'nextPageToken': response['nextPageToken'],
        } if response.get('nextPageToken', '') else {}
    })


def prepare_readable_output_for_datatransfer_list(response: dict[str, Any]) -> str:
    """
    prepares readable output for gsuite-datatransfer-list.

    :param response: API response.

    :return: output markdown string.
    """
    readable_output = f'### Next Page Token: {response["nextPageToken"]}\n\n' if response.get("nextPageToken") else ''

    # Formatting applicationDataTransfers list.
    for datatransfer in response.get('dataTransfers', []):
        app_transfer_markdown = ''
        for app_transfer in datatransfer.get('applicationDataTransfers', []):
            app_transfer_markdown += prepare_markdown_from_dictionary(app_transfer,
                                                                      ['applicationTransferParams']) + '\n\n'
        datatransfer['applicationDataTransfers'] = app_transfer_markdown

    readable_output += tableToMarkdown(
        HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Data Transfers',
                                                   len(response.get('dataTransfers', []))),
        response.get('dataTransfers', []),
        ['id', 'oldOwnerUserId', 'newOwnerUserId', 'overallTransferStatusCode', 'requestTime',
         'applicationDataTransfers'],
        headerTransform=pascalToSpace,
        removeNull=True)
    return readable_output


def prepare_args_for_custom_user_schema(args: dict[str, str]) -> dict[str, str]:
    """
    Prepares arguments for gsuite-custom-user-schema-create/update command.

    :param args: Command arguments.

    :return: Prepared arguments.
    :raises ValueError: If required argument(s) are not provided.
    """

    if args.get('field_raw_json'):
        field_json = GSuiteClient.safe_load_non_strict_json(args['field_raw_json'])
    elif args.get('field_json_entry_id'):
        field_json = return_file_from_entry_id(args['field_json_entry_id'])
    else:
        raise ValueError(MESSAGES['REQUIRED_ARGS_CUSTOM_SCHEMA'])

    return GSuiteClient.remove_empty_entities({
        'displayName': args.get('schema_display_name'),
        'schemaName': args.get('schema_name'),
        'schemaId': args.get('schema_id'),
        'fields': field_json.get('fields', [])
    })


def prepare_output_for_custom_user_schema(context_output: dict[str, Any], readable_output: dict[str, Any]) -> None:
    """
    Prepares outputs for custom user schema command.

    :param context_output: Context output dictionary.
    :param readable_output: readable output dictionary.

    :return: None
    """
    for field in readable_output.get('fields', []):
        field['numericIndexingSpec'] = prepare_markdown_from_dictionary(field.pop('numericIndexingSpec', {}))

    for field in context_output.get('fields', []):
        numeric_indexing_spec = field.pop('numericIndexingSpec', {})
        field['numericIndexingSpecMinValue'] = numeric_indexing_spec.get('minValue')
        field['numericIndexingSpecMaxValue'] = numeric_indexing_spec.get('maxValue')


def get_transfer_params_list_from_str(transfer_params_str: str) -> list:
    """
    Extract transfer parameter list from a string of format "key1:val;key2:val1,val2"

    :param transfer_params_str: Transfer parameters string
    :return: Application transfer parameters list.
    :raises ValueError: If the provided string is not in expected format.

    """
    transfer_params = []
    if transfer_params_str:
        try:
            if len(transfer_params_str) < 2 or ':' not in transfer_params_str:
                raise ValueError

            for transfer_param in transfer_params_str.split(';'):
                transfer_params.append({
                    'key': transfer_param.split(':')[0].strip(),
                    'value': transfer_param.split(':')[1].strip().split(',')
                })
        except Exception:
            raise ValueError(MESSAGES['DATATRANSFER_TRANSFER_PARAM_FORMAT_ERROR'])

    return transfer_params


def prepare_datatransfer_payload_from_arguments(args: dict[str, str]) -> dict[str, Any]:
    """
    Prepares datatransfer payload from command arguments dictionary.

    :param args: Command arguments
    :return: Dictionary containing datatransfer request payload.
    """
    transfer_params = get_transfer_params_list_from_str(args.get('application_transfer_params', ''))

    return GSuiteClient.remove_empty_entities({
        'oldOwnerUserId': args.get('old_owner_id'),
        'newOwnerUserId': args.get('new_owner_id'),
        'applicationDataTransfers': [{
            'applicationId': args.get('application_id'),
            'applicationTransferParams': transfer_params
        }]
    })


def is_email_valid(email: str) -> bool:
    """
    Validates provided email is valid or not.

    :param email: email string.
    :return:  True if email is in valid format.
    """

    return bool(re.match(emailRegex, email))


''' COMMAND FUNCTIONS '''


@logger
def test_module(client: Client) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """

    with GSuiteClient.http_exception_handler():
        client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'])
        if client.admin_email:
            client.http_request(url_suffix=f"{URL_SUFFIX['USER']}/{client.admin_email}", method='GET')
        else:
            return_results(MESSAGES.get('TEST_CONFIGURE_ERROR', ''))
    return 'ok'


@logger
def mobile_update_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Takes an action that affects a mobile device. For example, remotely wiping a device.

    :param client: client object used to get response from api
    :param args: command arguments
    :return: CommandResults which returns detailed results to war room and sets the context data.
    """

    client.set_authorized_http(scopes=COMMAND_SCOPES['MOBILE_UPDATE'])
    customer_id = return_customer_id(args)
    args.pop('admin_email', '')
    resource_id = urllib.parse.quote(args.pop('resource_id', ''))
    try:
        client.http_request(
            url_suffix=URL_SUFFIX['MOBILE_UPDATE'].format(urllib.parse.quote(customer_id), resource_id),
            method='POST', body=args)

        return CommandResults(readable_output=HR_MESSAGES['MOBILE_UPDATE_SUCCESS'].format(resource_id))
    except DemistoException as e:
        error_message = str(e)
        if ('Internal error encountered' in error_message or 'Bad Request' in error_message):
            raise DemistoException(MESSAGES.get('INVALID_RESOURCE_CUSTOMER_ID_ERROR', ''))
        raise DemistoException(error_message)


@logger
def mobile_delete_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Removes a mobile device. Note that this does not break the device's sync, it simply removes it from the list of
    devices connected to the domain. If the device still has a valid login/authentication, it will be added back on
    it's next successful sync.

    :param client: client object used to get response from api
    :param args: command arguments
    :return: CommandResults which returns detailed results to war room and sets the context data.
    """
    client.set_authorized_http(scopes=SCOPES['DEVICE_MOBILE'])
    customer_id = return_customer_id(args)
    resource_id = urllib.parse.quote(args.pop('resource_id', ''))
    client.http_request(
        url_suffix=URL_SUFFIX['MOBILE_DELETE'].format(urllib.parse.quote(customer_id), resource_id),
        method='DELETE')

    return CommandResults(readable_output=HR_MESSAGES['MOBILE_DELETE_SUCCESS'].format(resource_id))


@logger
def user_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Creates a user.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    prepared_args = prepare_args_for_user(args)
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'])

    response = client.http_request(url_suffix=URL_SUFFIX['USER'], body=prepared_args, method='POST')

    # Context
    outputs = prepare_output_for_user_command(copy.deepcopy(response))

    # Readable Output
    readable_output_dict = prepare_readable_output_for_user_command(copy.deepcopy(outputs))
    readable_output = tableToMarkdown(HR_MESSAGES['USER_CREATE'], readable_output_dict,
                                      ['id', 'customerId', 'primaryEmail', 'firstName', 'lastName', 'gender',
                                       'suspended', 'notesValue', 'notesContentType', 'isAdmin', 'creationTime',
                                       'phoneDetails',
                                       'addressDetails', 'secondaryEmailDetails', 'ipWhitelisted', 'recoveryEmail',
                                       'recoveryPhone'],
                                      headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX['CREATE_USER'],
                          outputs_key_field=['id'],
                          outputs=outputs, raw_response=response,
                          readable_output=readable_output)


@logger
def role_assignment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Prints all admin role assignments in the G Suite instance.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    arguments = prepare_args_for_role_assignment_list(args)
    customer_id = return_customer_id(args)
    client.set_authorized_http(scopes=COMMAND_SCOPES['ROLE_ASSIGNMENT'])
    response = client.http_request(
        url_suffix=URL_SUFFIX['ROLE_ASSIGNMENT'].format(urllib.parse.quote(customer_id)),
        params=arguments)

    # Context
    outputs = prepare_output_for_role_assignment_list(response)

    # Readable Output
    readable_output = f'### Next Page Token: {response["nextPageToken"]}\n' if response.get("nextPageToken") else ''
    readable_output += tableToMarkdown(
        HR_MESSAGES['LIST_COMMAND_SUCCESS'].format('Role Assignment(s)', len(response.get('items', []))),
        response.get('items', []),
        ['roleAssignmentId', 'roleId', 'assignedTo', 'scopeType', 'orgUnitId'],
        headerTransform=pascalToSpace,
        removeNull=True) if response.get(
        'items') else HR_MESSAGES['NO_RECORDS'].format('role assignment details')

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def role_assignment_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Assigns a role to the customer.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    arguments = prepare_args_for_role_assignment_create(args)
    customer_id = return_customer_id(args)

    client.set_authorized_http(scopes=SCOPES['ROLE_MANAGEMENT'])
    response = client.http_request(
        url_suffix=URL_SUFFIX['ROLE_ASSIGNMENT'].format(urllib.parse.quote(customer_id)),
        body=arguments, method='POST')

    # Readable Output
    readable_output = tableToMarkdown(
        HR_MESSAGES['ROLE_ASSIGNMENT_CREATE'],
        response,
        ['roleAssignmentId', 'roleId', 'assignedTo', 'scopeType', 'orgUnitId'],
        headerTransform=pascalToSpace,
        removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['ROLE_ASSIGNMENT_CREATE'],
        outputs_key_field='roleAssignmentId',
        outputs=GSuiteClient.remove_empty_entities(response),
        readable_output=readable_output,
        raw_response=response
    )


@logger
def user_alias_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Adds an alias.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    user_key = args.get('user_key', '')
    user_key = urllib.parse.quote(user_key)  # type: ignore
    alias = args.get('alias', '')
    # admin_email = ADMIN_EMAIL

    body = {'alias': alias}
    body = GSuiteClient.remove_empty_entities(body)

    client.set_authorized_http(scopes=COMMAND_SCOPES['USER_ALIAS_ADD'])
    response = client.http_request(url_suffix=URL_SUFFIX['USER_ALIAS'].format(user_key), body=body, method='POST')

    outputs = prepare_output_user_alias_add(response)

    readable_output = HR_MESSAGES['ALIAS_ADD_SUCCESS'].format(alias, args.get('user_key', ''))

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['ADD_ALIAS'],
        outputs_key_field=['id', 'alias'],
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def group_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Creates a group with a group name and its description.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    client.set_authorized_http(scopes=SCOPES['GROUP'])
    args.pop('admin_email', '')
    args = {key.replace('group_', ''): value for (key, value) in args.items()}

    response = client.http_request(url_suffix=URL_SUFFIX['GROUP_CREATE'], body=args, method='POST')

    response = GSuiteClient.remove_empty_entities(response)

    hr_output_fields = ['id', 'email', 'description', 'adminCreated']

    readable_output = tableToMarkdown(HR_MESSAGES['GROUP_CREATE_SUCCESS'].format(response['name']),
                                      response, headerTransform=pascalToSpace, removeNull=True,
                                      headers=hr_output_fields)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['GROUP'],
        outputs_key_field='id',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def group_get_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Get a group information with a group key

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    client.set_authorized_http(scopes=SCOPES['GROUP'])
    group_key_suffix = URL_SUFFIX['GROUP_GET'].format(args.pop('group', ''))

    response = client.http_request(
        url_suffix=group_key_suffix, method='GET')

    response = GSuiteClient.remove_empty_entities(response)

    hr_output_fields = ['id', 'email', 'description', 'adminCreated']

    readable_output = tableToMarkdown(HR_MESSAGES['GROUP_GET_SUCCESS'].format(response['name']),
                                      response, headerTransform=pascalToSpace, removeNull=True,
                                      headers=hr_output_fields)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['GROUP'],
        outputs_key_field='id',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def role_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Creates a role with a role name and its description.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """

    client.set_authorized_http(scopes=SCOPES['ROLE_MANAGEMENT'])
    customer_id = return_customer_id(args)

    params = {
        'rolePrivileges': get_privileges_list_from_string(args.pop('role_privileges', '')),
        'roleName': args.get('role_name', ''),
        'roleDescription': args.get('role_description', '')
    }

    response = client.http_request(
        url_suffix=URL_SUFFIX['ROLE_CREATE'].format(urllib.parse.quote(customer_id)), body=params,
        method='POST')

    response = GSuiteClient.remove_empty_entities(response)

    hr_output = {key.replace('role', ''): value for (key, value) in response.items()}

    hr_output['Privileges'] = ",\n".join(
        [privilege['privilegeName'] + ': ' + privilege['serviceId'] for privilege in hr_output.get('Privileges', [])])

    hr_output_fields = ['Id', 'Name', 'Description', 'Privileges']

    readable_output = tableToMarkdown(HR_MESSAGES['ROLE_CREATE_SUCCESS'], hr_output, headerTransform=pascalToSpace,
                                      removeNull=True, headers=hr_output_fields)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['ROLE'],
        outputs_key_field='roleId',
        outputs=response,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def token_revoke_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Delete all access tokens issued by a user for an application.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """

    client.set_authorized_http(scopes=SCOPES['USER_SECURITY'])

    user_key = urllib.parse.quote(args.get('user_key', ''))
    client_id = urllib.parse.quote(args.get('client_id', ''))

    client.http_request(url_suffix=URL_SUFFIX['TOKEN_REVOKE'].format(user_key, client_id), method='DELETE')

    return CommandResults(readable_output=HR_MESSAGES['TOKEN_REVOKE_SUCCESS'].format(args.get('client_id', '')))


@logger
def user_signout_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Signs a user out of all web and device sessions and reset their sign-in cookies.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """

    client.set_authorized_http(scopes=SCOPES['USER_SECURITY'])

    user_key = urllib.parse.quote(args.get('user_key', ''))
    client.http_request(url_suffix=URL_SUFFIX['USER_SIGN_OUT'].format(user_key), method='POST')

    return CommandResults(readable_output=HR_MESSAGES['USER_SIGNOUT_SESSIONS'].format(args.get('user_key', '')))


@logger
def datatransfer_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Lists the transfers for a customer by source user, destination user, or status.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    params = prepare_args_for_datatransfer_list(args)
    client.set_authorized_http(scopes=COMMAND_SCOPES['DATA_TRANSFER_LIST'])
    response = client.http_request(url_suffix=URL_SUFFIX['DATA_TRANSFER'], params=params)

    # Context
    outputs = prepare_output_for_datatransfer_list(response)

    # Readable Output
    readable_output = prepare_readable_output_for_datatransfer_list(copy.deepcopy(response)) if response.get(
        'dataTransfers') else HR_MESSAGES['NO_RECORDS'].format('data transfer details')

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


@logger
def custom_user_schema_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a custom user schema to add custom fields to user profiles.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    body = prepare_args_for_custom_user_schema(args)
    client.set_authorized_http(scopes=SCOPES['CUSTOM_USER_SCHEMA'])
    customer_id = return_customer_id(args)
    response = client.http_request(method='POST',
                                   url_suffix=URL_SUFFIX['CUSTOM_USER_SCHEMA'].format(
                                       urllib.parse.quote(customer_id)),
                                   body=body)

    outputs = copy.deepcopy(response)
    readable_output_dict = copy.deepcopy(response)

    prepare_output_for_custom_user_schema(outputs, readable_output_dict)

    readable_output = f"### {HR_MESSAGES['CUSTOM_USER_SCHEMA_CREATE']}\n"
    readable_output += f"Schema Id: {readable_output_dict.get('schemaId', '')}\n"
    readable_output += f"Schema Name: {readable_output_dict.get('schemaName', '')}\n"
    readable_output += f"Schema Display Name: {readable_output_dict.get('displayName', '')}\n"
    readable_output += tableToMarkdown(
        HR_MESSAGES['CUSTOM_USER_SCHEMA_FIELD_DETAILS'],
        readable_output_dict.get('fields', []),
        ['fieldId', 'fieldName', 'displayName', 'fieldType',
         'readAccessType', 'multiValued', 'indexed', 'numericIndexingSpec'],
        headerTransform=pascalToSpace,
        removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['CUSTOM_USER_SCHEMA'],
        outputs_key_field='schemaId',
        outputs=GSuiteClient.remove_empty_entities(outputs),
        readable_output=readable_output,
        raw_response=GSuiteClient.remove_empty_entities(response)
    )


@logger
def custom_user_schema_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Updates a custom user schema.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    :raise ValueError: If required arguments are not provided.
    """
    if not args.get('schema_id') and not args.get('schema_name'):
        raise ValueError(MESSAGES['CUSTOM_SCHEMA_UPDATE_REQUIRED_ARGS'])
    customer_id = return_customer_id(args)
    body = prepare_args_for_custom_user_schema(args)

    schema_key = args['schema_id'] if args.get('schema_id') else args.get('schema_name', '')

    url_suffix = f"{URL_SUFFIX['CUSTOM_USER_SCHEMA'].format(urllib.parse.quote(customer_id))}" \
                 f"/{urllib.parse.quote(schema_key)}"

    client.set_authorized_http(scopes=SCOPES['CUSTOM_USER_SCHEMA'])
    response = client.http_request(method='PUT',
                                   url_suffix=url_suffix,
                                   body=body)

    outputs = copy.deepcopy(response)
    readable_output_dict = copy.deepcopy(response)

    prepare_output_for_custom_user_schema(outputs, readable_output_dict)

    readable_output = f"### {HR_MESSAGES['CUSTOM_USER_SCHEMA_UPDATE']}\n"
    readable_output += f"Schema Id: {readable_output_dict['schemaId']}\n" if readable_output_dict.get(
        'schemaId', '') else ''
    readable_output += f"Schema Name: {readable_output_dict['schemaName']}\n" if readable_output_dict.get(
        'schemaName', '') else ''
    readable_output += f"Schema Display Name: {readable_output_dict['displayName']}\n" if readable_output_dict.get(
        'displayName', '') else ''
    readable_output += tableToMarkdown(
        HR_MESSAGES['CUSTOM_USER_SCHEMA_FIELD_DETAILS'],
        readable_output_dict.get('fields', []),
        ['fieldId', 'fieldName', 'displayName', 'fieldType',
         'readAccessType', 'multiValued', 'indexed', 'numericIndexingSpec'],
        headerTransform=pascalToSpace,
        removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['CUSTOM_USER_SCHEMA'],
        outputs_key_field='schemaId',
        outputs=GSuiteClient.remove_empty_entities(outputs),
        readable_output=readable_output,
        raw_response=GSuiteClient.remove_empty_entities(response)
    )


@logger
def datatransfer_request_create_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Inserts a data transfer request.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    if not any([args.get('applications_raw_json'), args.get('applications_raw_json_entry_id'),
                args.get('application_id')]):
        raise ValueError(MESSAGES['DATATRANSFER_MISSING_ARGUMENT'])

    app_payload = {}
    if args.get('applications_raw_json'):
        app_payload = GSuiteClient.safe_load_non_strict_json(args['applications_raw_json'])
    elif args.get('applications_raw_json_entry_id'):
        app_payload = return_file_from_entry_id(args['applications_raw_json_entry_id'])

    request_payload = prepare_datatransfer_payload_from_arguments(args)

    if app_payload.get('applicationDataTransfers'):
        request_payload['applicationDataTransfers'] = app_payload['applicationDataTransfers']

    client.set_authorized_http(scopes=SCOPES['DATA_TRANSFER'])

    response = client.http_request(url_suffix=URL_SUFFIX['DATA_TRANSFER_CREATE'], body=request_payload, method='POST')

    hr_output_data = response.copy()

    application_transfer_hr_output = '\n\n'.join(['Application Id: {}\nApplication Transfer Status: {}'.format(
        transfer.get('applicationId', ''), transfer.get('applicationTransferStatus', '')) for transfer in
        response.get('applicationDataTransfers', [])])

    hr_output_data['applicationDataTransfers'] = application_transfer_hr_output

    hr_output = tableToMarkdown(HR_MESSAGES['DATATRANSFER_REQUEST_CREATE_SUCCESS'], hr_output_data,
                                headerTransform=pascalToSpace, removeNull=True,
                                headers=['id', 'oldOwnerUserId', 'newOwnerUserId', 'overallTransferStatusCode',
                                         'requestTime', 'applicationDataTransfers'])

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['DATA_TRANSFER_REQUEST_CREATE'],
        outputs=GSuiteClient.remove_empty_entities(response),
        readable_output=hr_output,
        raw_response=GSuiteClient.remove_empty_entities(response),
        outputs_key_field='id'
    )


@logger
def user_delete_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Deletes a user.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'])
    user_key = args.get('user_key', '')
    url_suffix = f"{URL_SUFFIX['USER']}/{urllib.parse.quote(user_key)}"
    client.http_request(url_suffix=url_suffix, method='DELETE')

    return CommandResults(readable_output=HR_MESSAGES['USER_DELETE'].format(user_key))


@logger
def user_update_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    updates a user.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    prepared_args = prepare_args_for_user(args)
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'])
    user_key = args.get('user_key', '')
    url_suffix = f"{URL_SUFFIX['USER']}/{urllib.parse.quote(user_key)}"
    response = client.http_request(url_suffix=url_suffix, body=prepared_args, method='PUT')

    # Context
    outputs = prepare_output_for_user_command(copy.deepcopy(response))

    # Readable Output
    readable_output_dict = prepare_readable_output_for_user_command(copy.deepcopy(outputs))
    readable_output = tableToMarkdown(HR_MESSAGES['USER_UPDATE'], readable_output_dict,
                                      ['id', 'customerId', 'primaryEmail', 'firstName', 'lastName', 'gender',
                                       'archived', 'suspended',
                                       'orgUnitPath', 'notesValue', 'notesContentType', 'isAdmin', 'creationTime',
                                       'phoneDetails',
                                       'addressDetails', 'secondaryEmailDetails', 'ipWhitelisted', 'recoveryEmail',
                                       'recoveryPhone'],
                                      headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX['CREATE_USER'],
                          outputs_key_field=['id'],
                          outputs=outputs, raw_response=response,
                          readable_output=readable_output)


@logger
def user_get_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    get a user details based on user key.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'])
    user_key = args.get('user', '')
    url_suffix = urljoin(URL_SUFFIX['USER'], urllib.parse.quote(user_key))
    response = client.http_request(url_suffix=url_suffix, method='GET')

    # Context
    outputs = prepare_output_for_user_command(copy.deepcopy(response))

    # Readable Output
    readable_output_dict = prepare_readable_output_for_user_command(copy.deepcopy(outputs))
    readable_output = tableToMarkdown(HR_MESSAGES['USER_GET'].format(user_key), readable_output_dict,
                                      ['id', 'customerId', 'primaryEmail', 'firstName', 'lastName', 'gender',
                                       'archived', 'suspended',
                                       'orgUnitPath', 'notesValue', 'notesContentType', 'isAdmin', 'creationTime',
                                       'phoneDetails',
                                       'addressDetails', 'secondaryEmailDetails', 'ipWhitelisted', 'recoveryEmail',
                                       'recoveryPhone'],
                                      headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX['CREATE_USER'],
                          outputs_key_field=['id'],
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def mobile_device_list_request(client: Client, customer_id: str, query_params: dict = {}):
    response = client.http_request(
        url_suffix=URL_SUFFIX.get('MOBILE_DEVICES_LIST', '').format(urllib.parse.quote(customer_id)),
        params=query_params)
    return response


def chromeos_device_list_request(client: Client, customer_id: str, query_params: dict = {}):
    response = client.http_request(
        url_suffix=URL_SUFFIX.get('CHROMEOS_DEVICES_LIST', '').format(urllib.parse.quote(customer_id)),
        params=query_params)
    return response


def chromeos_device_action_request(client: Client, customer_id: str, resource_id: str, action: str,
                                   deprovision_reason: str = ''):
    json_body = {'action': action}
    if action == 'deprovision':
        json_body['deprovisionReason'] = deprovision_reason
    response = client.http_request(
        method='POST', url_suffix=URL_SUFFIX.get('CHROMEOS_DEVICE_ACTION', '').format(urllib.parse.quote(customer_id),
                                                                                      urllib.parse.quote(resource_id)),
        body=json_body)
    return response


def device_list_automatic_pagination(request_by_device_type: Callable, client, customer_id: str, query_params: dict,
                                     limit: int, response_devices_list_key: str) -> dict:
    """This function implements the automatic pagination mechanism for both commands: mobile-device-list, and chromos-device-list.
    Since the API does not support a `limit` argument, we have to do the automatic pagination manually. If the limit
    argument is smaller than or equal to the maximum page size allowed by the API, then we will only need one request call,
    else, we will make multiple requests by utilizing the `nextPageToken` argument supplied by the API.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        client (Client): A Client instance.
        customer_id (str): The unique ID of the customer's Google Workspace Admin account.
        query_params (dict): The query parameters that will be sent with the API call.
        limit (int): The limit argument that will act as the maximum number of results to return from the API request.
        response_devices_list_key (str): The key that will point to the list of devices in the response body.

    Returns:
        dict: A dictionary that holds all the relevant data for creating a CommandResult.
    """
    results_limit = limit
    devices = []  # This will hold all aggregated mobile devices returned from the API requests
    responses = []  # This will hold all the responses from the API requests
    next_page_token = ''
    continue_pagination = True  # This will decide if we should continue requesting from the API or that we should stop
    while continue_pagination:
        query_params['maxResults'] = results_limit if results_limit <= MAX_PAGE_SIZE else MAX_PAGE_SIZE
        if next_page_token:
            query_params['pageToken'] = next_page_token
        response = request_by_device_type(client=client, customer_id=customer_id, query_params=query_params)
        responses.append(response)
        response_mobile_devices = response.get(response_devices_list_key, [])
        next_page_token = response.get('nextPageToken', '')

        devices.extend(response_mobile_devices)
        results_limit -= len(response_mobile_devices)
        if (results_limit <= 0 or not next_page_token):
            continue_pagination = False
    return {'data': devices, 'raw_response': responses}


def device_list_manual_pagination(request_by_device_type: Callable, client, customer_id: str, query_params: dict,
                                  page_token: str, page_size: int, response_devices_list_key: str) -> dict:
    """This function is in charge of retrieving the data of one page using the page_size and page_token arguments supported
    by the API.

    Args:
        api_request (Callable): The API request that will be used to retrieve the list of devices.
        client (Client): A Client instance.
        customer_id (str): The unique ID of the customer's Google Workspace Admin account.
        query_params (dict): The query parameters that will be sent with the API call.
        page_token (str): The token of the page from where to retrieve the devices.
        page_size (int): The size of the page, which cannot be bigger than the maximum page size (100).
        response_devices_list_key (str): The key that will point to the list of devices in the response body.

    Returns:
        dict: A dictionary that holds all the relevant data for creating a CommandResult.
    """
    query_params['maxResults'] = page_size
    if page_token:
        query_params['pageToken'] = page_token
    response = request_by_device_type(client=client, customer_id=customer_id, query_params=query_params)
    devices = response.get(response_devices_list_key, [])
    return {'data': devices, 'raw_response': [response], 'next_page_token': response.get('nextPageToken', '')}


def prepare_pagination_arguments(page_token: str, page_size: int | None, limit: int | None) -> dict:
    """ The function gets the arguments from the user and checks the content of the pagination arguments,
        and if everything is valid, it returns a dictionary that holds the pagination information.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that holds the pagination information.
    """
    if (page_token or page_size is not None):
        if limit is not None:
            raise DemistoException(MESSAGES.get('INVALID_PAGINATION_ARGS_SUPPLIED'))
        page_size = page_size if (page_size is not None) else DEFAULT_PAGE_SIZE
        if page_size > MAX_PAGE_SIZE:
            raise DemistoException(MESSAGES.get('EXCEEDED_MAX_PAGE_SIZE_ERROR'))
        return {'page_size': page_size, 'page_token': page_token}

    limit = limit if (limit is not None) else DEFAULT_LIMIT
    if (limit <= 0):
        raise DemistoException(message=MESSAGES.get('LIMIT_ARG_INVALID_ERROR'))
    return {'limit': limit}


def mobile_device_list_create_query_parameters(projection: str, query: str, order_by: str,
                                               sort_order: str) -> dict:
    """This function takes in the arguments from the user and creates a dictionary that will hold
    the query arguments for the mobile-device-list request.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that will hold the query arguments of the request.
    """
    query_params = assign_params(projection=projection.lower(),
                                 query=query,
                                 orderBy=order_by.lower(),
                                 sortOrder=sort_order.lower(),
                                 )
    return query_params


def devices_to_human_readable(devices_data: list[dict], keys: list, keys_mapping: dict[str, str]) -> list[dict]:
    human_readable: list[dict] = []
    for device in devices_data:
        human_readable_data = {}
        for key in keys:
            if key in keys_mapping:
                human_readable_data[keys_mapping.get(key)] = device.get(key)
            else:
                human_readable_data[pascalToSpace(key)] = device.get(key)
        human_readable.append(human_readable_data)

    return human_readable


@logger
def gsuite_mobile_device_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Retrieves a paginated list that includes company-owned mobile devices.

    Args:
        client (Client): A Client instance.
        args (Dict[str, str]): The arguments of the command.

    Returns:
        List[CommandResults]: List of CommandResults that hold the data to return to the engine.
    """
    client.set_authorized_http(scopes=COMMAND_SCOPES.get('MOBILE_DEVICES_LIST', []))
    customer_id = return_customer_id(args)
    query_params = mobile_device_list_create_query_parameters(projection=args.get('projection', 'full'),
                                                              query=args.get('query', ''),
                                                              order_by=args.get('order_by', 'status'),
                                                              sort_order=args.get('sort_order', 'ascending'),)
    pagination_args = prepare_pagination_arguments(page_token=args.get('page_token', ''),
                                                   page_size=arg_to_number(args.get('page_size', '')),
                                                   limit=arg_to_number(args.get('limit', '')))
    mutual_pagination_args = assign_params(
        request_by_device_type=mobile_device_list_request,
        client=client,
        customer_id=customer_id,
        response_devices_list_key=MobileDevicesConfig.response_devices_list_key,
        query_params=query_params,
    )
    markdown = ''
    if 'limit' in pagination_args:
        pagination_result = device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)
    else:
        pagination_result = device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
    context_data: list[dict] = pagination_result.get('data', [{}])
    raw_response: list = pagination_result.get('raw_response', [])
    next_page_token: str = pagination_result.get('next_page_token', '')
    if not context_data:
        markdown = 'No results were found with the respected arguments'

    else:
        human_readable = devices_to_human_readable(
            devices_data=context_data,
            keys=['serialNumber', 'name', 'model', 'os', 'type', 'status', 'resourceId'],
            keys_mapping={'name': 'User Names', 'model': 'Model Name', 'os': 'OS'})
        num_of_devices = len(context_data)
        markdown = tableToMarkdown(MobileDevicesConfig.table_title, human_readable,
                                   metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
    outputs: dict[str, Any] = {}
    if context_data:
        outputs[(f'{MobileDevicesConfig.outputs_prefix}.'
                 'MobileListObjects(val.resourceId && val.resourceId == obj.resourceId)')] = context_data
    if next_page_token:
        markdown += f'### Next Page Token:\n{next_page_token}'
        outputs[f'{MobileDevicesConfig.outputs_prefix}.PageToken(val.NextPageToken)'] = {'NextPageToken': next_page_token}

    command_results = CommandResults(
        readable_output=markdown,
        outputs=outputs,
        raw_response=raw_response,
    )

    return command_results


def chromeos_device_list_create_query_parameters(projection: str, query: str, include_child_org_units: bool, order_by: str,
                                                 sort_order: str, org_unit_path: str) -> dict:  # pragma: no cover
    """This function takes in the arguments from the user and creates a dictionary that will hold
    the query arguments for the chromeos-device-list request.

    Args:
        args (dict): The arguments from the user

    Returns:
        dict: A dictionary that will hold the query arguments of the request.
    """
    query_params = assign_params(projection=projection.lower(),
                                 query=query,
                                 orderBy=order_by.lower(),
                                 sortOrder=sort_order.lower(),
                                 orgUnitPath=org_unit_path,
                                 includeChildOrgunits=str(include_child_org_units)
                                 )
    return query_params


@logger
def gsuite_chromeos_device_list_command(client: Client, args: dict[str, str]) -> CommandResults:  # pragma: no cover
    """Retrieves a paginated list that includes company-owned ChromeOS devices.

    Args:
        client (Client): A Client instance.
        args (Dict[str, str]): The arguments of the command.

    Returns:
        List[CommandResults]: List of CommandResults that hold the data to return to the engine.
    """
    client.set_authorized_http(scopes=COMMAND_SCOPES.get('CHROMEOS_DEVICES_LIST', []))
    customer_id = return_customer_id(args)
    query_params = chromeos_device_list_create_query_parameters(projection=args.get('projection', 'full'),
                                                                query=args.get('query', ''),
                                                                include_child_org_units=argToBoolean(args.get(
                                                                    'include_child_org_units', False)),
                                                                order_by=args.get('order_by', ''),
                                                                sort_order=args.get('sort_order', ''),
                                                                org_unit_path=args.get('org_unit_path', ''),
                                                                )
    pagination_args = prepare_pagination_arguments(page_token=args.get('page_token', ''),
                                                   page_size=arg_to_number(args.get('page_size', '')),
                                                   limit=arg_to_number(args.get('limit', '')))
    mutual_pagination_args = assign_params(
        request_by_device_type=chromeos_device_list_request,
        client=client,
        customer_id=customer_id,
        response_devices_list_key=ChromeOSDevicesConfig.response_devices_list_key,
        query_params=query_params,
    )
    try:
        markdown = ''
        if 'limit' in pagination_args:
            pagination_result = device_list_automatic_pagination(**mutual_pagination_args, **pagination_args)
        else:
            pagination_result = device_list_manual_pagination(**mutual_pagination_args, **pagination_args)
        context_data: list[dict] = pagination_result.get('data', [{}])
        raw_response: list = pagination_result.get('raw_response', [])
        next_page_token: str = pagination_result.get('next_page_token', '')
        if not context_data:
            markdown = 'No results were found with the respected arguments'

        else:
            human_readable = devices_to_human_readable(
                devices_data=context_data,
                keys=['serialNumber', 'annotatedUser', 'model', 'osVersion', 'status', 'deviceId'],
                keys_mapping={'annotatedUser': 'User Name', 'osVersion': 'OS'})
            num_of_devices = len(context_data)
            markdown = tableToMarkdown(ChromeOSDevicesConfig.table_title, human_readable,
                                       metadata=f'{num_of_devices} {"results" if num_of_devices != 1 else "result"} found')
        outputs: dict[str, Any] = {}
        if context_data:
            outputs[(f'{ChromeOSDevicesConfig.outputs_prefix}.'
                     'ChromeOSListObjects(val.resourceId && val.resourceId == obj.resourceId)')] = context_data

        if next_page_token:
            markdown += f'### Next Page Token:\n{next_page_token}'
            outputs[f'{ChromeOSDevicesConfig.outputs_prefix}.PageToken(val.NextPageToken)'] = {'NextPageToken': next_page_token}

        command_results = CommandResults(
            readable_output=markdown,
            outputs=outputs,
            raw_response=raw_response,
        )
        return command_results
    except DemistoException as e:
        error_message = str(e)
        if ('INVALID_OU_ID' in error_message):
            raise DemistoException(MESSAGES.get('INVALID_ORG_UNIT_PATH', ''))
        raise DemistoException(error_message)


@logger
def gsuite_chromeos_device_action_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Executes an action that affects a ChromeOS Device.

    Args:
        client (Client): A Client instance.
        args (Dict[str, str]): The arguments of the command.

    Raises:
        DemistoException: If customer_id or resource_id are invalid.

    Returns:
        CommandResults: CommandResults that hold the data to return to the engine.
    """
    try:
        client.set_authorized_http(scopes=COMMAND_SCOPES.get('CHROMEOS_DEVICE_ACTION', []))
        customer_id = return_customer_id(args)
        chromeos_device_action_request(client=client, customer_id=customer_id,
                                       resource_id=args.get('resource_id', ''),
                                       action=args.get('action', ''),
                                       deprovision_reason=args.get('deprovision_reason', ''))

    except DemistoException as e:
        error_message = str(e)
        if ('Delinquent account' in error_message):
            raise DemistoException(MESSAGES.get('INVALID_RESOURCE_CUSTOMER_ID_ERROR', ''))
        raise DemistoException(error_message)
    command_results = CommandResults(
        readable_output=HR_MESSAGES.get('CHROMEOS_DEVICE_ACTION_SUCCESS', '').format(args.get('resource_id')),
    )
    return command_results


def user_reset_password_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
        reset to user password based on given user_key (email)

        :param client: Client object.
        :param args: Command arguments.

        :return: Command Result.
    """
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'])
    user_key = args.get('user_key', '')
    url_suffix = urljoin(URL_SUFFIX['USER'], urllib.parse.quote(user_key))
    body = {"changePasswordAtNextLogin": True}
    response = client.http_request(url_suffix=url_suffix, method='PUT', body=body)

    # Context
    outputs = prepare_output_for_user_command(copy.deepcopy(response))
    # Output
    readable_output = tableToMarkdown(HR_MESSAGES['USER_UPDATE'].format(user_key), outputs,
                                      ['id', 'customerId', 'primaryEmail', 'changePasswordAtNextLogin'],
                                      headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX['CREATE_USER'],
                          outputs_key_field=['id'],
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def chromebrowser_move_ou_command(client: Client, args: dict[str, str]) -> str:
    """
        Move Chrome Browser devices assigned to an account from one organization unit to another

        :param client: Client object.
        :param args: Command arguments - customer_id, resource_ids, org_unit_path - required.

        :return: Message for user upon success
    """
    client.set_authorized_http(scopes=SCOPES['CHROME_BROWSERS'])
    customer_id = return_customer_id(args)
    resource_ids_list = argToList(args.get('resource_ids', ''))
    org_unit_path = args.get('org_unit_path', '')
    full_url = f'https://www.googleapis.com/admin/directory/v1.1beta1/customer/{customer_id}' \
               f'/devices/chromebrowsers/moveChromeBrowsersToOu'
    body = {"resource_ids": resource_ids_list, "org_unit_path": org_unit_path}
    client.http_request(full_url=full_url, method='POST', body=body)

    # Output
    return f'Chrome browser devices have been moved to the new organization unit {org_unit_path}'


def assign_params_chromebrowser_list(projection, query, order_by, sort_order, org_u_path, page_t, page_s):
    return GSuiteClient.remove_empty_entities({
        'projection': projection,
        'query': query,
        'orderBy': order_by,
        'sortOrder': sort_order,
        'orgUnitPath': org_u_path,
        'pageToken': page_t,
        'maxResults': page_s
    })


def chromebrowser_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    '''
        List chromebrowsers devices

        :param client: Client object.
        :param args: Command arguments - customer_id (reqyired), device_id, order_by, org_unit_path, projection, query,
         sort_order, page_size and limit
        :return: Command Result.
    '''
    API_LIMIT = 100
    client.set_authorized_http(scopes=SCOPES['CHROME_BROWSERS'])
    customer_id = return_customer_id(args)
    device_id = args.get('device_id', '')
    order_by = args.get('order_by', '')
    org_unit_path = args.get('org_unit_path', '')
    projection = args.get('projection', '')
    query = args.get('query', '')
    sort_order = args.get('sort_order', '')
    page_size = args.get('page_size', '')
    page_token = args.get('page_token', '')
    limit = args.get('limit', '')

    full_url = f'https://www.googleapis.com/admin/directory/v1.1beta1/customer/{customer_id}/devices/chromebrowsers/'
    cb_list_resp = []
    if device_id:
        full_url = full_url + f'{device_id}'
        params_for_command = GSuiteClient.remove_empty_entities({
            'projection': projection
        })
        response = client.http_request(full_url=full_url, method='GET', params=params_for_command)
        cb_list_resp.append(response)
    else:
        if page_size or page_token:
            if not page_size:
                page_size = str(DEFAULT_PAGE_SIZE)
            if int(page_size) > API_LIMIT:
                page_size = str(API_LIMIT)
            params_for_command = assign_params_chromebrowser_list(projection, query, order_by, sort_order, org_unit_path,
                                                                  page_token, page_size)
            response = client.http_request(full_url=full_url, method='GET', params=params_for_command)
            page_token = response.get('nextPageToken', '')
            cb_list_resp.extend(response.get('browsers', ''))
        else:
            while len(cb_list_resp) < int(limit):
                if int(limit) - len(cb_list_resp) > API_LIMIT:
                    page_size = str(API_LIMIT)
                else:
                    page_size = str(int(limit) - len(cb_list_resp))
                params_for_command = assign_params_chromebrowser_list(projection, query, order_by, sort_order, org_unit_path,
                                                                      page_token, page_size)
                response = client.http_request(full_url=full_url, method='GET', params=params_for_command)
                page_token = response.get('nextPageToken', '')
                cb_list_resp.extend(response.get('browsers', ''))  # type: ignore
                if not page_token:
                    break

    readable_output = tableToMarkdown(HR_MESSAGES['CHROME_BROWSER_LIST'].format(device_id), cb_list_resp,
                                      ['deviceId', 'osPlatform', 'osVersion', 'machineName', 'serialNumber', 'orgUnitPath'],
                                      headerTransform=pascalToSpace, removeNull=True)
    outputs = {
        'GSuite.ChromeBrowserDevices(val.deviceId && val.deviceId == obj.deviceId)':
            cb_list_resp,
        'GSuite(true)': {'ChromeBrowserNextToken': page_token}
    }
    return CommandResults(outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def modify_policy_command(client: Client, args: dict[str, str]) -> str:
    """
        get a user details based on user key.

        :param client: Client object.
        :param args: Command arguments.

        :return: String that confirms request was executed.
    """
    client.set_authorized_http(scopes=SCOPES['POLICY_MANAGEMENT'])
    customer_id = return_customer_id(args)
    target_type = args.get('target_type', '')
    policy_raw_json = args.get('policy_raw_json', '')
    policy_field_json_entry_id = args.get('policy_field_json_entry_id', '')
    target_resource = args.get('target_resource', '')
    additional_target_keys = args.get('additional_target_keys', '')
    policy_schema = args.get('policy_schema', '')
    policy_value = args.get('policy_value', '')
    update_mask = args.get('update_mask', '')

    if target_type == 'Group':
        full_url = f'https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/groups:batchModify'
        target_resource_customized = f'groups/{target_resource}'
    else:
        full_url = f'https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/orgunits:batchModify'
        target_resource_customized = f'orgunits/{target_resource}'

    if additional_target_keys:
        atk_dict = json.loads(additional_target_keys)
    else:
        atk_dict = {}

    if policy_raw_json:
        app_payload = GSuiteClient.safe_load_non_strict_json(policy_raw_json)
    elif policy_field_json_entry_id:
        app_payload = return_file_from_entry_id(policy_field_json_entry_id)
    else:
        app_payload = {
            "requests": [
                {
                    "policyTargetKey":
                    {
                        "targetResource": target_resource_customized,
                        "additionalTargetKeys": atk_dict
                    },
                    "policyValue": {
                        "policySchema": policy_schema,
                        "value": {
                            "appInstallType": policy_value
                        }
                    },
                    "updateMask": update_mask
                }
            ]
        }

    client.http_request(full_url=full_url, method='POST', body=app_payload)

    # Output
    return f'Policy has been modified for the customer {customer_id}'


def policy_resolve_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
        resolve the provided policy and return its details

        :param client: Client object.
        :param args: Command arguments.

        :return: Command Result.
    """
    API_LIMIT = 1000
    client.set_authorized_http(scopes=SCOPES['POLICY_MANAGEMENT'])
    customer_id = return_customer_id(args)
    target_type = args.get('target_type', '')
    policy_schema_filter = args.get('policy_schema_filter', '')
    target_resource = args.get('target_resource', '')
    additional_target_keys = args.get('additional_target_keys', '')
    page_size = args.get('page_size', '')
    page_token = args.get('page_token', '')
    limit = args.get('limit', '')

    if additional_target_keys:
        atk_dict = json.loads(additional_target_keys)
    else:
        atk_dict = {}

    if target_type == 'Group':
        target_resource_customized = f'groups/{target_resource}'
    else:
        target_resource_customized = f'orgunits/{target_resource}'

    app_payload = {
        "policySchemaFilter": policy_schema_filter,
        "policyTargetKey": {
            "targetResource": target_resource_customized,
            "additionalTargetKeys": atk_dict
        },
        "pageSize": page_size,
        "pageToken": page_token
    }

    full_url = f'https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies:resolve'

    policy_resolved_resp = []
    if page_size or page_token:
        if not page_size:
            page_size = str(DEFAULT_PAGE_SIZE)
        if int(page_size) > API_LIMIT:
            page_size = str(API_LIMIT)
        app_payload['pageSize'] = page_size
        response = client.http_request(full_url=full_url, method='POST', body=app_payload)
        page_token = response.get('nextPageToken', '')
        policy_resolved_resp.extend(response.get('resolvedPolicies', ''))  # type: ignore
    else:
        while len(policy_resolved_resp) < int(limit):
            if int(limit) - len(policy_resolved_resp) > API_LIMIT:
                page_size = str(API_LIMIT)
            else:
                page_size = str(int(limit) - len(policy_resolved_resp))
            app_payload['pageSize'] = page_size
            app_payload['pageToken'] = page_token
            response = client.http_request(full_url=full_url, method='POST', body=app_payload)
            page_token = response.get('nextPageToken', '')
            policy_resolved_resp.extend(response.get('resolvedPolicies', ''))  # type: ignore
            if not page_token:
                break

    hr_from_response = []
    for res in policy_resolved_resp:
        customized_resp = {'targetResource': res['targetKey']['targetResource'],  # type: ignore
                           'additionalTargetKeys': res['targetKey']['additionalTargetKeys'],  # type: ignore
                           'policySchema': res['value']['policySchema']}  # type: ignore
        hr_from_response.append(customized_resp)
    # Readable Output
    readable_output = tableToMarkdown(HR_MESSAGES['POLICY_RESOLVE'], hr_from_response,
                                      ['targetResource', 'additionalTargetKeys', 'policySchema'],
                                      headerTransform=pascalToSpace, removeNull=True)
    outputs = {
        'GSuite.Policy(val.targetKey.targetResource && val.targetKey.targetResource == obj.targetKey.targetResource)':
            policy_resolved_resp,
        'GSuite(true)': {'PolicyNextToken': page_token}
    }
    return CommandResults(outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def assign_params_policy_schemas(filter, page_size, page_token):
    return GSuiteClient.remove_empty_entities({
        'filter': filter,
        'pageSize': page_size,
        'pageToken': page_token
    })


def policy_schemas_list_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
        list policy schemas

        :param client: Client object.
        :param args: Command arguments.

        :return: Command Result.
    """
    API_LIMIT = 1000
    client.set_authorized_http(scopes=SCOPES['POLICY_MANAGEMENT'])
    customer_id = return_customer_id(args)
    schema_name = args.get('schema_name', '')
    filter = args.get('filter', '')
    page_size = args.get('page_size', '')
    page_token = args.get('page_token', '')
    limit = args.get('limit', '')

    full_url = f'https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policySchemas'
    policy_schemas_resp = []
    if schema_name:
        full_url = f'https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policySchemas/{schema_name}'
        response = client.http_request(full_url=full_url, method='GET')
        policy_schemas_resp.append(response)  # type: ignore
    else:
        if page_size or page_token:
            if not page_size:
                page_size = str(DEFAULT_PAGE_SIZE)
            if int(page_size) > API_LIMIT:
                page_size = str(API_LIMIT)
            params_for_command = assign_params_policy_schemas(filter, page_size, page_token)
            response = client.http_request(full_url=full_url, method='GET', params=params_for_command)
            page_token = response.get('nextPageToken', '')
            policy_schemas_resp.extend(response.get('policySchemas', ''))  # type: ignore
        else:
            while len(policy_schemas_resp) < int(limit):
                if int(limit) - len(policy_schemas_resp) > API_LIMIT:
                    page_size = str(API_LIMIT)
                else:
                    page_size = str(int(limit) - len(policy_schemas_resp))
                params_for_command = assign_params_policy_schemas(filter, page_size, page_token)
                response = client.http_request(full_url=full_url, method='GET', params=params_for_command)
                page_token = response.get('nextPageToken', '')
                policy_schemas_resp.extend(response.get('policySchemas', ''))  # type: ignore
                if not page_token:
                    break

    # Readable Output
    readable_output = tableToMarkdown(HR_MESSAGES['POLICY_LIST'], policy_schemas_resp,
                                      ['name', 'policyDescription', 'schemaName'],
                                      headerTransform=pascalToSpace, removeNull=True)
    outputs = {
        'GSuite.Policy(val.name && val.name == obj.name)':
            policy_schemas_resp,
        'GSuite(true)': {'PolicySchemasNextToken': page_token}
    }
    return CommandResults(outputs=outputs,
                          readable_output=readable_output,
                          raw_response=response)


def group_delete_command(client: Client, args: dict[str, str]) -> str:
    """
       delete a user_group based on target_id

       :param client: Client object.
       :param args: Command arguments.

       :return: String that confirms request was executed.
   """
    client.set_authorized_http(scopes=SCOPES['POLICY_MANAGEMENT'])
    customer_id = return_customer_id(args)
    policy_raw_json = args.get('policy_raw_json', '')
    policy_field_json_entry_id = args.get('policy_field_json_entry_id', '')
    target_resource = args.get('target_resource', '')
    additional_target_keys = args.get('additional_target_keys', '')
    policy_schema = args.get('policy_schema', '')

    if additional_target_keys:
        atk_dict = json.loads(additional_target_keys)
    else:
        atk_dict = {}

    target_resource_customized = f'groups/{target_resource}'
    full_url = f'https://chromepolicy.googleapis.com/v1/customers/{customer_id}/policies/groups:batchDelete'
    if policy_raw_json:
        app_payload = GSuiteClient.safe_load_non_strict_json(policy_raw_json)
    elif policy_field_json_entry_id:
        app_payload = return_file_from_entry_id(policy_field_json_entry_id)
    else:
        app_payload = {
            "requests": [
                {
                    "policyTargetKey":
                        {
                            "targetResource": target_resource_customized,
                            "additionalTargetKeys": atk_dict
                        },
                    "policySchema": policy_schema,
                }
            ]
        }

    client.http_request(full_url=full_url, method='POST', body=app_payload)

    # Output
    return f'Policy has been deleted for the customer {customer_id}'


def main() -> None:
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dictionary
    commands: dict[str, Callable] = {
        'gsuite-custom-user-schema-update': custom_user_schema_update_command,
        'gsuite-custom-user-schema-create': custom_user_schema_create_command,
        'gsuite-datatransfer-list': datatransfer_list_command,
        'gsuite-role-assignment-create': role_assignment_create_command,
        'gsuite-role-assignment-list': role_assignment_list_command,
        'gsuite-user-create': user_create_command,
        'gsuite-user-get': user_get_command,
        'gsuite-mobile-update': mobile_update_command,
        'gsuite-mobile-delete': mobile_delete_command,
        'gsuite-user-alias-add': user_alias_add_command,
        'gsuite-group-create': group_create_command,
        'gsuite-group-get': group_get_command,
        'gsuite-role-create': role_create_command,
        'gsuite-token-revoke': token_revoke_command,
        'gsuite-datatransfer-request-create': datatransfer_request_create_command,
        'gsuite-user-delete': user_delete_command,
        'gsuite-user-update': user_update_command,
        'gsuite-mobiledevice-list': gsuite_mobile_device_list_command,
        'gsuite-chromeosdevice-action': gsuite_chromeos_device_action_command,
        'gsuite-chromeosdevice-list': gsuite_chromeos_device_list_command,
        'gsuite-user-signout': user_signout_command,
        'gsuite-user-reset-password': user_reset_password_command,
        'gsuite-chromebrowserdevice-move-ou': chromebrowser_move_ou_command,
        'gsuite-chromebrowserdevice-list': chromebrowser_list_command,
        'gsuite-policy-modify': modify_policy_command,
        'gsuite-policy-schemas-list': policy_schemas_list_command,
        'gsuite-policy-resolve': policy_resolve_command,
        'gsuite-policy-groups-delete': group_delete_command
    }
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        params = demisto.params()
        service_account_dict = GSuiteClient.safe_load_non_strict_json(
            params.get('admin_email_creds', {}).get('password') or params.get('user_service_account_json'))
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        headers = {
            'Content-Type': 'application/json'
        }

        args = GSuiteClient.strip_dict(demisto.args())

        admin_email = args.get('admin_email')\
            or params.get('admin_email_creds', {}).get('identifier')\
            or params.get('admin_email')

        if admin_email and not is_email_valid(admin_email):
            raise ValueError(MESSAGES['INVALID_ADMIN_EMAIL'])

        # prepare client class object
        client = Client(service_account_dict=service_account_dict, base_url='https://admin.googleapis.com/',
                        verify=verify_certificate, proxy=proxy, headers=headers,
                        admin_email=admin_email
                        )

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
        # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

from CommonServerPython import *

''' IMPORTS '''

import urllib.parse
import urllib3
import hashlib
import copy
from typing import List, Dict, Any, Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MESSAGES: Dict[str, str] = {
    'TEST_FAILED_ERROR': 'Test connectivity failed. Check the configuration parameters provided.',
    'BOOLEAN_ERROR': 'The argument {} must be either true or false.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'REQUIRED_ARGS_CUSTOM_SCHEMA': 'Argument field_raw_json or field_json_entry_id is required.',
    'CUSTOM_SCHEMA_UPDATE_REQUIRED_ARGS': 'Argument schema_id or schema_name is required.',
    'UNEXPECTED_ERROR': 'An unexpected error occurred.',
    'DATATRANSFER_MISSING_ARGUMENT': 'The argument application_id or applications_raw_json'
                                     ' or application_raw_json_entry_id is required.',
    'DATATRANSFER_TRANSFER_PARAM_FORMAT_ERROR': 'application_transfer_params argument not in expected format. Please '
                                                'provide a comma separated string of format "key1:val;key2:val1,val2"',
    'INVALID_ADMIN_EMAIL': 'Invalid value of argument/parameter Admin Email.'
}

HR_MESSAGES: Dict[str, str] = {
    'MOBILE_UPDATE_SUCCESS': 'Mobile device with resource id - {} updated.',
    'MOBILE_DELETE_SUCCESS': 'Mobile device with resource id - {} deleted.',
    'USER_CREATE': 'User Details',
    'LIST_COMMAND_SUCCESS': 'Total Retrieved {}: {}',
    'ALIAS_ADD_SUCCESS': 'Added alias "{}" to user key "{}".',
    'GROUP_CREATE_SUCCESS': 'A new group named "{}" created.',
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
    'USER_UPDATE': 'Updated User Details'
}

URL_SUFFIX: Dict[str, str] = {
    'DATA_TRANSFER': 'admin/datatransfer/v1/transfers',
    'USER': 'admin/directory/v1/users',
    'MOBILE_UPDATE': 'admin/directory/v1/customer/{}/devices/mobile/{}/action',
    'MOBILE_DELETE': 'admin/directory/v1/customer/{}/devices/mobile/{}',
    'USER_ALIAS': 'admin/directory/v1/users/{}/aliases',
    'GROUP_CREATE': 'admin/directory/v1/groups',
    'ROLE_ASSIGNMENT': 'admin/directory/v1/customer/{}/roleassignments',
    'ROLE_CREATE': 'admin/directory/v1/customer/{}/roles',
    'TOKEN_REVOKE': 'admin/directory/v1/users/{}/tokens/{}',
    'CUSTOM_USER_SCHEMA': 'admin/directory/v1/customer/{}/schemas',
    'DATA_TRANSFER_CREATE': 'admin/datatransfer/v1/transfers'
}
SCOPES: Dict[str, List[str]] = {
    'DIRECTORY_USER': ['https://www.googleapis.com/auth/admin.directory.user'],
    'DEVICE_MOBILE': ['https://www.googleapis.com/auth/admin.directory.device.mobile'],
    'GROUP': ['https://www.googleapis.com/auth/admin.directory.group'],
    'ROLE_MANAGEMENT': ['https://www.googleapis.com/auth/admin.directory.rolemanagement'],
    'USER_SECURITY': ['https://www.googleapis.com/auth/admin.directory.user.security'],
    'DATA_TRANSFER': ['https://www.googleapis.com/auth/admin.datatransfer'],
    'CUSTOM_USER_SCHEMA': ['https://www.googleapis.com/auth/admin.directory.userschema']
}

COMMAND_SCOPES: Dict[str, List[str]] = {
    'DATA_TRANSFER_LIST': ['https://www.googleapis.com/auth/admin.datatransfer.readonly', *SCOPES['DATA_TRANSFER']],
    'MOBILE_UPDATE': ['https://www.googleapis.com/auth/admin.directory.device.mobile.action',
                      'https://www.googleapis.com/auth/admin.directory.device.mobile'],
    'USER_ALIAS_ADD': ['https://www.googleapis.com/auth/admin.directory.user.alias',
                       'https://www.googleapis.com/auth/admin.directory.user'],
    'ROLE_ASSIGNMENT': ['https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly',
                        *SCOPES['ROLE_MANAGEMENT']]
}

OUTPUT_PREFIX: Dict[str, str] = {
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
}

ADMIN_EMAIL = None


def prepare_output_user_alias_add(alias: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def prepare_args_for_user(args: Dict[str, str]) -> Dict[str, Any]:
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
        'password': hashlib.md5(args['password'].encode()).hexdigest() if args.get('password') else None,  # NOSONAR
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


def prepare_output_for_user_create(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepares output for gsuite-user-create command.

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


def prepare_markdown_from_dictionary(data: Dict[str, Any], ignore_fields: List[str] = []) -> str:
    """
    Prepares markdown from dictionary.

    :param data: data directory.
    :param ignore_fields: fields to ignore while preparing mark-down from dictionary.

    :return: data in markdown format.
    """
    hr_cell_info: List[str] = []
    for key, value in data.items():
        if key not in ignore_fields:
            hr_cell_info.append(
                '{}: {}'.format(pascalToSpace(key), ', '.join(value) if isinstance(value, list) else value))
    return '\n'.join(hr_cell_info)


def prepare_readable_output_for_user_create(outputs):
    """
    Prepares readable output for gsuite-user-create command.

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


def prepare_args_for_role_assignment_list(args: Dict[str, str]) -> Dict[str, str]:
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


def prepare_output_for_role_assignment_list(response: Dict[str, Any]) -> Dict[str, Any]:
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


def prepare_args_for_role_assignment_create(args: Dict[str, str]) -> Dict[str, str]:
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


def get_privileges_list_from_string(privileges: str) -> List[Dict[str, str]]:
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


def prepare_args_for_datatransfer_list(args: Dict[str, str]) -> Dict[str, str]:
    """
    Prepares arguments for gsuite-datatransfer-list command.

    :param args: Command arguments.

    :return: Prepared arguments.
    """
    return GSuiteClient.remove_empty_entities({
        'customerId': args.get('customer_id'),
        'maxResults': GSuiteClient.validate_get_int(args.get('max_results'),
                                                    MESSAGES['INTEGER_ERROR'].format('max_results')),
        'newOwnerUserId': args.get('new_owner_user_id'),
        'oldOwnerUserId': args.get('old_owner_user_id'),
        'pageToken': args.get('page_token'),
        'status': args.get('status'),
    })


def prepare_output_for_datatransfer_list(response: Dict[str, Any]) -> Dict[str, Any]:
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


def prepare_readable_output_for_datatransfer_list(response: Dict[str, Any]) -> str:
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


def prepare_args_for_custom_user_schema(args: Dict[str, str]) -> Dict[str, str]:
    """
    Prepares arguments for gsuite-custom-user-schema-create/update command.

    :param args: Command arguments.

    :return: Prepared arguments.
    :raises ValueError: If required argument(s) are not provided.
    """

    if args.get('field_raw_json'):
        field_json = GSuiteClient.safe_load_non_strict_json(args['field_raw_json'])
    elif args.get('field_json_entry_id'):
        field_json = safe_load_json(args['field_json_entry_id'])
    else:
        raise ValueError(MESSAGES['REQUIRED_ARGS_CUSTOM_SCHEMA'])

    return GSuiteClient.remove_empty_entities({
        'displayName': args.get('schema_display_name'),
        'schemaName': args.get('schema_name'),
        'schemaId': args.get('schema_id'),
        'fields': field_json.get('fields', [])
    })


def prepare_output_for_custom_user_schema(context_output: Dict[str, Any], readable_output: Dict[str, Any]) -> None:
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


def get_transfer_params_list_from_str(transfer_params_str: str) -> List:
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


def prepare_datatransfer_payload_from_arguments(args: Dict[str, str]) -> Dict[str, Any]:
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

    return True if re.match(emailRegex, email) else False


''' COMMAND FUNCTIONS '''


@logger
def test_module(client) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """

    with GSuiteClient.http_exception_handler():
        client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'], subject=ADMIN_EMAIL)
        if ADMIN_EMAIL:
            client.http_request(url_suffix=f"{URL_SUFFIX['USER']}/{ADMIN_EMAIL}", method='GET')
        else:
            return_results("Please insert Admin Email parameter for the test to run")
    return 'ok'


@logger
def mobile_update_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Takes an action that affects a mobile device. For example, remotely wiping a device.

    :param client: client object used to get response from api
    :param args: command arguments
    :return: CommandResults which returns detailed results to war room and sets the context data.
    """

    client.set_authorized_http(scopes=COMMAND_SCOPES['MOBILE_UPDATE'], subject=ADMIN_EMAIL)
    args.pop('admin_email', '')
    resource_id = urllib.parse.quote(args.pop('resource_id', ''))
    client.http_request(
        url_suffix=URL_SUFFIX['MOBILE_UPDATE'].format(urllib.parse.quote(args.pop('customer_id', '')), resource_id),
        method='POST', body=args)

    return CommandResults(readable_output=HR_MESSAGES['MOBILE_UPDATE_SUCCESS'].format(resource_id))


@logger
def mobile_delete_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Removes a mobile device. Note that this does not break the device's sync, it simply removes it from the list of
    devices connected to the domain. If the device still has a valid login/authentication, it will be added back on
    it's next successful sync.

    :param client: client object used to get response from api
    :param args: command arguments
    :return: CommandResults which returns detailed results to war room and sets the context data.
    """
    client.set_authorized_http(scopes=SCOPES['DEVICE_MOBILE'], subject=ADMIN_EMAIL)
    resource_id = urllib.parse.quote(args.pop('resource_id', ''))
    client.http_request(
        url_suffix=URL_SUFFIX['MOBILE_DELETE'].format(urllib.parse.quote(args.pop('customer_id', '')), resource_id),
        method='DELETE')

    return CommandResults(readable_output=HR_MESSAGES['MOBILE_DELETE_SUCCESS'].format(resource_id))


@logger
def user_create_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Creates a user.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    prepared_args = prepare_args_for_user(args)
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'], subject=ADMIN_EMAIL)

    response = client.http_request(url_suffix=URL_SUFFIX['USER'], body=prepared_args, method='POST')

    # Context
    outputs = prepare_output_for_user_create(copy.deepcopy(response))

    # Readable Output
    readable_output_dict = prepare_readable_output_for_user_create(copy.deepcopy(outputs))
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
def role_assignment_list_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Prints all admin role assignments in the G Suite instance.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    arguments = prepare_args_for_role_assignment_list(args)
    client.set_authorized_http(scopes=COMMAND_SCOPES['ROLE_ASSIGNMENT'], subject=ADMIN_EMAIL)
    response = client.http_request(
        url_suffix=URL_SUFFIX['ROLE_ASSIGNMENT'].format(urllib.parse.quote(args.get('customer_id', ''))),
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
def role_assignment_create_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Assigns a role to the customer.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    arguments = prepare_args_for_role_assignment_create(args)

    client.set_authorized_http(scopes=SCOPES['ROLE_MANAGEMENT'], subject=ADMIN_EMAIL)
    response = client.http_request(
        url_suffix=URL_SUFFIX['ROLE_ASSIGNMENT'].format(urllib.parse.quote(args.get('customer_id', ''))),
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
def user_alias_add_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Adds an alias.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    user_key = args.get('user_key', '')
    user_key = urllib.parse.quote(user_key)  # type: ignore
    alias = args.get('alias', '')
    admin_email = ADMIN_EMAIL

    body = {'alias': alias}
    body = GSuiteClient.remove_empty_entities(body)

    client.set_authorized_http(scopes=COMMAND_SCOPES['USER_ALIAS_ADD'], subject=admin_email)
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
def group_create_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Creates a group with a group name and its description.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    client.set_authorized_http(scopes=SCOPES['GROUP'], subject=ADMIN_EMAIL)
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
def role_create_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Creates a role with a role name and its description.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """

    client.set_authorized_http(scopes=SCOPES['ROLE_MANAGEMENT'], subject=ADMIN_EMAIL)

    params = {
        'rolePrivileges': get_privileges_list_from_string(args.pop('role_privileges', '')),
        'roleName': args.get('role_name', ''),
        'roleDescription': args.get('role_description', '')
    }

    response = client.http_request(
        url_suffix=URL_SUFFIX['ROLE_CREATE'].format(urllib.parse.quote(args.get('customer_id', ''))), body=params,
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
def token_revoke_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Delete all access tokens issued by a user for an application.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """

    client.set_authorized_http(scopes=SCOPES['USER_SECURITY'], subject=ADMIN_EMAIL)

    user_key = urllib.parse.quote(args.get('user_key', ''))
    client_id = urllib.parse.quote(args.get('client_id', ''))

    client.http_request(url_suffix=URL_SUFFIX['TOKEN_REVOKE'].format(user_key, client_id), method='DELETE')

    return CommandResults(readable_output=HR_MESSAGES['TOKEN_REVOKE_SUCCESS'].format(args.get('client_id', '')))


@logger
def datatransfer_list_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Lists the transfers for a customer by source user, destination user, or status.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    params = prepare_args_for_datatransfer_list(args)
    client.set_authorized_http(scopes=COMMAND_SCOPES['DATA_TRANSFER_LIST'], subject=ADMIN_EMAIL)
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
def custom_user_schema_create_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Creates a custom user schema to add custom fields to user profiles.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    """
    body = prepare_args_for_custom_user_schema(args)
    client.set_authorized_http(scopes=SCOPES['CUSTOM_USER_SCHEMA'], subject=ADMIN_EMAIL)
    response = client.http_request(method='POST',
                                   url_suffix=URL_SUFFIX['CUSTOM_USER_SCHEMA'].format(
                                       urllib.parse.quote(args.get('customer_id', ''))),
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
def custom_user_schema_update_command(client, args: Dict[str, Any]) -> CommandResults:
    """
    Updates a custom user schema.

    :param client: client object which is used to get response from api
    :param args: command arguments.

    :return: CommandResults object with context and human-readable.
    :raise ValueError: If required arguments are not provided.
    """
    if not args.get('schema_id') and not args.get('schema_name'):
        raise ValueError(MESSAGES['CUSTOM_SCHEMA_UPDATE_REQUIRED_ARGS'])

    body = prepare_args_for_custom_user_schema(args)

    schema_key = args['schema_id'] if args.get('schema_id') else args.get('schema_name', '')

    url_suffix = f"{URL_SUFFIX['CUSTOM_USER_SCHEMA'].format(urllib.parse.quote(args.get('customer_id', '')))}" \
                 f"/{urllib.parse.quote(schema_key)}"

    client.set_authorized_http(scopes=SCOPES['CUSTOM_USER_SCHEMA'], subject=ADMIN_EMAIL)
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
def datatransfer_request_create_command(client, args: Dict[str, str]) -> CommandResults:
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
        app_payload = safe_load_json(args['applications_raw_json_entry_id'])

    request_payload = prepare_datatransfer_payload_from_arguments(args)

    if app_payload.get('applicationDataTransfers'):
        request_payload['applicationDataTransfers'] = app_payload['applicationDataTransfers']

    client.set_authorized_http(scopes=SCOPES['DATA_TRANSFER'], subject=ADMIN_EMAIL)

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
def user_delete_command(client, args: Dict[str, str]) -> CommandResults:
    """
    Deletes a user.

    :param client: Client object.
    :param args: Command arguments.

    :return: CommandResults.
    """
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'], subject=ADMIN_EMAIL)
    user_key = args.get('user_key', '')
    url_suffix = f"{URL_SUFFIX['USER']}/{urllib.parse.quote(user_key)}"
    client.http_request(url_suffix=url_suffix, method='DELETE')

    return CommandResults(readable_output=HR_MESSAGES['USER_DELETE'].format(user_key))


@logger
def user_update_command(client, args: Dict[str, str]) -> CommandResults:
    """
    updates a user.

    :param client: Client object.
    :param args: Command arguments.

    :return: Command Result.
    """
    prepared_args = prepare_args_for_user(args)
    client.set_authorized_http(scopes=SCOPES['DIRECTORY_USER'], subject=ADMIN_EMAIL)
    user_key = args.get('user_key', '')
    url_suffix = f"{URL_SUFFIX['USER']}/{urllib.parse.quote(user_key)}"
    response = client.http_request(url_suffix=url_suffix, body=prepared_args, method='PUT')

    # Context
    outputs = prepare_output_for_user_create(copy.deepcopy(response))

    # Readable Output
    readable_output_dict = prepare_readable_output_for_user_create(copy.deepcopy(outputs))
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


def main() -> None:
    """
         PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # Commands dictionary
    commands: Dict[str, Callable] = {
        'gsuite-custom-user-schema-update': custom_user_schema_update_command,
        'gsuite-custom-user-schema-create': custom_user_schema_create_command,
        'gsuite-datatransfer-list': datatransfer_list_command,
        'gsuite-role-assignment-create': role_assignment_create_command,
        'gsuite-role-assignment-list': role_assignment_list_command,
        'gsuite-user-create': user_create_command,
        'gsuite-mobile-update': mobile_update_command,
        'gsuite-mobile-delete': mobile_delete_command,
        'gsuite-user-alias-add': user_alias_add_command,
        'gsuite-group-create': group_create_command,
        'gsuite-role-create': role_create_command,
        'gsuite-token-revoke': token_revoke_command,
        'gsuite-datatransfer-request-create': datatransfer_request_create_command,
        'gsuite-user-delete': user_delete_command,
        'gsuite-user-update': user_update_command

    }
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        global ADMIN_EMAIL
        params = demisto.params()
        service_account_dict = GSuiteClient.safe_load_non_strict_json(params.get('user_service_account_json'))
        verify_certificate = not params.get('insecure', False)
        proxy = params.get('proxy', False)

        headers = {
            'Content-Type': 'application/json'
        }

        # prepare client class object
        gsuite_client = GSuiteClient(service_account_dict,
                                     base_url='https://www.googleapis.com/', verify=verify_certificate, proxy=proxy,
                                     headers=headers)

        # Trim the arguments
        args = GSuiteClient.strip_dict(demisto.args())

        ADMIN_EMAIL = args.get('admin_email') if args.get('admin_email') else params.get('admin_email')

        # Validation of ADMIN_EMAIL
        if ADMIN_EMAIL and not is_email_valid(ADMIN_EMAIL):
            raise ValueError(MESSAGES['INVALID_ADMIN_EMAIL'])

        # This is the call made when pressing the integration Test button.
        if demisto.command() == 'test-module':
            result = test_module(gsuite_client)
            demisto.results(result)

        elif command in commands:
            return_results(commands[command](gsuite_client, args))

        # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Error: {str(e)}')


from GSuiteApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

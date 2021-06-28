''' IMPORTS '''

# import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import List, Dict, Any, Callable

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

ADMIN_EMAIL = None

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


URL_SUFFIX = 'admin/reports/v1/activity/users/{}/applications/{}'
SCOPES: Dict[str, List[str]] = {
    'DIRECTORY_USER': ['https://www.googleapis.com/auth/admin.directory.user'],
    'DEVICE_MOBILE': ['https://www.googleapis.com/auth/admin.directory.device.mobile'],
    'GROUP': ['https://www.googleapis.com/auth/admin.directory.group'],
    'ROLE_MANAGEMENT': ['https://www.googleapis.com/auth/admin.directory.rolemanagement'],
    'USER_SECURITY': ['https://www.googleapis.com/auth/admin.directory.user.security'],
    'DATA_TRANSFER': ['https://www.googleapis.com/auth/admin.datatransfer'],
    'CUSTOM_USER_SCHEMA': ['https://www.googleapis.com/auth/admin.directory.userschema']
}


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


''' HELPER FUNCTIONS '''


def is_email_valid(email: str) -> bool:
    """
    Validates provided email is valid or not.

    :param email: email string.
    :return:  True if email is in valid format.
    """

    return True if re.match(emailRegex, email) else False

@logger
def test_module(client) -> str:
    """
    Performs test connectivity by valid http response

    :param client: client object which is used to get response from api.

    :return: raise ValueError if any error occurred during connection
    :raises DemistoException: If there is any other issues while making the http call.
    """
    with GSuiteClient.http_exception_handler():
        client.set_authorized_http(scopes='https://www.googleapis.com/auth/admin.reports.audit.readonly', subject=ADMIN_EMAIL)
        if ADMIN_EMAIL:
            suffix = URL_SUFFIX.format('all', "admin")
            client.http_request(url_suffix=suffix, method='GET')
        else:
            return_results("Please insert Admin Email parameter for the test to run")
    return 'ok'


# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''

#
# def test_module(client: Client) -> str:
#     """Tests API connectivity and authentication'
#
#     Returning 'ok' indicates that the integration works like it is supposed to.
#     Connection to the service is successful.
#     Raises exceptions if something goes wrong.
#
#     :type client: ``Client``
#     :param Client: client to use
#
#     :return: 'ok' if test passed, anything else will fail the test.
#     :rtype: ``str``
#     """
#
#     message: str = ''
#     try:
#         # TODO: ADD HERE some code to test connectivity and authentication to your service.
#         # This  should validate all the inputs given in the integration configuration panel,
#         # either manually or by using an API that uses them.
#         message = 'ok'
#     except DemistoException as e:
#         if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
#             message = 'Authorization Error: make sure API Key is correctly set'
#         else:
#             raise e
#     return message

#
# # TODO: REMOVE the following dummy command function
# def baseintegration_dummy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
#
#     dummy = args.get('dummy', None)
#     if not dummy:
#         raise ValueError('dummy not specified')
#
#     # Call the Client function and get the raw response
#     result = client.baseintegration_dummy(dummy)
#
#     return CommandResults(
#         outputs_prefix='BaseIntegration',
#         outputs_key_field='',
#         outputs=result,
#     )
# # TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # Commands dictionary
    commands: Dict[str, Callable] = {
        # 'gsuite-custom-user-schema-update': custom_user_schema_update_command,
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
                                     base_url='https://admin.googleapis.com/', verify=verify_certificate, proxy=proxy,
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

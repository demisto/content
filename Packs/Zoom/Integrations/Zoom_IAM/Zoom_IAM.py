import demistomock as demisto
from CommonServerPython import *
from IAMApiModule import *
import traceback
import jwt
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DEFAULT_OUTGOING_MAPPER = "User Profile - SCIM (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - SCIM (Incoming)"

ERROR_CODES_TO_SKIP = [
    404
]
BASE_URL = 'https://api.zoom.us/v2/'

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with Zoom application. """

    def __init__(self, base_url, api_key, api_secret, verify=True, proxy=False):
        super().__init__(base_url, verify, proxy)
        self.api_key = api_key
        self.api_secret = api_secret
        self.access_token = get_jwt(api_key, api_secret)

    def test(self):
        """ Tests connectivity with the application. """

        self.get_user('', 'me')
        return 'ok'

    def get_user(self, _, filter_value: str) -> Optional[IAMUserAppData]:
        uri = f'/users/{filter_value}'

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            headers={'authorization': f'Bearer {self.access_token}',
                     'Accept': 'application/json',
                     'Content-Type': 'application/json',
                     },
        )
        if res and (not res.get('users')):
            user_app_data = res
            user_id = user_app_data.get('id')
            is_active = True if user_app_data.get('status') == 'active' else False
            email = user_app_data.get('email')
            # the API does not provide user name
            username = ''

            return IAMUserAppData(user_id, username, is_active, user_app_data, email=email)
        return None

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = f'/users/{user_id}/status'
        self._http_request(
            method='PUT',
            url_suffix=uri,
            json_data=user_data,
            return_empty_response=True,
            headers={'authorization': f'Bearer {self.access_token}',
                     'Accept': 'application/json',
                     'Content-Type': 'application/json',
                     },
        )
        # res is an empty *response object*
        user_app_data: dict = {}
        # if we wanted to disable the user and request succeeded,
        # we get to this line and know the user's status
        is_active = True if user_data.get('action', '') == 'activate' else False
        username = ''

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {'action': 'deactivate'}
        return self.update_user(user_id, user_data)

    def get_app_fields(self):
        user_app_data = self.get_user('', 'me')
        if user_app_data:
            return {k: underscoreToCamelCase(k) for k, _ in user_app_data.full_data.items()}
        raise DemistoException('Could not retrieve fields for mapping')

    @staticmethod
    def handle_exception(user_profile: IAMUserProfile,
                         e: Union[DemistoException, Exception],
                         action: IAMActions):
        """ Handles failed responses from the application API by setting the User Profile object with the result.
            The result entity should contain the following data:
            1. action        (``IAMActions``)       The failed action                       Required
            2. success       (``bool``)             The success status                      Optional (by default, True)
            3. skip          (``bool``)             Whether or not the command was skipped  Optional (by default, False)
            3. skip_reason   (``str``)              Skip reason                             Optional (by default, None)
            4. error_code    (``Union[str, int]``)  HTTP error code                         Optional (by default, None)
            5. error_message (``str``)              The error description                   Optional (by default, None)

            Note: This is the place to determine how to handle specific edge cases from the API, e.g.,
            when a DISABLE action was made on a user which is already disabled and therefore we can't
            perform another DISABLE action.

        :type user_profile: ``IAMUserProfile``
        :param user_profile: The user profile object

        :type e: ``Union[DemistoException, Exception]``
        :param e: The exception object - if type is DemistoException, holds the response json object (`res` attribute)

        :type action: ``IAMActions``
        :param action: An enum represents the current action (GET, UPDATE, CREATE, DISABLE or ENABLE)
        """
        if isinstance(e, DemistoException) and e.res is not None:
            error_code = e.res.status_code

            if action == IAMActions.DISABLE_USER and error_code in ERROR_CODES_TO_SKIP:
                skip_message = 'Users is already disabled or does not exist in the system.'
                user_profile.set_result(action=action,
                                        skip=True,
                                        skip_reason=skip_message)

            try:
                resp = e.res.json()
                error_message = get_error_details(resp)
            except ValueError:
                error_message = str(e)
        else:
            error_code = ''
            error_message = str(e)

        user_profile.set_result(action=action,
                                success=False,
                                error_code=error_code,
                                error_message=error_message)

        demisto.error(traceback.format_exc())


'''HELPER FUNCTIONS'''


def get_jwt(api_key: str, api_secret: str) -> str:
    """
    Encode the JWT token given the api ket and secret
    """
    now = time.time()
    expire_time = int(now) + 5000
    payload = {
        'iss': api_key,
        'exp': expire_time
    }
    encoded = jwt.encode(payload, api_secret, algorithm='HS256')
    return str(encoded)


def get_error_details(res: Dict[str, Any]) -> str:
    """ Parses the error details retrieved from the application and outputs the resulted string.

    :type res: ``Dict[str, Any]``
    :param res: The error data retrieved from the application.

    :return: The parsed error details.
    :rtype: ``str``
    """
    message = res.get('code', '')
    details = res.get('message', '')
    return f'{message}: {details}'


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """
    try:
        client.test()
    except Exception as e:
        error_message_index = str(e).find('"message":')
        error_message = str(e)[error_message_index:]
        if 'Invalid access token' in error_message:
            error_message = 'Invalid API Key. Please verify that your API key is valid.'
        if "The Token's Signature resulted invalid" in error_message:
            error_message = 'Invalid API Secret. Please verify that your API Secret is valid.'
        return error_message
    return 'ok'


def get_mapping_fields(client: Client):
    mapping = client.get_app_fields()
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE, fields=mapping)
    return GetMappingFieldsResponse([incident_type_scheme])


def main():
    user_profile = None
    params = demisto.params()
    api_key = params.get('api_key')
    api_secret = params.get('api_secret')
    mapper_in = params.get('mapper_in', DEFAULT_INCOMING_MAPPER)
    # mapper_out = params.get('mapper_out', DEFAULT_OUTGOING_MAPPER)
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_disable_enabled = params.get('disable-user-enabled')

    iam_command = IAMCommand(is_create_enabled=False,
                             is_enable_enabled=False,
                             is_disable_enabled=is_disable_enabled,
                             is_update_enabled=False,
                             create_if_not_exists=False,
                             mapper_in=mapper_in,
                             # Currently we don't use scim API endpoints, so we don't map the arguments.
                             mapper_out=None,
                             get_user_iam_attrs=['id', 'username', 'email']
                             )
    client = Client(
        base_url=BASE_URL,
        verify=verify_certificate,
        proxy=proxy,
        api_key=api_key,
        api_secret=api_secret,
    )

    demisto.debug(f'Command being called is {command}')

    '''CRUD commands'''
    if command == 'iam-disable-user':
        user_profile = iam_command.disable_user(client, args)
    elif command == 'iam-get-user':
        user_profile = iam_command.get_user(client, args)

    if user_profile:
        return_results(user_profile)

    '''non-CRUD commands'''

    try:
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))
    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

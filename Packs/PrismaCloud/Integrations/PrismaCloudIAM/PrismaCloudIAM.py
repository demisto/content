import demistomock as demisto
from CommonServerPython import *
from IAMApiModule import *
import traceback
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]

USER_SCHEMA = {
    'email': 'The email of the user',
    'firstName': 'The first name',
    'lastName': 'The last name',
    'displayName': 'The display name of the user',
    'timeZone': 'The time zone e.g Asia/Jerusalem',
    'roleId': 'The role id for the user'
}

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def __init__(self, username, password, customer_name, **kwargs):
        super(Client, self).__init__(**kwargs)
        self._username = username
        self._password = password
        self._customer_name = customer_name

    def test(self):
        """ Tests connectivity with the application. """
        self.login()
        return 'ok'

    def get_user(self, _, email: str) -> Optional[IAMUserAppData]:
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type email: ``str``
        :param email: Email address of the user

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        uri = f'user/{encode_string_results(email)}'
        user_app_data = self._http_request(
            method='GET',
            url_suffix=uri,
            error_handler=get_user_error_handler,
            empty_valid_codes=[400],
            return_empty_response=True
        )

        if user_app_data:
            user_id = email
            is_active = user_app_data.get('enabled')
            email = user_app_data.get('email')
            return IAMUserAppData(user_id, user_id, is_active, user_app_data, email)

        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = 'user'
        self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data,
            return_empty_response=True,
            empty_valid_codes=[200]
        )
        return IAMUserAppData(user_id=None, username=None, is_active=True, app_data=user_data)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object from the get_user command that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = f'user/{user_id}'
        self._http_request(
            method='PUT',
            url_suffix=uri,
            json_data=user_data,
            return_empty_response=True,
            empty_valid_codes=[200]
        )
        # Because the update api also enables the user, we should disable if we don't want to enable.
        if demisto.args().get('allow-enable', 'true') == 'false' or not demisto.params().get("enable_user_enabled", True):
            self.disable_user(user_id)

        return self.get_user('id', user_id)  # type: ignore

    def enable_user(self, user_id: str) -> IAMUserAppData:
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        return self.enable_disable_user(user_id=user_id, enable=True)

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        return self.enable_disable_user(user_id=user_id, enable=False)

    def enable_disable_user(self, user_id: str, enable: bool) -> IAMUserAppData:
        """ Enables or disable a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type enable: ``bool``
        :param enable: True to enable, False for disable

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        status = 'true' if enable else 'false'
        uri = f'user/{user_id}/status/{status}'
        self._http_request(
            method='PATCH',
            url_suffix=uri,
            return_empty_response=True,
            empty_valid_codes=[200]
        )
        return IAMUserAppData(user_id=user_id, username=user_id, is_active=enable, app_data=None)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """
        return USER_SCHEMA

    def login(self):
        uri = '/login/'
        body = {
            "username": self._username,
            "password": self._password,
            "customerName": self._customer_name
        }
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=body
        )
        self._headers['x-redlock-auth'] = res.get('token')

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

            error_message = get_error_details(e.res)
        else:
            error_code = ''
            error_message = str(e)

        user_profile.set_result(action=action,
                                success=False,
                                error_code=error_code,
                                error_message=f'{error_message}\n{traceback.format_exc()}')

        demisto.error(traceback.format_exc())


'''HELPER FUNCTIONS'''


def get_user_error_handler(res: requests.Response):
    """
        Handle errors in get user command to avoid fail in create user command when checking if user already exist,
        if the error is due to user doesn't exist - return None otherwise raise DemistoException

        :type res: ``requests.Response``
        :param res: The error response retrieved from the application.
    """
    err_msg = get_error_details(res)
    if 'user_inactive_or_not_exist' in err_msg:
        return None

    raise DemistoException(err_msg, res=res)


def get_error_details(res: requests.Response) -> str:
    """ Parses the error details retrieved from the application and outputs the resulted string.

    :type res: ``Dict[str, Any]``
    :param res: The error data retrieved from the application.

    :return: The parsed error details.
    :rtype: ``str``
    """
    err_details = f'Error in API call [{res.status_code}]'
    status_header_str = res.headers.get('x-redlock-status')
    if status_header_str:
        status_header = json.loads(status_header_str)
        if isinstance(status_header, list):
            status_header = status_header[0]
        err_details += f' - {status_header.get("i18nKey")}'

    return err_details


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """
    try:
        return_results(client.test())
    except DemistoException as e:
        return_error(e.message)


def get_mapping_fields(client: Client) -> GetMappingFieldsResponse:
    """ Creates and returns a GetMappingFieldsResponse object of the user schema in the application

    :param client: (Client) The integration Client object that implements a get_app_fields() method
    :return: (GetMappingFieldsResponse) An object that represents the user schema
    """
    app_fields = client.get_app_fields()
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

    for field, description in app_fields.items():
        incident_type_scheme.add_field(field, description)

    return GetMappingFieldsResponse([incident_type_scheme])


def main():
    user_profile = None
    params = demisto.params()
    base_url = params['url']
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    customer_name = params.get('customerName')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out,
                             get_user_iam_attrs=['id', 'username', 'email'])

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': ''
    }

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            ok_codes=(200, 201),
            username=username,
            password=password,
            customer_name=customer_name
        )

        '''non-CRUD commands - not need to login'''

        if command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

        '''CRUD commands - login needed'''
        client.login()
        if command == 'iam-get-user':
            user_profile = iam_command.get_user(client, args)

        elif command == 'iam-create-user':
            user_profile = iam_command.create_user(client, args)

        elif command == 'iam-update-user':
            user_profile = iam_command.update_user(client, args)

        elif command == 'iam-disable-user':
            user_profile = iam_command.disable_user(client, args)

        if user_profile:
            return_results(user_profile)

    except Exception:
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

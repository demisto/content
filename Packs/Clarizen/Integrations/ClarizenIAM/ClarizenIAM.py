import demistomock as demisto
from CommonServerPython import *
from IAMApiModule import *
import traceback
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
USER_FIELDS = 'Name,Email,Region,Location,JobTitle,DirectManager,MobilePhone,TimeZone,username,profile,firstname,' \
              'lastname,state'
ERROR_CODES_TO_SKIP = [
    404
]

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=(), headers=None, auth=None, manager_email=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.username = auth[0]
        self.password = auth[1]
        self.manager_id = self.get_manager_id(manager_email)

    def get_manager_id(self, manager_email: Optional[str]) -> str:
        """ Gets the user's manager ID from manager email.
        :type manager_email: ``str``
        :param manager_email: user's manager email
        :return: The user's manager ID
        :rtype: ``str``
        """

        # Get manager ID.
        manager_id = ''
        if manager_email:
            res = self.get_user(manager_email)
            if res is not None:
                manager_id = res.id
        return manager_id

    def test(self):
        """ Tests connectivity with the application. """

        uri = '/authentication/login'
        params = {
            "userName": self.username,
            "Password": self.password,
        }

        return self._http_request(method='POST', url_suffix=uri, data={}, params=params)

    def get_user_by_id(self, user_id):
        uri = f'/data/objects{user_id}'
        params = {
            'fields': USER_FIELDS
        }

        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params,
        )

    def get_user(self, email: str) -> Optional[IAMUserAppData]:
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type email: ``str``
        :param email: Email address of the user

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        uri = '/data/findUserQuery'
        data = {'email': email}

        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data,
        )

        entities = res.get('entities')

        if entities:
            user_id = entities[0].get('id')
            user_app_data = self.get_user_by_id(user_id)

            user_id = user_app_data.get('id').replace('/User/', '')
            user_name = user_app_data.get('username')
            active = user_app_data.get('state', {}).get('id').replace('/State/', '')
            is_active = False if active == 'Disabled' else True

            return IAMUserAppData(user_id, user_name, is_active, user_app_data)
        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = '/data/objects/User'
        if self.manager_id:
            user_data['manager_id'] = self.manager_id

        res = self._http_request(
            method='PUT',
            url_suffix=uri,
            json_data=user_data,
        )

        user_id = res.get('id')
        user_app_data = self.get_user_by_id(user_id)

        user_id = user_app_data.get('id').replace('/User/', '')
        user_name = user_app_data.get('username')
        is_active = True

        return IAMUserAppData(user_id, user_name, is_active, user_app_data)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = f'/data/objects/User/{user_id}'
        if self.manager_id:
            user_data['manager_id'] = self.manager_id

        self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data,
        )

        user_app_data = self.get_user_by_id(f'/User/{user_id}')

        user_name = user_app_data.get('username')
        active = user_app_data.get('state', {}).get('id').replace('/State/', '')
        is_active = False if active == 'Disabled' else True

        return IAMUserAppData(user_id, user_name, is_active, user_app_data)

    def enable_user(self, user_id: str) -> IAMUserAppData:
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        uri = '/data/lifecycle'
        user_data = {
            "ids": [f"/User/{user_id}"],
            "operation": "Enable",
        }

        self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data,
        )

        user_app_data = self.get_user_by_id(f'/User/{user_id}')

        user_name = user_app_data.get('username')
        is_active = True

        return IAMUserAppData(user_id, user_name, is_active, user_app_data)

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        uri = '/data/lifecycle'
        user_data = {
            "ids": [f"/User/{user_id}"],
            "operation": "Disable",
        }

        self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data,
        )

        user_app_data = self.get_user_by_id(f'/User/{user_id}')

        user_name = user_app_data.get('username')
        is_active = False

        return IAMUserAppData(user_id, user_name, is_active, user_app_data)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """

        uri = '/metadata/describeEntities'
        params = {
            'typeNames': 'User'
        }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=params,
        )

        fields = res.get('entityDescriptions', {}).get('fields', [])
        return {field.get('name'): field.get('label') for field in fields}

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


def get_error_details(res: Dict[str, Any]) -> str:
    """ Parses the error details retrieved from the application and outputs the resulted string.

    :type res: ``Dict[str, Any]``
    :param res: The error data retrieved from the application.

    :return: The parsed error details.
    :rtype: ``str``
    """
    message = res.get('error', {}).get('message')
    details = res
    return f'{message}: {details}'


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """

    res = client.test()
    if res.status_code == 200:
        return_results('ok')
    else:
        return_error(f'Error testing {res.status_code} - {res.text}')


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
    base_url = urljoin(params['url'].strip('/'), '/V2.0/services')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()
    manager_email = args.get('user-profile', {}).get('manageremailaddress')

    is_create_enabled = params.get("create_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201),
        auth=(username, password),
        manager_email=manager_email,
    )

    demisto.debug(f'Command being called is {command}')

    '''CRUD commands'''

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

    '''non-CRUD commands'''

    try:
        if command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception as exc:
        # For any other integration command exception, return an error
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command. Error:\n{exc}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

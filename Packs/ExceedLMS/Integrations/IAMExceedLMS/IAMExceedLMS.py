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

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """
    def __init__(self, base_url, api_key, headers, proxy=False, verify=True, ok_codes=None, manager_email=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers)
        self.api_key = api_key
        self.manager_id = self.get_manager_id(manager_email)

    def test(self):
        """ Tests connectivity with the application. """

        uri = '/api/v2/users.json/'
        params = {'api_key': self.api_key,
                  'user[login]': 123}
        self._http_request(method='GET', url_suffix=uri, params=params, timeout=30)

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
            res = self.get_user('email', manager_email)
            if res is not None:
                manager_id = res.id
        return manager_id

    def get_user(self, filter_name: str, filter_value: str) -> Optional[IAMUserAppData]:
        """ Queries the user in the application using REST API by its iam get attributes,
        and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type filter_name: ``str``
        :param filter_name: Name of the filter to retrieve the user by.

        :type filter_value: ``str``
        :param filter_value: Value corresponding to given filter to retrieve user by.

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        uri = '/api/v2/users.json/'
        params = {'api_key': self.api_key,
                  f'user[{filter_name}]': filter_value}
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=params,
            timeout=30
        )
        if isinstance(res, dict):
            res = [res]
        if res and len(res) == 1:
            user_app_data = res[0]
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('is_active')
            username = user_app_data.get('login')
            email = user_app_data.get('email')

            return IAMUserAppData(user_id, username, is_active, user_app_data, email)
        return None

    def create_user(self, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = '/api/v2/users.json'
        params = {'api_key': self.api_key}
        if self.manager_id:
            user_data['manager_id'] = self.manager_id
        user_app_data = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data,
            params=params,
            timeout=30
        )
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('is_active')
        username = user_app_data.get('login')
        email = user_app_data.get('email')

        return IAMUserAppData(user_id, username, is_active, user_app_data, email)

    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> IAMUserAppData:
        """ Updates a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the updated user in the application.
        :rtype: ``IAMUserAppData``
        """
        uri = f'/api/v2/users/{user_id}'
        params = {'api_key': self.api_key}
        if self.manager_id:
            user_data['manager_id'] = self.manager_id
        self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data,
            params=params,
            resp_type='response',
            timeout=30
        )

        username = user_data.get('login')

        return IAMUserAppData(user_id=user_id, username=username, is_active=None, app_data=user_data)

    def enable_user(self, user_id: str) -> IAMUserAppData:
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        user_data = {
            'is_active': 'true'
        }
        return self.update_user(user_id, user_data)

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """
        user_data = {
            'is_active': 'false'
        }
        return self.update_user(user_id, user_data)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """
        uri = '/api/v2/users.json/'
        params = {'api_key': self.api_key}
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=params,
            timeout=30
        )
        if isinstance(res, dict):
            res = [res]
        if len(res) > 0:
            res = res[0]
        return {key: "" for key, val in res.items()}

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
    err = res.get('error', '')
    if err:
        return str(err)
    return str(res)


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """

    client.test()
    return_results('ok')


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
    base_url = urljoin(params['url'].strip('/'))
    api_key = params.get('api_key')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', True)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = params.get("update_user_enabled")
    create_if_not_exists = params.get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out, get_user_iam_attrs=['id', 'login', 'email'])

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201),
        api_key=api_key,
        manager_email=safe_load_json(args.get('user-profile', {})).get('manageremailaddress'),
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
        return_error(f'Failed to execute {command} command.\nError: {exc}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
import traceback
import base64
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]

'''CLIENT CLASS'''


class Client(BaseClient):
    """ A client class that implements logic to authenticate with the application. """

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, client_id=None,
                 client_secret=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers)
        self.client_id = client_id
        self.client_secret = client_secret
        self.headers = headers
        self.headers['Authorization'] = f'Bearer {self.get_access_token()}'

    def get_access_token(self):
        client_id_and_secret = f'{self.client_id}:{self.client_secret}'

        # Standard Base64 Encoding
        encodedBytes = base64.b64encode(client_id_and_secret.encode("utf-8"))
        encodedStr = str(encodedBytes, "utf-8")

        headers = {
            'Authorization': f'Basic {encodedStr}',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }

        data = {
            'grant_type': 'client_credentials',
            'scope': 'urn:opc:idm:__myscopes__'
        }

        token = self._http_request('POST', url_suffix='/oauth2/v1/token', headers=headers, data=data)
        return token.get('access_token')

    def test(self):
        """ Tests connectivity with the application. """

        return self.get_access_token()

    def get_user_by_id(self, user_id) -> 'IAMUserAppData':
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type user_id: ``str``
        :param user_id: ID of the user

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``IAMUserAppData``
        """
        user_app_data = self._http_request(
            'GET',
            url_suffix=f'/admin/v1/Users/{user_id}',
        )

        if user_app_data:
            user_name = user_app_data.get('userName')
            is_active = user_app_data.get('active')

            return IAMUserAppData(user_id, user_name, is_active, user_app_data)
        return None

    def get_user(self, email: str) -> Optional['IAMUserAppData']:
        """ Queries the user in the application using REST API by its email, and returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type email: ``str``
        :param email: Email address of the user

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """
        query_params = {'filter': f'userName eq "{email}"'}

        res = self._http_request(
            method='GET',
            url_suffix='/admin/v1/Users',
            params=query_params
        )

        if res and res.get('Resources'):
            user_app_data = res.get('Resources')[0]

            user_id = user_app_data.get('id')

            return self.get_user_by_id(user_id)
        return None

    def create_user(self, user_data: Dict[str, Any]) -> 'IAMUserAppData':
        """ Creates a user in the application using REST API.

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: An IAMUserAppData object that contains the data of the created user in the application.
        :rtype: ``IAMUserAppData``
        """
        user_data['schemas'] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
        user_data['emails'] = [user_data['emails']]
        user_data['addresses'] = [user_data['addresses']]

        demisto.log(f'This is the ############# {user_data}')

        user_app_data = self._http_request(
            method='POST',
            url_suffix='/admin/v1/Users',
            json_data=user_data
        )

        user_id = user_app_data.get('user_id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('user_name')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def enable_user(self, user_id: str) -> 'IAMUserAppData':
        """ Enables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {
                    'op': 'replace',
                    'value': {
                        'active': True
                    }
                }
            ]
        }

        user_app_data = self._http_request(
            'PATCH',
            url_suffix=f'/admin/v1/Users/{user_id}',
            json_data=user_data
        )

        if user_app_data:
            user_name = user_app_data.get('userName')
            is_active = user_app_data.get('active')

            return IAMUserAppData(user_id, user_name, is_active, user_app_data)
        return None

    def disable_user(self, user_id: str) -> 'IAMUserAppData':
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        user_data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [
                {
                    'op': 'replace',
                    'value': {
                        'active': False
                    }
                }
            ]
        }

        user_app_data = self._http_request(
            'PATCH',
            url_suffix=f'/admin/v1/Users/{user_id}',
            json_data=user_data
        )

        if user_app_data:
            user_name = user_app_data.get('userName')
            is_active = user_app_data.get('active')

            return IAMUserAppData(user_id, user_name, is_active, user_app_data)
        return None

    def get_group(self, group_id: str):
        """ Disables a user in the application using REST API.

        :type group_id: ``str``
        :param group_id: ID of the group in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        return

    def get_group(self, group_id: str):
        """ Disables a user in the application using REST API.

        :type group_id: ``str``
        :param group_id: ID of the group in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        return

    def get_group(self, group_id: str):
        """ Disables a user in the application using REST API.

        :type group_id: ``str``
        :param group_id: ID of the group in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        return

    def get_group(self, group_id: str):
        """ Disables a user in the application using REST API.

        :type group_id: ``str``
        :param group_id: ID of the group in the application

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        return

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """

        res = self._http_request(
            method='GET',
            url_suffix='admin/v1/Schemas/urn:ietf:params:scim:schemas:core:2.0:User'
        )

        fields = res.get('attributes', [])
        return {field.get('name'): field.get('description') for field in fields}

    @staticmethod
    def handle_exception(user_profile: 'IAMUserProfile',
                         e: Union[DemistoException, Exception],
                         action: 'IAMActions'):
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
    details = res.get('detail')
    return details


'''COMMAND FUNCTIONS'''


def test_module(client: Client):
    """ Tests connectivity with the client. """

    client.test()
    return_results('ok')


def get_group_command(client, args):
    pass


def create_group_command(client, args):
    pass


def update_group_command(client, args):
    pass


def delete_group_command(client, args):
    pass


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
    client_id = params.get('credentials', {}).get('identifier')
    client_secret = params.get('credentials', {}).get('password')
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
                             create_if_not_exists, mapper_in, mapper_out)

    headers = {
        'Content-Type': 'application/scim+json',
        'Accept': 'application/scim+json'
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201),
        client_id=client_id,
        client_secret=client_secret
    )

    demisto.debug(f'Command being called is {command}')

    '''CRUD commands'''

    if command == 'iam-get-user':
        user_profile = iam_command.get_user(client, args)

    elif command == 'iam-create-user':
        user_profile = iam_command.create_user(client, args)

    elif command == 'iam-disable-user':
        user_profile = iam_command.disable_user(client, args)

    if command == 'iam-get-group':
        user_profile = iam_command.get_user(client, args)

    elif command == 'iam-create-group':
        user_profile = iam_command.create_user(client, args)

    elif command == 'iam-update-group':
        user_profile = iam_command.update_user(client, args)

    elif command == 'iam-delete-group':
        user_profile = iam_command.disable_user(client, args)

    if user_profile:
        return_results(user_profile)

    '''non-CRUD commands'''

    try:
        if command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


from IAMApiModule import *  # noqa E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

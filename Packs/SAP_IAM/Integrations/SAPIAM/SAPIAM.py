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

    def __init__(self, base_url: str, verify: bool = True, proxy: bool = False, ok_codes: tuple = None,
                 headers: dict = None, auth: tuple = None, deactivate_uri: str = None, user_id: str = None,
                 email: str = None, user_name: str = None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self.deactivate_uri = deactivate_uri
        self.id = user_id
        self.email = email
        self.user_name = user_name

    def test(self, params):
        """ Tests connectivity with the application. """

        uri = params.get('deactivate_uri')
        return self._http_request(method='GET', url_suffix=uri, resp_type='response')

    def get_user(self, _, user_name: str) -> Optional[IAMUserAppData]:
        """ Returns an IAMUserAppData object
        that holds the user_id, username, is_active and app_data attributes given in the query response.

        :type user_name: ``str``
        :param user_name: userName of the user in the app

        :return: An IAMUserAppData object if user exists, None otherwise.
        :rtype: ``Optional[IAMUserAppData]``
        """

        user_id = self.id if self.id else user_name.split('@')[0]
        is_active = True

        return IAMUserAppData(user_id, user_name, is_active, {})

    def disable_user(self, user_id: str) -> IAMUserAppData:
        """ Disables a user in the application using REST API.

        :type user_id: ``str``
        :param user_id: The ID of the user in the app

        :return: An IAMUserAppData object that contains the data of the user in the application.
        :rtype: ``IAMUserAppData``
        """

        uri = self.deactivate_uri
        user_id = user_id if user_id else self.user_name

        body = {
            'id': user_id,
            'email': self.email,
            'termdate': datetime.now().strftime("%Y/%m/%d")
        }

        res = self._http_request(
            method='POST',
            url_suffix=uri,
            data=body,
        )

        user_app_data = res.get('MT_Account_Terminate_Response')
        is_active = user_app_data.get('IsActive')

        return IAMUserAppData(user_id, self.user_name, is_active, res)

    def get_app_fields(self) -> Dict[str, Any]:
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """

        uri = '/schema'  # TODO: replace to the correct GET Schema API endpoint
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        fields = res.get('result', [])
        return {field.get('name'): field.get('description') for field in fields}

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
    message = res.get('error', {}).get('message')  # TODO: make sure you parse the error details correctly
    details = res.get('error', {}).get('detail')
    return f'{message}: {details}'


'''COMMAND FUNCTIONS'''


def test_module(client: Client, params: dict):
    """ Tests connectivity with the client. """

    res = client.test(params)
    if res.status_code == 200:
        return_results('ok')
    else:
        return_results(res)


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
    params = demisto.params()
    base_url = params.get('url').strip('/')
    deactivate_uri = params.get('deactivate_uri')
    identifier = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    user_profile: Optional[IAMUserProfile] = None
    user_id, email, user_name = '', '', ''

    # Extracting the user ID, email and username to pass to Client. This is needed because IAM Command uses the client
    # get-user When get-user is not supported by the api. So get-user here just returns the fields to allow disable
    # Command to work as expected.
    if args.get('user-profile'):
        incident_type: str = IAMUserProfile.CREATE_INCIDENT_TYPE if command == 'iam-create-user' else \
            IAMUserProfile.UPDATE_INCIDENT_TYPE
        if user_profile := IAMUserProfile(args.get('user-profile'), mapper=mapper_out, incident_type=incident_type):
            user_id = user_profile.get_attribute('id')
            email = user_profile.get_attribute('email')
            user_name = user_profile.get_attribute('username')

    is_disable_enabled = params.get("disable_user_enabled")

    iam_command = IAMCommand(is_disable_enabled=is_disable_enabled, mapper_in=mapper_in, mapper_out=mapper_out,
                             get_user_iam_attrs=['username'])

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        ok_codes=(200, 201),
        headers=headers,
        auth=(identifier, password),
        deactivate_uri=deactivate_uri,
        user_id=user_id,
        email=email,
        user_name=user_name
    )

    demisto.debug(f'Command being called is {command}')

    '''CRUD commands'''

    if command == 'iam-get-user':
        user_profile = iam_command.get_user(client, args)

    elif command == 'iam-disable-user':
        user_profile = iam_command.disable_user(client, args)

    if user_profile:
        return_results(user_profile)

    '''non-CRUD commands'''

    try:
        if command == 'test-module':
            test_module(client, params)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception as exc:
        # For any other integration command exception, return an error
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command. Error:\n{exc}', error=exc)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()

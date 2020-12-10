import demistomock as demisto
from CommonServerPython import *
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


ERROR_CODES_TO_SKIP = [
    404
]

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    ServiceNow IAM Client class that implements logic to authenticate with the application.
    """

    def test(self):
        """ Tests connectivity to server.
        """
        uri = '/test'                                 # TODO: replace to a valid test API endpoint
        self._http_request(method='GET', url_suffix=uri)

    def get_user(self, email):
        """ Gets the user data from the application by email using REST API

        :type email: ``str``
        :param email: Email address of the user

        :return: A tuple of the user ID, username, activation status and the full user data
        :rtype: ``Tuple[str, str, str, Dict[str, Any]]``
        """
        uri = '/users'                               # TODO: replace to the correct GET User API endpoint
        query_params = {'email': email}              # TODO: replace to the correct query parameters

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )

        if res and len(res.get('result', [])) == 1:  # TODO: make sure you verify a single result was retrieved
            user_app_data = res.get('result')[0]     # TODO: then get the user_id, username, is_active and user_app_data

            user_id = user_app_data.get('user_id')
            is_active = user_app_data.get('active')
            username = user_app_data.get('user_name')

            return user_id, username, is_active, user_app_data
        return None, None, None, None

    def create_user(self, user_data):
        """ Creates a user in the application using REST API

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: The full created user data
        :rtype: ``Dict[str, Any]``
        """
        uri = '/users'
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data
        )
        return res.get('result')

    def update_user(self, user_id, user_data):
        """ Updates a user in the application using REST API

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :type user_data: ``Dict[str, Any]``
        :param user_data: User data in the application format

        :return: The full updated user data
        :rtype: ``Dict[str, Any]``
        """
        uri = f'/users/{user_id}'
        res = self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data
        )
        return res.get('result')

    def enable_user(self, user_id):
        """ Enables a user in the application using REST API

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: The full enabled user data
        :rtype: ``Dict[str, Any]``
        """
        user_data = {'active': True}
        return self.update_user(user_id, user_data)

    def disable_user(self, user_id):
        """ Disables a user in the application using REST API

        :type user_id: ``str``
        :param user_id: ID of the user in the application

        :return: The full disabled user data
        :rtype: ``Dict[str, Any]``
        """
        user_data = {'active': False}
        return self.update_user(user_id, user_data)

    def get_app_fields(self):
        """ Gets a dictionary of the user schema fields in the application and their description.

        :return: The user schema fields dictionary
        :rtype: ``Dict[str, str]``
        """
        uri = '/schema'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        fields = res.get('result', [])
        return {field.get('name'): field.get('description') for field in fields}

    @staticmethod
    def handle_exception(user_profile, e, action):
        """ Handles failed responses from the application API by setting the User Profile object with the result.
            The result entity should contain the following data:
            1. action        (``IAMActions``)       The failed action                       Required
            2. success       (``bool``)             The success status                      Optional (by default, True)
            3. skip          (``bool``)             Whether or not the command was skipped  Optional (by default, False)
            3. skip_reason   (``str``)              Skip reason                             Optional (by default, None)
            4. error_code    (``Union[str, int]``)  HTTP error code                         Optional (by default, None)
            5. error_message (``str``)              The error description                   Optional (by default, None)

            Note: This is the place to determine how to handle specific edge cases from the API,
                  e.g., when a DISABLE action was made on a user which is already disabled or does not exist.

        :type user_profile: ``Dict[str, Any]``
        :param user_profile: The user profile object

        :type e: ``Union[DemistoException, Exception]``
        :param e: The exception object - if type is DemistoException, holds the response json object (`res` attribute)

        :type action: ``IAMActions``
        :param action: An enum represents the current action (GET, UPDATE, CREATE, DISABLE or ENABLE)
        """
        if e.__class__ is DemistoException and hasattr(e, 'res') and e.res is not None:
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


def get_error_details(res):
    """ Parses the error details retrieved from the application and outputs the resulted string.

    Args:
        res (dict): The data retrieved from the application.

    Returns:
        (str) The parsed error details.
    """
    message = res.get('error', {}).get('message')
    details = res.get('error', {}).get('detail')
    return f'{message}: {details}'


'''COMMAND FUNCTIONS'''


def test_module(client):
    client.test()
    return_results('ok')


def main():
    user_profile = None
    params = demisto.params()
    base_url = urljoin(params['url'].strip('/'), '/api/now/')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out)

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
        auth=(username, password)
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
            return_results(iam_command.get_mapping_fields(client))

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

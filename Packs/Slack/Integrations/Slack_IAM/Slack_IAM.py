import demistomock as demisto
from CommonServerPython import *
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Slack IAM Client class that implements logic to authenticate with Slack.
    """

    def test(self):
        uri = '/Users?count=1'
        res = self._http_request(method='GET', url_suffix=uri)
        return res

    def get_user(self, email):
        uri = '/Users'
        query_params = {
            'filter': f'email eq {email}'
        }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )
        if res and res.get('totalResults') == 1:
            user_app_data = res.get('Resources')[0]
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('active')
            username = user_app_data.get('userName')
            return IAMUserAppData(user_id, username, is_active, user_app_data)
        return None

    def create_user(self, user_data):
        uri = '/Users'
        user_data["schemas"] = ["urn:scim:schemas:core:1.0"]  # Mandatory user profile field.
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def update_user(self, user_id, user_data):
        uri = f'/Users/{user_id}'
        res = self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def disable_user(self, user_id):
        user_data = {'active': False}
        return self.update_user(user_id, user_data)

    def get_app_fields(self):
        app_fields = {}
        uri = '/Schemas/Users'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        elements = res.get('attributes', [])
        for elem in elements:
            if elem.get('name'):
                field_name = elem.get('name')
                description = elem.get('description')
                app_fields[field_name] = description

        return app_fields

    @staticmethod
    def handle_exception(user_profile, e, action):
        """ Handles failed responses from the application API by setting the User Profile object with the results.

        Args:
            user_profile (IAMUserProfile): The User Profile object.
            e (Exception): The exception error. If DemistoException, holds the response json.
            action (IAMActions): An enum represents the current action (get, update, create, etc).
        """
        if e.__class__ is DemistoException and hasattr(e, 'res') and e.res is not None:
            error_code = e.res.status_code
            try:
                resp = e.res.json()
                error_message = resp.get('Errors', {}).get('description')
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


'''COMMAND FUNCTIONS'''


def test_module(client):
    client.test()
    return_results('ok')


def get_mapping_fields(client: Client) -> GetMappingFieldsResponse:
    """ Creates and returns a GetMappingFieldsResponse object of the user schema in the application

    :param client: (Client) The integration Client object that implements a get_app_fields() method
    :return: (GetMappingFieldsResponse) An object that represents the user schema
    """
    app_fields = client.get_app_fields()
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.INDICATOR_TYPE)

    for field, description in app_fields.items():
        incident_type_scheme.add_field(field, description)

    return GetMappingFieldsResponse([incident_type_scheme])


def main():
    user_profile = None
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    access_token = params.get('access_token')

    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    is_create_enabled = params.get("create_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out)

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    client = Client(
        base_url='https://api.slack.com/scim/v1/',
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200, 201)
    )

    demisto.debug(f'Command being called is {command}')

    if command == 'iam-get-user':
        user_profile = iam_command.get_user(client, args)

    elif command == 'iam-create-user':
        user_profile = iam_command.create_user(client, args)

    elif command == 'iam-update-user':
        user_profile = iam_command.update_user(client, args)

    elif command == 'iam-disable-user':
        user_profile = iam_command.disable_user(client, args)

    if user_profile:
        # user_profile.return_outputs()
        return_results(user_profile)

    try:
        if command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields(client))

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


from IAMApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

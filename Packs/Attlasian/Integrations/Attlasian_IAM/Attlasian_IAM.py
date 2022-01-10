import demistomock as demisto
from CommonServerPython import *
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Atlassian IAM Client class that implements logic to authenticate with Atlassian.
    """
    def __init__(self, base_url, directory_id, headers, ok_codes=None, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.directory_id = directory_id

    def test(self):
        uri = f'/scim/directory/{self.directory_id}/Users?count=1'
        res = self._http_request(method='GET', url_suffix=uri)
        return res

    def get_user(self, filter_name, filter_value):
        uri = f'/scim/directory/{self.directory_id}/Users'
        query_params = {
            'filter': f'{filter_name} eq "{filter_value}"'
        }

        if filter_name == 'id':
            uri += f'/{filter_value}'
            query_params = {}

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )
        if res:
            user_app_data = res.get('Resources')[0] if res.get('totalResults') == 1 else res
            user_id = user_app_data.get('id')
            is_active = user_app_data.get('active')
            username = user_app_data.get('userName')
            email = get_first_primary_email_by_scim_schema(user_app_data)

            return IAMUserAppData(user_id, username, is_active, user_app_data, email)
        return None

    def create_user(self, user_data):
        if isinstance(user_data.get('emails'), dict):
            user_data['emails'] = [user_data['emails']]
        uri = f'/scim/directory/{self.directory_id}/Users'
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')
        email = get_first_primary_email_by_scim_schema(user_app_data)

        return IAMUserAppData(user_id, username, is_active, user_app_data, email)

    def update_user(self, user_id, user_data):
        if isinstance(user_data.get('emails'), dict):
            user_data['emails'] = [user_data['emails']]
        uri = f'/scim/directory/{self.directory_id}/Users/{user_id}'
        res = self._http_request(
            method='PUT',
            url_suffix=uri,
            json_data=user_data
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def disable_user(self, user_id):
        uri = f'/scim/directory/{self.directory_id}/Users/{user_id}'
        res = self._http_request(
            method='DELETE',
            url_suffix=uri
        )
        user_app_data = res
        user_id = user_app_data.get('id')
        is_active = user_app_data.get('active')
        username = user_app_data.get('userName')

        return IAMUserAppData(user_id, username, is_active, user_app_data)

    def get_app_fields(self):
        app_fields = {}
        uri = f'/scim/directory/{self.directory_id}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User'
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
                error_message = resp.get('detail')
            except ValueError:
                error_message = str(e)
        else:
            error_code = ''
            error_message = str(e)

        if error_code == 204:
            user_profile.set_result(action=action,
                                    success=True,
                                    details='The user was successfully disabled.')

        user_profile.set_result(action=action,
                                success=False,
                                error_code=error_code,
                                error_message=f'{error_message}\n{traceback.format_exc()}')

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
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

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
    base_url = params.get('url')
    if base_url[-1] != '/':
        base_url += '/'
    access_token = params.get('access_token')
    directory_id = params.get('directory_id')

    mapper_in = params.get('mapper_in')
    mapper_out = params.get('mapper_out')
    is_create_enabled = params.get("create_user_enabled")
    is_disable_enabled = params.get("disable_user_enabled")
    is_enable_enabled = params.get("enable_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    iam_command = IAMCommand(is_create_enabled, is_enable_enabled, is_disable_enabled, is_update_enabled,
                             create_if_not_exists, mapper_in, mapper_out,
                             get_user_iam_attrs=['id', 'userName', 'emails'])

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    client = Client(
        base_url=base_url,
        directory_id=directory_id,
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

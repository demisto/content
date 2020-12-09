import demistomock as demisto
from CommonServerPython import *
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    ServiceNow IAM Client class that implements logic to authenticate with the application.
    """

    def test(self):
        uri = '/table/sys_user?sysparm_limit=1'
        self._http_request(method='GET', url_suffix=uri)

    def get_user(self, email):
        uri = 'table/sys_user'
        query_params = {
            'email': email
        }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )

        if res and len(res.get('result', [])) == 1:
            return res.get('result')[0]
        return None

    def create_user(self, user_data):
        uri = 'table/sys_user'
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=user_data
        )
        return res.get('result')

    def update_user(self, user_id, user_data):
        uri = f'/table/sys_user/{user_id}'
        res = self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=user_data
        )
        return res.get('result')

    def enable_user(self, user_id):
        user_data = {'active': True, 'locked_out': False}
        return self.update_user(user_id, user_data)

    def disable_user(self, user_id):
        user_data = {'active': False}
        return self.update_user(user_id, user_data)

    def get_app_fields(self):
        service_now_fields = {}
        uri = 'table/sys_dictionary?sysparm_query=name=sys_user'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        elements = res.get('result', [])
        for elem in elements:
            if elem.get('element'):
                field_name = elem.get('element')
                description = elem.get('sys_name')
                service_now_fields[field_name] = description

        return service_now_fields

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
        res (dict): The data retrieved from ServiceNow.

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

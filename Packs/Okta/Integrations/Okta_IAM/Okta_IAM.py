import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
# noqa: F401
# noqa: F401


import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''


INCOMING_MAPPER = 'User Profile - Okta (Incoming)'
OUTGOING_MAPPER = 'User Profile - Okta (Outgoing)'

DEPROVISIONED_STATUS = 'DEPROVISIONED'
USER_IS_DIABLED_ERROR = "E0000007"

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Okta IAM Client class that implements logic to authenticate with Okta.

    Attributes:
        base_url (str): Okta API's base URL.
        verify (bool): XSOAR insecure parameter.
        headers (dict): Okta API request headers.
        iam (IAMCommandHelper): An IAM Command Helper class object.
        app_data (dict): The user data, in Okta's format.
        res_json (dict): The last response's json data.
        user_not_found (bool): Whether or not the employee exists in Okta.
        user_id (str): The employee's Okta user ID.
    """

    def __init__(self, base_url: str, verify: bool, token: str, proxy: bool):
        self.base_url = base_url
        self.verify = verify
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'SSWS {token}'
        }
        super().__init__(base_url=base_url,
                         verify=verify,
                         proxy=proxy,
                         headers=headers,
                         ok_codes=(200,))

    def get_user(self, email):
        uri = 'users'
        query_params = {
            'filter': encode_string_results(f'profile.login eq "{email}"')
        }

        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )

        if res and len(res) == 1:
            return res[0]
        return None

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/deactivate'
        res = self._http_request(
            method="POST",
            url_suffix=uri
        )
        return res

    def activate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/activate'
        res = self._http_request(
            method="POST",
            url_suffix=uri
        )
        return res

    def create_user(self, user_data):
        body = {
            'profile': user_data,
            'groupIds': [],
            'credentials': {}
        }
        uri = 'users'
        query_params = {
            'activate': 'true',
            'provider': 'true'
        }
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            data=body,
            params=query_params
        )
        return res

    def update_user(self, user_id, user_data):
        body = {
            "profile": user_data,
            "credentials": {}
        }
        uri = f"users/{user_id}"
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            data=body
        )
        return res

    def iam_command_failure(self):
        if str(self.res_json.get('errorCode')) == USER_IS_DIABLED_ERROR:
            error_msg = 'User is disabled.'
        else:
            error_msg = get_error_details(self.res_json)

        self.iam.return_outputs(success=False,
                                error_code=self.res_json.get('errorCode'),
                                error_message=error_msg,
                                details=self.res_json)

    def iam_command_success(self):
        if demisto.command() == 'disable-user':
            active = False
        elif demisto.command() == 'enable-user':
            active = True
        else:
            active = False if self.res_json.get('status') == DEPROVISIONED_STATUS else True

        self.iam.return_outputs(success=True,
                                iden=self.res_json.get('id'),
                                email=self.res_json.get('profile', {}).get('email'),
                                username=self.res_json.get('profile', {}).get('login'),
                                details=self.res_json,
                                active=active)


'''HELPER FUNCTIONS'''


def get_error_details(res_json):
    error_msg = f'{res_json.get("errorSummary")}. '
    causes = ''
    for idx, cause in enumerate(res_json.get('errorCauses', []), 1):
        causes += f'{idx}. {cause.get("errorSummary")}\n'
    if causes:
        error_msg += f'Reason:\n{causes}'
    return error_msg


'''COMMAND FUNCTIONS'''


def test_module(client):
    uri = 'users/me'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200:
        return_results('ok')
    else:
        raise Exception(f'Failed: Error Code: {res.status_code}. Error Response: {res.json()}')


def get_user_command(client, args, incoming_mapper):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    okta_user = client.get_user(user_profile.email)
    if not okta_user:
        error_code, error_message = IAMErrors.USER_NOT_FOUND
        user_profile.set_result(
            success=False,
            error_code=error_code,
            error_message=error_message
        )
    else:
        user_profile.update_with_app_data(data=okta_user, incoming_mapper)
        user_profile.set_result(
            success=True,
            active=active, # todo
            iden=user_profile.id,
            username=bla,
            email=bla,
            details=okta_user
        )
    return user_profile


def enable_user_command(client, args):
    if demisto.params().get("enable-disable-user-enabled"):
        if client.user_id:
            success = client.activate_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        else:
            if client.user_not_found and args.get('create-if-not-exists') == 'true':
                create_user_command(client, args)
            else:
                client.iam_command_failure()


def disable_user_command(client, args):
    if demisto.params().get("enable-disable-user-enabled"):
        if client.user_id:
            success = client.deactivate_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        else:
            if client.user_not_found:
                return_outputs('Skipping - user does not exist.')
            else:
                client.iam_command_failure()


def create_user_command(client, args):
    if demisto.params().get("create-user-enabled"):
        if client.user_not_found:
            success = client.create_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        elif client.user_id:
            return_outputs('Skipping - user already exist.')
        else:
            client.iam_command_failure()


def update_user_command(client, args):
    if demisto.params().get("update-user-enabled"):
        if client.user_id:
            success = client.update_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        else:
            if client.user_not_found and args.get('create-if-not-exists') == 'true':
                create_user_command(client, args)
            else:
                client.iam_command_failure()


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    handle_proxy()
    params = demisto.params()
    base_url = urljoin(params['url'].strip('/'), '/api/v1/')
    token = params.get('apitoken')
    incoming_mapper = params.get('incoming_mapper')
    verify_certificate = not params.get('insecure', False)
    command = demisto.command()
    args = demisto.args()

    LOG(f'Command being called is {command}')

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        token=token
    )

    try:
        if command == 'get-user':
            return_results(get_user_command(client, args, incoming_mapper))
        elif command == 'create-user':
            return_results(get_user_command(client, args, incoming_mapper))
        elif command == 'update-user':
            return_results(get_user_command(client, args, incoming_mapper))
        elif command == 'disable-user':
            return_results(get_user_command(client, args, incoming_mapper))
        elif command == 'enable-user':
            return_results(get_user_command(client, args, incoming_mapper))
        elif command == 'test-module':
            test_module(client)

    # Log exceptions
    except DemistoException as e:
        return_results(handle_error(e.res))  # todo


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

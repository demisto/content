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
        self._http_request(
            method="POST",
            url_suffix=uri
        )

    def activate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/activate'
        self._http_request(
            method="POST",
            url_suffix=uri
        )

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


'''HELPER FUNCTIONS'''


def iam_command_failure(user_profile, e):
    error_code = e.res.get('errorCode')

    if error_code == USER_IS_DIABLED_ERROR:
        error_message = 'User is disabled'
    else:
        error_message = e.res.get('errorMessage')

    user_profile.set_result(success=False,
                            error_code=error_code,
                            error_message=error_message,
                            details=e.res)


def iam_command_success(user_profile, okta_user):
    if demisto.command() == 'disable-user':
        active = False
    elif demisto.command() == 'enable-user':
        active = True
    else:
        active = False if okta_user.get('status') == DEPROVISIONED_STATUS else True

    user_profile.set_result(
        success=True,
        active=active,
        iden=okta_user.get('id'),
        email=okta_user.get('profile', {}).get('email'),
        username=okta_user.get('profile', {}).get('login'),
        details=okta_user
    )


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
    res = client._http_request(method='GET', url_suffix=uri)
    return_results('ok')


def get_user_command(client, args, incoming_mapper):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    try:
        okta_user = client.get_user(user_profile.email)
        if not okta_user:
            error_code, error_message = IAMErrors.USER_NOT_FOUND
            user_profile.set_result(success=False, error_code=error_code, error_message=error_message)
        else:
            user_profile.update_with_app_data(okta_user, incoming_mapper)
            iam_command_success(user_profile, okta_user)

    except DemistoException as e:
        iam_command_failure(user_profile, e)

    return user_profile


def enable_user_command(client, args, outgoing_mapper, is_command_enabled, is_create_user_enabled):
    if is_command_enabled:
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        try:
            okta_user = client.get_user(user_profile.email)
            if not okta_user:
                if args.get('create-if-not-exists').lower() == 'true':
                    user_profile.set_command_name('create')
                    user_profile = create_user_command(client, args, outgoing_mapper, is_create_user_enabled)
                else:
                    return_outputs('Skipping - user does not exist.')
            else:
                client.activate_user(okta_user.get('id'))
                iam_command_success(user_profile, okta_user)

        except DemistoException as e:
            iam_command_failure(user_profile, e)

        return user_profile


def disable_user_command(client, args, is_command_enabled):
    if is_command_enabled:
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        try:
            okta_user = client.get_user(user_profile.email)
            if not okta_user:
                return_outputs('Skipping - user does not exist.')
            else:
                client.deactivate_user(okta_user.get('id'))
                iam_command_success(user_profile, okta_user)

        except DemistoException as e:
            iam_command_failure(user_profile, e)

        return user_profile


def create_user_command(client, args, outgoing_mapper, is_command_enabled):
    if is_command_enabled:
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        try:
            okta_user = client.get_user(user_profile.email)
            if okta_user:
                return_outputs('Skipping - user already exist.')
            else:
                okta_profile = user_profile.map_object(outgoing_mapper)
                created_user = client.create_user(okta_profile)
                user_profile.set_id(created_user.get('id'))
                iam_command_success(user_profile, okta_user)

        except DemistoException as e:
            iam_command_failure(user_profile, e)

        return user_profile


def update_user_command(client, args, outgoing_mapper, is_command_enabled, is_create_user_enabled):
    if is_command_enabled:
        user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        try:
            okta_user = client.get_user(user_profile.email)
            if okta_user:
                okta_profile = user_profile.map_object(outgoing_mapper)
                updated_user = client.update_user(okta_profile)
                user_profile.set_id(updated_user.get('id'))
                iam_command_success(user_profile, okta_user)
            else:
                if args.get('create-if-not-exists').lower() == 'true':
                    user_profile.set_command_name('create')
                    user_profile = create_user_command(client, args, outgoing_mapper, is_create_user_enabled)
                else:
                    return_outputs('Skipping - user does not exist.')

        except DemistoException as e:
            iam_command_failure(user_profile, e)

        return user_profile

    if is_command_enabled:
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
    incoming_mapper = params.get('incoming-mapper')
    outgoing_mapper = params.get('outgoing-mapper')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_user_enabled = params.get("create-user-enabled")
    is_enable_disable_user_enabled = params.get("enable-disable-user-enabled")
    is_update_user_enabled = demisto.params().get("update-user-enabled")

    LOG(f'Command being called is {command}')

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        token=token,
        proxy=proxy
    )

    try:
        if command == 'get-user':
            user_profile = get_user_command(
                client,
                args,
                incoming_mapper
            )
            return_results(user_profile)

        elif command == 'create-user':
            user_profile = create_user_command(
                client,
                args,
                outgoing_mapper,
                is_create_user_enabled
            )
            return_results(user_profile)

        elif command == 'update-user':
            user_profile = update_user_command(
                client,
                args,
                outgoing_mapper,
                is_update_user_enabled,
                is_create_user_enabled
            )
            return_results(user_profile)

        elif command == 'disable-user':
            user_profile = disable_user_command(
                client,
                args,
                is_enable_disable_user_enabled
            )
            return_results(user_profile)

        elif command == 'enable-user':
            user_profile = enable_user_command(
                client,
                args,
                outgoing_mapper,
                is_enable_disable_user_enabled,
                is_create_user_enabled
            )
            return_results(user_profile)

        elif command == 'test-module':
            test_module(client)

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

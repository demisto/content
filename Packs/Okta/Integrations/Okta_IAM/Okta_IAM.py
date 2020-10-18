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
USER_IS_DISABLED_ERROR = 'E0000007'
ERROR_CODES_TO_SKIP = [
    'E0000016',  # user is already enabled
    USER_IS_DISABLED_ERROR
]

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Okta IAM Client class that implements logic to authenticate with Okta.

    Attributes:
        base_url (str): Okta API's base URL.
        verify (bool): XSOAR insecure parameter.
        headers (dict): Okta API request headers.
        proxy (bool): Whether to run the integration using the system proxy.
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

    def test(self):
        uri = 'users/me'
        self._http_request(method='GET', url_suffix=uri)

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
            data=json.dumps(body),
            params=query_params
        )
        return res

    def update_user(self, user_id, user_data):
        body = {
            "profile": user_data
        }
        uri = f"users/{user_id}"
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            data=json.dumps(body)
        )
        return res


'''HELPER FUNCTIONS'''


def iam_command_failure(user_profile, e=None, iam_error=None, skip_command=False):
    """ Handles failed responses from Okta API by preparing the User Profile object with the failure data.

    Args:
        user_profile (￿IAMUserProfile): The User Profile object.
        e (DemistoException): The exception error that holds the response json (optional).
        iam_error (IAMErrors): An IAMErrors enum object that indicates the error reason (optional).
        skip_command (bool): If false then the command should fail, otherwise - should be skipped.
    """
    if iam_error:
        error_code, error_message = iam_error
    else:
        error_code = e.res.get('errorCode')
        error_message = get_error_details(e.res)
        if error_code == USER_IS_DISABLED_ERROR:
            error_message = 'Deactivation failed because the user is already disabled'

    if error_code in ERROR_CODES_TO_SKIP or skip_command:
        user_profile.set_result(skip=True,
                                skip_reason=error_message)
    else:
        user_profile.set_result(success=False,
                                error_code=error_code,
                                error_message=error_message,
                                details=e.res)


def iam_command_success(user_profile, okta_user):
    """ Handles successful responses from Okta API by preparing the User Profile object with the user data.

    Args:
        user_profile (￿IAMUserProfile): The User Profile object.
        okta_user (dict): The data retrieved from Okta.
    """
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


def get_error_details(res):
    """ Parses the error details retrieved from Okta and outputs the resulted string.

    Args:
        res (dict): The data retrieved from Okta.

    Returns:
        (str) The parsed error details.
    """
    error_msg = f'{res.get("errorSummary")}. '
    causes = ''
    for idx, cause in enumerate(res.get('errorCauses', []), 1):
        causes += f'{idx}. {cause.get("errorSummary")}\n'
    if causes:
        error_msg += f'Reason:\n{causes}'
    return error_msg


'''COMMAND FUNCTIONS'''


def test_module(client):
    client.test()
    return_results('ok')


def get_user_command(client, args, mapper_in):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    try:
        okta_user = client.get_user(user_profile.email)
        if not okta_user:
            iam_command_failure(user_profile, iam_error=IAMErrors.USER_DOES_NOT_EXIST)
        else:
            user_profile.update_with_app_data(okta_user, mapper_in)
            iam_command_success(user_profile, okta_user)

    except DemistoException as e:
        iam_command_failure(user_profile, e)

    return user_profile


def enable_user_command(client, args, mapper_out, is_command_enabled, is_create_user_enabled):
    if not is_command_enabled:
        return None

    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    try:
        okta_user = client.get_user(user_profile.email)
        if not okta_user:
            if args.get('create-if-not-exists').lower() == 'true':
                user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled,
                                                   set_command_name=True)
            else:
                iam_command_failure(user_profile, iam_error=IAMErrors.USER_DOES_NOT_EXIST, skip_command=True)
        else:
            client.activate_user(okta_user.get('id'))
            iam_command_success(user_profile, okta_user)

    except DemistoException as e:
        iam_command_failure(user_profile, e)

    return user_profile


def disable_user_command(client, args, is_command_enabled):
    if not is_command_enabled:
        return None

    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    try:
        okta_user = client.get_user(user_profile.email)
        if not okta_user:
            iam_command_failure(user_profile, iam_error=IAMErrors.USER_DOES_NOT_EXIST, skip_command=True)
        else:
            client.deactivate_user(okta_user.get('id'))
            iam_command_success(user_profile, okta_user)

    except DemistoException as e:
        iam_command_failure(user_profile, e)

    return user_profile


def create_user_command(client, args, mapper_out, is_command_enabled, set_command_name=False):
    if not is_command_enabled:
        return None

    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    if set_command_name:
        user_profile.set_command_name('create')
    try:
        okta_user = client.get_user(user_profile.email)
        if okta_user:
            iam_command_failure(user_profile, iam_error=IAMErrors.USER_ALREADY_EXISTS, skip_command=True)
        else:
            okta_profile = user_profile.map_object(mapper_out)
            created_user = client.create_user(okta_profile)
            iam_command_success(user_profile, created_user)

    except DemistoException as e:
        iam_command_failure(user_profile, e)

    return user_profile


def update_user_command(client, args, mapper_out, is_command_enabled, is_create_user_enabled):
    if not is_command_enabled:
        return None

    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    try:
        okta_user = client.get_user(user_profile.email)
        if okta_user:
            user_id = okta_user.get('id')
            okta_profile = user_profile.map_object(mapper_out)
            updated_user = client.update_user(user_id, okta_profile)
            iam_command_success(user_profile, updated_user)
        else:
            if args.get('create-if-not-exists').lower() == 'true':
                user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled,
                                                   set_command_name=True)
            else:
                iam_command_failure(user_profile, iam_error=IAMErrors.USER_DOES_NOT_EXIST, skip_command=True)

    except DemistoException as e:
        iam_command_failure(user_profile, e)

    return user_profile


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    user_profile = None
    params = demisto.params()
    base_url = urljoin(params['url'].strip('/'), '/api/v1/')
    token = params.get('apitoken')
    mapper_in = params.get('mapper-in')
    mapper_out = params.get('mapper-out')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    is_create_enabled = params.get("create-user-enabled")
    is_enable_disable_enabled = params.get("enable-disable-user-enabled")
    is_update_enabled = demisto.params().get("update-user-enabled")

    LOG(f'Command being called is {command}')

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        token=token,
        proxy=proxy
    )

    try:
        if command == 'get-user':
            user_profile = get_user_command(client, args, mapper_in)

        elif command == 'create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled)

        elif command == 'update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled, is_create_enabled)

        elif command == 'disable-user':
            user_profile = disable_user_command(client, args, is_enable_disable_enabled)

        elif command == 'enable-user':
            user_profile = enable_user_command(client, args, mapper_out, is_enable_disable_enabled, is_create_enabled)

        elif command == 'test-module':
            test_module(client)

        if user_profile:
            return_results(user_profile)

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

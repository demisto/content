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
USER_IS_DISABLED_MSG = 'Deactivation failed because the user is already disabled.'
USER_IS_DISABLED_ERROR = 'E0000007'
ERROR_CODES_TO_SKIP = [
    'E0000016',  # user is already enabled
    USER_IS_DISABLED_ERROR
]

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Okta IAM Client class that implements logic to authenticate with Okta.
    """

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
            'profile': user_data
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
            'profile': user_data
        }
        uri = f'users/{user_id}'
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            data=json.dumps(body)
        )
        return res

    def get_okta_fields(self):
        okta_fields = {}
        uri = 'meta/schemas/user/default'
        res = self._http_request(
            method='GET',
            url_suffix=uri
        )

        base_properties = res.get('definitions', {}).get('base', {}).get('properties', {})
        okta_fields.update({k: base_properties[k].get('title') for k in base_properties.keys()})

        custom_properties = res.get('definitions', {}).get('custom', {}).get('properties', {})
        okta_fields.update({k: custom_properties[k].get('title') for k in custom_properties.keys()})

        return okta_fields


'''HELPER FUNCTIONS'''


def merge(user_profile, full_user_data):
    """ Merges the user_profile and the full user data, such that existing attributes in user_profile will remain as
    they are, but attributes not provided will be added to it.

    Args:
        user_profile (dict): The user profile data, in Okta format.
        full_user_data (dict): The full user data retrieved from Okta.

    Return:
        (dict) The full user profile.
    """
    for attribute, value in full_user_data.get('profile').items():
        if attribute not in user_profile.keys():
            user_profile[attribute] = value

    return user_profile


def handle_exception(user_profile, e, action):
    """ Handles failed responses from Okta API by setting the User Profile object with the results.

    Args:
        user_profile (IAMUserProfile): The User Profile object.
        e (DemistoException): The exception error that holds the response json.
        action (IAMActions): An enum represents the current action (get, update, create, etc).
    """
    error_code = e.res.get('errorCode')
    error_message = get_error_details(e.res)
    if error_code == USER_IS_DISABLED_ERROR:
        error_message = USER_IS_DISABLED_MSG

    if error_code in ERROR_CODES_TO_SKIP:
        user_profile.set_result(action=action,
                                skip=True,
                                skip_reason=error_message)
    else:
        user_profile.set_result(action=action,
                                success=False,
                                error_code=error_code,
                                error_message=error_message,
                                details=e.res)


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


def get_mapping_fields_command(client):
    okta_fields = client.get_okta_fields()
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.INDICATOR_TYPE)

    for field, description in okta_fields.items():
        incident_type_scheme.add_field(field, description)

    return GetMappingFieldsResponse([incident_type_scheme])


def get_user_command(client, args, mapper_in):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    try:
        okta_user = client.get_user(user_profile.get_attribute('email'))
        if not okta_user:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            user_profile.set_result(action=IAMActions.GET_USER,
                                    success=False,
                                    error_code=error_code,
                                    error_message=error_message)
        else:
            user_profile.update_with_app_data(okta_user, mapper_in)
            user_profile.set_result(
                action=IAMActions.GET_USER,
                success=True,
                active=False if okta_user.get('status') == DEPROVISIONED_STATUS else True,
                iden=okta_user.get('id'),
                email=okta_user.get('profile', {}).get('email'),
                username=okta_user.get('profile', {}).get('login'),
                details=okta_user
            )

    except DemistoException as e:
        handle_exception(user_profile, e, IAMActions.GET_USER)

    return user_profile


def enable_user_command(client, args, mapper_out, is_command_enabled, is_create_user_enabled, create_if_not_exists):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.ENABLE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            okta_user = client.get_user(user_profile.get_attribute('email'))
            if not okta_user:
                if create_if_not_exists:
                    user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled)
                else:
                    _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.ENABLE_USER,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                client.activate_user(okta_user.get('id'))
                user_profile.set_result(
                    action=IAMActions.ENABLE_USER,
                    success=True,
                    active=True,
                    iden=okta_user.get('id'),
                    email=okta_user.get('profile', {}).get('email'),
                    username=okta_user.get('profile', {}).get('login'),
                    details=okta_user
                )

        except DemistoException as e:
            handle_exception(user_profile, e, IAMActions.ENABLE_USER)

    return user_profile


def disable_user_command(client, args, is_command_enabled):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.DISABLE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            okta_user = client.get_user(user_profile.get_attribute('email'))
            if not okta_user:
                _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                user_profile.set_result(action=IAMActions.DISABLE_USER,
                                        skip=True,
                                        skip_reason=error_message)
            else:
                client.deactivate_user(okta_user.get('id'))
                user_profile.set_result(
                    action=IAMActions.DISABLE_USER,
                    success=True,
                    active=False,
                    iden=okta_user.get('id'),
                    email=okta_user.get('profile', {}).get('email'),
                    username=okta_user.get('profile', {}).get('login'),
                    details=okta_user
                )

        except DemistoException as e:
            handle_exception(user_profile, e, IAMActions.DISABLE_USER)

    return user_profile


def create_user_command(client, args, mapper_out, is_command_enabled):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.CREATE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            okta_user = client.get_user(user_profile.get_attribute('email'))
            if okta_user:
                _, error_message = IAMErrors.USER_ALREADY_EXISTS
                user_profile.set_result(action=IAMActions.CREATE_USER,
                                        skip=True,
                                        skip_reason=error_message)
            else:
                okta_profile = user_profile.map_object(mapper_out)
                created_user = client.create_user(okta_profile)
                user_profile.set_result(
                    action=IAMActions.CREATE_USER,
                    success=True,
                    active=False if created_user.get('status') == DEPROVISIONED_STATUS else True,
                    iden=created_user.get('id'),
                    email=created_user.get('profile', {}).get('email'),
                    username=created_user.get('profile', {}).get('login'),
                    details=created_user
                )

        except DemistoException as e:
            handle_exception(user_profile, e, IAMActions.CREATE_USER)

    return user_profile


def update_user_command(client, args, mapper_out, is_command_enabled, is_create_user_enabled, create_if_not_exists):
    user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
    if not is_command_enabled:
        user_profile.set_result(action=IAMActions.UPDATE_USER,
                                skip=True,
                                skip_reason='Command is disabled.')
    else:
        try:
            okta_user = client.get_user(user_profile.get_attribute('email'))
            if okta_user:
                user_id = okta_user.get('id')
                okta_profile = user_profile.map_object(mapper_out)
                full_okta_profile = merge(okta_profile, okta_user)
                updated_user = client.update_user(user_id, full_okta_profile)
                user_profile.set_result(
                    action=IAMActions.UPDATE_USER,
                    success=True,
                    active=False if updated_user.get('status') == DEPROVISIONED_STATUS else True,
                    iden=updated_user.get('id'),
                    email=updated_user.get('profile', {}).get('email'),
                    username=updated_user.get('profile', {}).get('login'),
                    details=updated_user
                )
            else:
                if create_if_not_exists:
                    user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled)
                else:
                    _, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.UPDATE_USER,
                                            skip=True,
                                            skip_reason=error_message)

        except DemistoException as e:
            handle_exception(user_profile, e, IAMActions.UPDATE_USER)

    return user_profile


def main():
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
    create_if_not_exists = demisto.params().get("create-if-not-exists")

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'SSWS {token}'
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy,
        headers=headers,
        ok_codes=(200,)
    )

    demisto.debug(f'Command being called is {command}')

    try:
        if command == 'iam-get-user':
            user_profile = get_user_command(client, args, mapper_in)

        elif command == 'iam-create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled)

        elif command == 'iam-update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                               is_create_enabled, create_if_not_exists)

        elif command == 'iam-disable-user':
            user_profile = disable_user_command(client, args, is_enable_disable_enabled)

        elif command == 'iam-enable-user':
            user_profile = enable_user_command(client, args, mapper_out, is_enable_disable_enabled,
                                               is_create_enabled, create_if_not_exists)

        if user_profile:
            return_results(user_profile)

    except Exception:
        # We don't want to return an error entry CRUD commands execution
        return_results(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')

    try:
        if command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))

    except Exception:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DEFAULT_OUTGOING_MAPPER = "User Profile - GitHub (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - GitHub (Incoming)"


class Client(BaseClient):

    def __init__(self, base_url, token, org, headers, ok_codes=None, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.org = org

    def get_user(self, input_type, user_term):

        uri = f'scim/v2/organizations/{self.org}/' \
              f'Users?filter={input_type} eq {user_term}'

        return self._http_request(
            method='GET',
            url_suffix=uri,
        )

    def create_user(self, data):
        uri = f'scim/v2/organizations/{self.org}/Users'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data,
        )

    def update_user(self, user_term, data):
        uri = f'scim/v2/organizations/{self.org}/Users/{user_term}'
        return self._http_request(
            method='PUT',
            url_suffix=uri,
            json_data=data,
        )

    def disable_user(self, data):
        uri = f'scim/v2/organizations/{self.org}/Users/{data}'
        return self._http_request(
            method='DELETE',
            url_suffix=uri,
            resp_type='text'
        )

    def get_user_id_by_mail(self, email):
        user_id = ""
        uri = f'scim/v2/organizations/{self.org}/Users?filter=emails eq {email}'

        res = self._http_request(
            method='GET',
            url_suffix=uri
        )
        if not res.get('totalResults', 0) == 0:
            if isinstance(res.get('Resources'), list):
                item = res.get('Resources')[0]
                if item:
                    user_id = item.get('id')

        return user_id


def github_handle_error(e):
    try:
        resp = e.res
        error_code = resp.get('errorCode', '')
        error_message = resp.get('errorCauses', str(e))
        if isinstance(error_message, list):
            error_list = []
            for error in error_message:
                if isinstance(error, dict):
                    for key, value in error.items():
                        error_list.append(f'{key}: {value}')
                error_message = str('\n '.join(error_list))
        return error_code, error_message

    except Exception as e:
        error_code = ""
        error_message = str(e)
        return error_code, error_message


def test_module(client):
    uri = ""
    client._http_request(method='GET', url_suffix=uri)
    return 'ok'


def get_user_command(client, args, mapper_in):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        email = iam_user_profile.get_attribute('email')
        res = client.get_user('emails', email)

        if res.get('totalResults', 0) == 0:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(success=False,
                                        email=email,
                                        error_message=error_message,
                                        error_code=error_code,
                                        action=IAMActions.GET_USER)

        else:
            item = res.get('Resources')[0]
            github_user = convert_scheme_to_dict(item)
            iam_user_profile.update_with_app_data(github_user, mapper_in)
            iam_user_profile.set_result(success=True,
                                        iden=item.get('id', None),
                                        email=email,
                                        username=item.get('userName', None),
                                        action=IAMActions.GET_USER,
                                        details=res,
                                        active=item.get('active', None))

        return iam_user_profile

    except Exception as e:
        error_code, error_message = github_handle_error(e)
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=error_message,
                                    action=IAMActions.GET_USER
                                    )
        return iam_user_profile


def create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_create_enabled:
            iam_user_profile.set_result(action=IAMActions.CREATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            email = iam_user_profile.get_attribute('email')
            user_id = client.get_user_id_by_mail(email)

            if user_id:
                # if user exists - update it
                create_if_not_exists = False
                update_user_command(client, args, mapper_out, is_update_enabled,
                                    is_create_enabled, create_if_not_exists)
                _, error_message = IAMErrors.USER_ALREADY_EXISTS
                iam_user_profile.set_result(action=IAMActions.CREATE_USER,
                                            skip=True,
                                            skip_reason=error_message)

            else:
                github_user = iam_user_profile.map_object(mapper_name=mapper_out)
                github_user_schema = generate_user_scheme(github_user)
                res = client.create_user(github_user_schema)
                user_id = res.get('id', None)
                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            email=res.get('email'),
                                            username=res.get('userName'),
                                            action=IAMActions.CREATE_USER,
                                            details=res,
                                            active=True)

        return iam_user_profile

    except Exception as e:
        error_code, error_message = github_handle_error(e)
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=error_message,
                                    action=IAMActions.CREATE_USER
                                    )
        return iam_user_profile


def update_user_command(client, args, mapper_out, is_update_enabled, is_create_enabled, create_if_not_exists):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_update_enabled:
            iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            email = iam_user_profile.get_attribute('email')
            user_id = client.get_user_id_by_mail(email)

            if not user_id:
                # user doesn't exists
                if create_if_not_exists:
                    iam_user_profile = create_user_command(client, args, mapper_out, is_create_enabled, False)
                else:
                    error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                                error_code=error_code,
                                                skip=True,
                                                skip_reason=error_message)
            else:
                github_user = iam_user_profile.map_object(mapper_name=mapper_out)
                github_user_schema = generate_user_scheme(github_user)
                res = client.update_user(user_term=user_id, data=github_user_schema)
                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            email=github_user.get('email'),
                                            username=github_user.get('userName'),
                                            action=IAMActions.UPDATE_USER,
                                            details=res,
                                            active=True)

        return iam_user_profile

    except Exception as e:
        error_code, error_message = github_handle_error(e)
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=error_message,
                                    action=IAMActions.UPDATE_USER
                                    )
        return iam_user_profile


def disable_user_command(client, args, mapper_out, is_disable_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_disable_enabled:
            iam_user_profile.set_result(action=IAMActions.DISABLE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            github_user = iam_user_profile.map_object(mapper_name=mapper_out)
            email = github_user.get('email')
            user_id = client.get_user_id_by_mail(email)

            if not user_id:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                iam_user_profile.set_result(action=IAMActions.DISABLE_USER,
                                            error_code=error_code,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                res = client.disable_user(user_id)
                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            email=email,
                                            username=github_user.get('userName'),
                                            action=IAMActions.DISABLE_USER,
                                            details=res,
                                            active=False)

        return iam_user_profile
    except Exception as e:
        error_code, error_message = github_handle_error(e)
        iam_user_profile.set_result(success=False,
                                    error_code=error_code,
                                    error_message=error_message,
                                    action=IAMActions.DISABLE_USER
                                    )
        return iam_user_profile


def generate_user_scheme(github_user):
    scheme = {'name': {'familyName': github_user.get('familyName'),
                       'givenName': github_user.get('givenName')},
              'userName': github_user.get('userName'),
              'emails': [{'type': 'work', 'primary': True, 'value': github_user.get('email')}]}
    return scheme


def convert_scheme_to_dict(user_scheme):
    user_dict = {}
    for key, value in user_scheme.items():
        if isinstance(value, str):
            user_dict[key] = value
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, str):
                    user_dict[sub_key] = sub_value
        elif isinstance(value, List):
            if not value:
                continue
            elif isinstance(value[0], dict):
                user_dict[key] = value[0].get('value')
    return user_dict


def get_mapping_fields_command():
    scheme = [
        "userName",
        "familyName",
        "givenName",
        "email"
    ]
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.INDICATOR_TYPE)

    for field in scheme:
        incident_type_scheme.add_field(field, "Field")

    return GetMappingFieldsResponse([incident_type_scheme])


def main():

    params = demisto.params()
    args = demisto.args()

    base_url = params.get('url')
    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != '/':
        base_url += '/'
    token = params.get('token')
    org = params.get('org')

    mapper_in = params.get('mapper-in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper-out', DEFAULT_OUTGOING_MAPPER)
    is_create_enabled = params.get("create-user-enabled")
    is_disable_enabled = params.get("disable-user-enabled")
    is_update_enabled = demisto.params().get("update-user-enabled")
    create_if_not_exists = demisto.params().get("create-if-not-exists")

    verify_certificate = not demisto.params().get('insecure', False)

    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    proxy = demisto.params().get('proxy', False)
    command = demisto.command()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            org=org,
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            ok_codes=(200, 201, 204)
        )
        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'iam-get-user':
            user_profile = get_user_command(client, args, mapper_in)
            return_results(user_profile)

        elif command == 'iam-create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled)
            return_results(user_profile)

        elif command == 'iam-update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                               is_create_enabled, create_if_not_exists)
            return_results(user_profile)

        elif command == 'iam-disable-user':
            user_profile = disable_user_command(client, args, mapper_out, is_disable_enabled)
            return_results(user_profile)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

    except Exception as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Exception: {e}. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

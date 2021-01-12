import demistomock as demisto
from CommonServerPython import *
from IAMModule import *
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DEFAULT_OUTGOING_MAPPER = "User Profile - SCIM (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - SCIM (Incoming)"


class Client(BaseClient):

    def __init__(self, base_url, org, headers, ok_codes=None, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.org = org

    def get_user(self, input_type, user_term):

        uri = f'scim/v2/organizations/{self.org}/Users?filter={input_type} eq \"{user_term}\"'

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
        uri = f"scim/v2/organizations/{self.org}/Users?filter=emails eq \"{email}\""

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
    """
    Handles an error from the Github API
    an error example: Error in API call [401] - Unauthorized
    {"message": "Bad credentials", "documentation_url": "https://docs.github.com/rest"}
    The error might contain error_code, error_reason and error_message
    The error_reason and error_message might be the same but usually, the error_reason adds more information that
    the error_message doesn't provide
    examples:
        error_code = 401
        error_message = 'Bad credentials'
        error_reason = 'Unauthorized'
    :param e: the client object
    :return: error_code and  error_message
    """
    try:
        error_code = ""
        error_message = str(e)
        if e.__class__ is DemistoException and e.res is not None:
            error_res = e.res
            if isinstance(error_res, dict):
                error_code = str(error_res.get("status"))
                error_message = str(error_res.get("detail"))
            else:
                error_code = e.res.status_code
                if not e.res.ok:
                    if e.res.json():
                        error_message = error_res.json().get("message", "")
                        if not error_message:
                            error_message = error_res.json().get("detail", "")
                        error_reason = error_res.reason
                        if error_reason and error_reason != error_message:
                            error_message += f' {error_reason}'
        return error_code, error_message

    except Exception as e:
        error_code = ""
        error_message = str(e)
        return error_code, error_message


def test_module(client):
    """
    Trying to get a user by a fake id,
    if the command returns with no errors the connection is ok
    :param client: the client object
    :return: ok if got a valid accesses token
    """
    client.get_user("id", "1234")
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
            github_user = res.get('Resources')[0]
            iam_user_profile.update_with_app_data(github_user, mapper_in)
            iam_user_profile.set_result(success=True,
                                        iden=github_user.get('id', None),
                                        email=email,
                                        username=github_user.get('userName', None),
                                        action=IAMActions.GET_USER,
                                        details=res,
                                        active=github_user.get('active', None))

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
                iam_user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                                       is_create_enabled, create_if_not_exists)

            else:
                github_user = iam_user_profile.map_object(mapper_name=mapper_out)
                # make sure the email is transformer to a list
                emails = github_user.get("emails")
                if not isinstance(emails, list):
                    github_user["emails"] = [emails]

                res = client.create_user(github_user)
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
                emails = github_user.get("emails")
                if not isinstance(emails, list):
                    github_user["emails"] = [emails]

                res = client.update_user(user_term=user_id, data=github_user)
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
            email = iam_user_profile.get_attribute('email')
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


def get_mapping_fields_command():
    scheme = [
        "userName",
        "externalId",
        "title",
        "userType",
        "name",
        "emails",
        "phoneNumbers",
        "urn:scim:schemas:extension:enterprise:1.0"
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

    mapper_in = params.get('mapper_in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper_out', DEFAULT_OUTGOING_MAPPER)
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
            user_profile.return_outputs

        elif command == 'iam-create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled)
            user_profile.return_outputs

        elif command == 'iam-update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                               is_create_enabled, create_if_not_exists)
            user_profile.return_outputs

        elif command == 'iam-disable-user':
            user_profile = disable_user_command(client, args, mapper_out, is_disable_enabled)
            user_profile.return_outputs

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

    except Exception as e:
        # For any other integration command exception, return an error
        return_error(f'Failed to execute {command} command. Exception: {e}. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

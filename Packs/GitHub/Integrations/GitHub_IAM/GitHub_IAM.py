import demistomock as demisto
from CommonServerPython import *
import traceback
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

DEFAULT_OUTGOING_MAPPER = "User Profile - SCIM (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - SCIM (Incoming)"

IAM_GET_USER_ATTRIBUTES = ['id', 'userName', 'emails']


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


def get_user_command(client, args, mapper_in, mapper_out):
    iam_user_profile = IAMUserProfile(user_profile=args.get("user-profile"), mapper=mapper_out,
                                      incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
    try:
        iam_attr, iam_attr_value = iam_user_profile.get_first_available_iam_user_attr(IAM_GET_USER_ATTRIBUTES)
        res = client.get_user(iam_attr, iam_attr_value)

        if res.get('totalResults', 0) == 0:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(success=False,
                                        email=iam_attr_value if iam_attr == 'emails' else None,
                                        username=iam_attr_value if iam_attr == 'userName' else None,
                                        error_message=error_message,
                                        error_code=error_code,
                                        action=IAMActions.GET_USER)

        else:
            github_user = res.get('Resources')[0]
            email_result = iam_user_profile.get_attribute('emails',
                                                          user_profile_data=iam_user_profile.mapped_user_profile)
            if (emails := github_user.get('emails')) and not email_result:
                first_email = emails[0].get('value')
                email_result = next((email.get('value') for email in emails if email.get('primary')), first_email)
            iam_user_profile.update_with_app_data(github_user, mapper_in)
            iam_user_profile.set_result(success=True,
                                        iden=github_user.get('id', None),
                                        email=email_result,
                                        username=github_user.get('userName', None),
                                        action=IAMActions.GET_USER,
                                        details=github_user,
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
        iam_user_profile = IAMUserProfile(user_profile=args.get("user-profile"), mapper=mapper_out,
                                          incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)

        if not is_create_enabled:
            iam_user_profile.set_result(action=IAMActions.CREATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            iam_attr, iam_attr_value = iam_user_profile.get_first_available_iam_user_attr(IAM_GET_USER_ATTRIBUTES)
            get_user_response = client.get_user(iam_attr, iam_attr_value)

            if get_user_response.get('totalResults', 0) > 0:
                # if user exists - update it
                create_if_not_exists = False
                iam_user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                                       is_create_enabled, create_if_not_exists)

            else:
                github_user = iam_user_profile.map_object(mapper_name=mapper_out,
                                                          incident_type=IAMUserProfile.CREATE_INCIDENT_TYPE)
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
        iam_user_profile = IAMUserProfile(user_profile=args.get("user-profile"), mapper=mapper_out,
                                          incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)

        if not is_update_enabled:
            iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            iam_attr, iam_attr_value = iam_user_profile.get_first_available_iam_user_attr(IAM_GET_USER_ATTRIBUTES)
            get_user_response = client.get_user(iam_attr, iam_attr_value)

            if get_user_response.get('totalResults', 0) == 0:
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
                user_id: str = get_user_response.get('Resources')[0].get('id', '')
                github_user = iam_user_profile.map_object(mapper_name=mapper_out,
                                                          incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)
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
        iam_user_profile = IAMUserProfile(user_profile=args.get("user-profile"), mapper=mapper_out,
                                          incident_type=IAMUserProfile.UPDATE_INCIDENT_TYPE)

        if not is_disable_enabled:
            iam_user_profile.set_result(action=IAMActions.DISABLE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')

        else:
            iam_attr, iam_attr_value = iam_user_profile.get_first_available_iam_user_attr(IAM_GET_USER_ATTRIBUTES)
            get_user_response = client.get_user(iam_attr, iam_attr_value)

            if get_user_response.get('totalResults', 0) == 0:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                iam_user_profile.set_result(action=IAMActions.DISABLE_USER,
                                            error_code=error_code,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                user_data = get_user_response.get('Resources')[0]
                user_id: str = user_data.get('id', '')
                username: str = user_data.get('userName')
                res = client.disable_user(user_id)
                iam_user_profile.set_result(success=True,
                                            iden=user_data.get('id', ''),
                                            email=iam_attr_value if iam_attr == 'email' else None,
                                            action=IAMActions.DISABLE_USER,
                                            username=username,
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
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.DEFAULT_INCIDENT_TYPE)

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
            user_profile = get_user_command(client, args, mapper_in, mapper_out)
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


from IAMApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

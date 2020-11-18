import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


DEFAULT_OUTGOING_MAPPER = "User Profile - Salesforce (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - Salesforce (Incoming)"
URI_PREFIX = '/services/data/v44.0/'


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, conn_client_id, conn_client_secret, conn_username,
                 conn_password, headers, verify=True, proxy=False):
        self.base_url = base_url
        self.conn_client_id = conn_client_id
        self.conn_client_secret = conn_client_secret
        self.conn_username = conn_username
        self.conn_password = conn_password
        self.verify = verify
        self.headers = headers
        self.session = requests.Session()
        if not proxy:
            self.session.trust_env = False
        self.get_access_token()

    def get_access_token(self):
        uri = '/services/oauth2/token'
        params = {
            "client_id": self.conn_client_id,
            "client_secret": self.conn_client_secret,
            "username": self.conn_username,
            "password": self.conn_password,
            "grant_type": "password"
        }
        res = self.http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            resp_type='json'
        )
        self.headers['content-type'] = 'application/json'
        if res.get('access_token') is not None:
            self.headers['Authorization'] = "Bearer " + res.get('access_token')
        else:
            self.headers['Authorization'] = None

    def get_user_profile(self, user_term):
        uri = URI_PREFIX + f'sobjects/User/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def search_user_profile(self, user_term, user_where):
        uri = URI_PREFIX + 'parameterizedSearch/'
        params = {
            "q": user_term,
            "sobject": "User",
            "User.where": user_where,
            "User.fields": "Id, IsActive, FirstName, LastName,Email,Username"
        }
        return self.http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def create_user_profile(self, data):
        uri = URI_PREFIX + 'sobjects/User'
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user_profile(self, user_term, data):
        uri = URI_PREFIX + f'sobjects/User/{encode_string_results(user_term)}'
        params = {"_HttpMethod": "PATCH"}
        return self.http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            data=data
        )

    def http_request(self, method, url_suffix, params=None, data=None, resp_type='json'):
        return self._http_request(method=method, url_suffix=url_suffix, params=params, data=data, resp_type=resp_type,
                                  ok_codes=(200, 201, 204))


''' COMMAND FUNCTIONS '''


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: SalesforceITAdmin client
        args  : SalesforceITAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    uri = URI_PREFIX + 'sobjects/User/testid'
    res = client.http_request(method='GET', url_suffix=uri)
    if res.status_code == 200 or res.status_code == 404:
        return 'ok', None, None
    else:
        res_json = res.json()[0]
        error_response = res_json.get('message')
        raise Exception(f"Failed to execute test_module. Error Code: {res.status_code}.Error "
                        f"Response: {error_response}")


def get_user_command(client, args, mapper_out):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)
        salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)

        email = salesforce_user.get('email')

        if not email:
            raise Exception('You must provide a valid email')

        user_id = get_user_id_by_mail(client, email)
        if not user_id:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(success=False,
                                        error_message=error_message,
                                        error_code=error_code,
                                        action=IAMActions.GET_USER)
        else:
            res = client.get_user_profile(user_id)
            res_json = res.json()
            if res.status_code == 200:
                iam_user_profile.set_result(success=True,
                                            iden=res_json.get('Id'),
                                            email=res_json.get('Email'),
                                            username=res_json.get('Username'),
                                            action=IAMActions.GET_USER,
                                            details=res_json,
                                            active=res_json.get('IsActive'))

            else:
                iam_user_profile.set_result(success=False,
                                            email=email,
                                            error_code=res.status_code,
                                            error_message=res_json.get('message'),
                                            action=IAMActions.GET_USER,
                                            details=res_json)
        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.GET_USER
                                    )
        return iam_user_profile


def create_user_command(client, args, mapper_out, is_command_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_command_enabled:
            user_profile.set_result(action=IAMActions.CREATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')

        else:
            salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)

            # Removing empty elements from salesforce_user
            salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}

            res = client.create_user_profile(salesforce_user)

            res_json = res.json()
            if res.status_code == 201:
                iam_user_profile.set_result(success=True,
                                            iden=res_json.get('id'),
                                            email=salesforce_user.get('email'),
                                            username=salesforce_user.get('userName'),
                                            action=IAMActions.CREATE_USER,
                                            details=res_json,
                                            active=True)

            else:
                iam_user_profile.set_result(success=False,
                                            error_code=res.status_code,
                                            error_message=res_json[0].get('message'),
                                            action=IAMActions.CREATE_USER,
                                            )

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.CREATE_USER
                                    )
        return iam_user_profile


def update_user_command(client, args, mapper_out, is_command_enabled, is_create_user_enabled, create_if_not_exists):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_command_enabled:
            user_profile.set_result(action=IAMActions.CREATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')

        else:
            iam_user_profile = IAMUserProfile(user_profile=user_profile)
            salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)

            email = salesforce_user.get('email')
            user_id = get_user_id_by_mail(client, email)

            if not user_id:
                if create_if_not_exists:
                    iam_user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled)
                else:
                    error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.UPDATE_USER,
                                            error_code=error_code,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                # Removing empty elements from salesforce_user
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}

                res = client.update_user_profile(user_term=user_id, data=salesforce_user)

                if res.status_code == 204:
                    iam_user_profile.set_result(success=True,
                                                iden=user_id,
                                                active=True,
                                                action=IAMActions.UPDATE_USER,
                                                details=res.json()
                                                )

                else:
                    res_json = res.json()[0]
                    iam_user_profile.set_result(success=False,
                                                iden=user_id,
                                                error_code=res.status_code,
                                                error_message=res_json.get('message'),
                                                action=IAMActions.UPDATE_USER,
                                                details=res.json()
                                                )

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.UPDATE_USER
                                    )
        return iam_user_profile


def enable_disable_user_command(enable, client, args, mapper_out, is_command_enabled, is_create_user_enabled,
                                create_if_not_exists):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_command_enabled:
            user_profile.set_result(action=IAMActions.CREATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')

        else:
            salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)

            email = salesforce_user.get('email')
            user_id = get_user_id_by_mail(client, email)

            if not user_id:
                if enable and create_if_not_exists:
                    iam_user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled)
                else:
                    error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    user_profile.set_result(action=IAMActions.UPDATE_USER,
                                            error_code=error_code,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                salesforce_user['IsActive'] = enable
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.update_user_profile(user_term=user_id, data=salesforce_user)

                if res.status_code == 204:
                    iam_user_profile.set_result(success=True,
                                                iden=user_id,
                                                active=enable,
                                                action=IAMActions.ENABLE_USER,
                                                details=res.json()
                                                )

                else:
                    res_json = res.json()[0]
                    iam_user_profile.set_result(success=False,
                                                iden=user_id,
                                                error_code=res.status_code,
                                                error_message=res_json.get('message'),
                                                action=IAMActions.ENABLE_USER,
                                                details=res.json()
                                                )

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.ENABLE_USER
                                    )
        return iam_user_profile


def get_user_id_by_mail(client, email):
    """
    Search user by email, if the user exists return the user id, else return ""
    """
    user_id = ''
    user_where = f"Email='{email}'"
    res = client.search_user_profile(email, user_where)
    if res.status_code == 200:
        res_json = res.json()
        search_records = res_json.get('searchRecords')
        if len(search_records) > 0:
            for search_record in search_records:
                user_id = search_record.get('Id')

    return user_id


def get_mapping_fields_command(client):
    # in progress
    return ""


def main():

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get('url')
    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != '/':
        base_url += '/'

    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    secret_token = params.get('secret_token')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    mapper_in = params.get('mapper-in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper-out', DEFAULT_OUTGOING_MAPPER)
    is_create_enabled = params.get("create_user_enabled")
    is_enable_disable_enabled = params.get("enable_disable_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    LOG(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            conn_client_id=client_id,
            conn_client_secret=client_secret,
            conn_username=username,
            conn_password=password + secret_token,
            verify=verify_certificate,
            headers={},
            proxy=proxy)

        if command == 'iam-get-user':
            user_profile = get_user_command(client, args, mapper_out)

        elif command == 'iam-create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled)

        elif command == 'iam-update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                               is_create_enabled, create_if_not_exists)

        elif command == 'iam-disable-user':
            user_profile = enable_disable_user_command(False, client, args, mapper_out, is_enable_disable_enabled,
                                                       is_create_enabled, create_if_not_exists)
        elif command == 'iam-enable-user':
            user_profile = enable_disable_user_command(True, client, args, mapper_out, is_enable_disable_enabled,
                                                       is_create_enabled, create_if_not_exists)

        elif command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))

        if user_profile:
            return_results(user_profile)

    except Exception:
        return_error(f'Failed to execute {command} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


DEFAULT_OUTGOING_MAPPER = "User Profile - Salesforce (Outgoing)"
DEFAULT_INCOMING_MAPPER = "User Profile - Salesforce (Incoming)"
URI_PREFIX = '/services/data/v44.0/'
GENERATE_TOKEN_URL = 'https://login.salesforce.com/services/oauth2/token'

# setting defaults for mandatory fields
MANDATORY_FIELDS = {
    "lastname": "",
    "alias": "",
    "timezonesidkey": "",
    "localesidkey": "en_US",
    "emailencodingkey": "ISO-8859-1",
    "languagelocalekey": "en_US",
    "profileid": "",
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, conn_client_id, conn_client_secret, conn_username, conn_password,
                 ok_codes, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes)
        self._conn_client_id = conn_client_id
        self._conn_client_secret = conn_client_secret
        self._conn_username = conn_username
        self._conn_password = conn_password
        self._instance_url = ""
        self.token = self.get_access_token_()

    def get_access_token_(self):
        params = {
            "client_id": self._conn_client_id,
            "client_secret": self._conn_client_secret,
            "username": self._conn_username,
            "password": self._conn_password,
            "grant_type": "password"
        }
        res = self._http_request(
            method='POST',
            full_url=GENERATE_TOKEN_URL,
            params=params
        )
        token = res.get('access_token')

        headers = {
            'content-type': 'application/json',
            'Authorization': f'Bearer {token}'
        }

        self._headers = headers
        return token

    def get_user(self, user_term):
        uri = URI_PREFIX + f'sobjects/User/{user_term}'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def search_user_profile(self, user_term, user_where):
        uri = URI_PREFIX + 'parameterizedSearch/'
        params = {
            "q": user_term,
            "sobject": "User",
            "User.where": user_where,
            "User.fields": "Id, IsActive, FirstName, LastName, Email, Username"
        }
        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )

    def get_user_id_and_activity_by_mail(self, email):
        # check for errors, what id no user is found?
        user_id = ""
        active = ""
        user_where = f"Email='{email}'"
        res = self.search_user_profile(email, user_where)

        search_records = res.get('searchRecords')
        if len(search_records) > 0:
            for search_record in search_records:
                user_id = search_record.get('Id')
                active = search_record.get('IsActive') == 'true'

        return user_id, active

    def create_user(self, data):
        uri = URI_PREFIX + 'sobjects/User'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=data
        )

    def update_user(self, user_term, data):
        uri = URI_PREFIX + f'sobjects/User/{user_term}'
        params = {"_HttpMethod": "PATCH"}
        return self._http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            json_data=data,
            resp_type='text'
        )

    def get_all_users(self):
        uri = URI_PREFIX + 'parameterizedSearch/'
        params = {
            "q": "User",
            "sobject": "User",
        }
        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=params
        )


def handle_exception(e):
    if e.__class__ is DemistoException and hasattr(e, 'res') and e.res is not None:
        error_code = e.res.status_code
        error_message = e.res.text
    else:
        error_code = ''
        error_message = str(e)

    demisto.error(traceback.format_exc())
    return error_message, error_code


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: SalesforceITAdmin client
        args  : SalesforceITAdmin arguments passed

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.get_user_id_and_activity_by_mail("test@test.com")
    return 'ok'


def get_user_command(client, args, mapper_in):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        email = iam_user_profile.get_attribute('email')
        user_id, _ = client.get_user_id_and_activity_by_mail(email)

        if not user_id:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(success=False,
                                        error_message=error_message,
                                        error_code=error_code,
                                        action=IAMActions.GET_USER)
        else:
            # unlike query with email, getting a user by id will bring back all the attributes
            github_user = client.get_user(user_id)
            iam_user_profile.update_with_app_data(github_user, mapper_in)

            iam_user_profile.set_result(success=True,
                                        iden=github_user.get('Id'),
                                        email=github_user.get('Email'),
                                        username=github_user.get('Username'),
                                        action=IAMActions.GET_USER,
                                        details=github_user,
                                        active=True if github_user.get('IsActive') == "true" else False)

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
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
            user_id, _ = client.get_user_id_and_activity_by_mail(email)

            if user_id:
                create_if_not_exists = False
                iam_user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                                       is_create_enabled, create_if_not_exists)

            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)
                # Removing empty elements from salesforce_user
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                salesforce_user = check_and_set_manndatory_fields(salesforce_user)
                res = client.create_user(salesforce_user)
                iam_user_profile.set_result(success=True,
                                            iden=res.get('id'),
                                            email=salesforce_user.get('email'),
                                            username=salesforce_user.get('userName'),
                                            action=IAMActions.CREATE_USER,
                                            details=res,
                                            active=True)

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    action=IAMActions.CREATE_USER
                                    )
        return iam_user_profile


def update_user_command(client, args, mapper_out, is_command_enabled, is_create_user_enabled, create_if_not_exists):
    try:
        iam_user_profile = IAMUserProfile(user_profile=args.get('user-profile'))
        allow_enable = args.get('allow-enable') == 'true'

        if not is_command_enabled:
            iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                        skip=True,
                                        skip_reason='Command is disabled.')
        else:
            email = iam_user_profile.get_attribute('email')
            user_id, active = client.get_user_id_and_activity_by_mail(email)

            if not user_id:
                # user doesn't exists
                if create_if_not_exists:
                    iam_user_profile = create_user_command(client, args, mapper_out, is_create_user_enabled, False)
                else:
                    error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                    iam_user_profile.set_result(action=IAMActions.UPDATE_USER,
                                                error_code=error_code,
                                                skip=True,
                                                skip_reason=error_message)
            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                if allow_enable:
                    salesforce_user['IsActive'] = True

                res = client.update_user(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            active=True,
                                            action=IAMActions.UPDATE_USER,
                                            details=res
                                            )

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    action=IAMActions.UPDATE_USER
                                    )
        return iam_user_profile


def disable_user_command(client, args, mapper_out, is_command_enabled):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        if not is_command_enabled:
            user_profile.set_result(action=IAMActions.DISABLE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')

        else:
            email = iam_user_profile.get_attribute('email')
            user_id, _ = client.get_user_id_and_activity_by_mail(email)

            if not user_id:
                error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
                iam_user_profile.set_result(action=IAMActions.DISABLE_USER,
                                            error_code=error_code,
                                            skip=True,
                                            skip_reason=error_message)
            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)
                salesforce_user['IsActive'] = False
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.update_user_profile(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            active=False,
                                            action=IAMActions.DISABLE_USER,
                                            details=res
                                            )

        return iam_user_profile

    except Exception as e:
        message, code = handle_exception(e)
        iam_user_profile.set_result(success=False,
                                    error_message=message,
                                    error_code=code,
                                    action=IAMActions.DISABLE_USER
                                    )
        return iam_user_profile


def check_and_set_manndatory_fields(salesforce_user):
    for field, default_value in MANDATORY_FIELDS.items():
        if not salesforce_user.get(field):
            salesforce_user[field] = default_value

    return salesforce_user


def get_all_user_attributes(client):
    """
    This command gets all users, chooses the first
    then, run a second get command that returns all the users attributes
    """
    user_id = ""
    attributes = []

    all_users = client.get_all_users()
    users_list = all_users.get("searchRecords")
    if isinstance(users_list, list):
        user = users_list[0]
        user_id = user.get("Id")

    if user_id:
        user_data = client.get_user(user_id)
        attributes = list(user_data.keys())
    return attributes


def get_mapping_fields_command(client):
    scheme = get_all_user_attributes(client)
    incident_type_scheme = SchemeTypeMapping(type_name=IAMUserProfile.INDICATOR_TYPE)

    for field in scheme:
        incident_type_scheme.add_field(field, "Field")

    return GetMappingFieldsResponse([incident_type_scheme])


def main():

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get('url')
    # checks for '/' at the end url, if it is not available add it
    if base_url[-1] != '/':
        base_url += '/'

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    client_id = params.get('consumer_key')
    client_secret = params.get('consumer_secret')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    mapper_in = params.get('mapper-in', DEFAULT_INCOMING_MAPPER)
    mapper_out = params.get('mapper-out', DEFAULT_OUTGOING_MAPPER)

    is_create_enabled = params.get("create_user_enabled")
    is_update_enabled = demisto.params().get("update_user_enabled")
    is_disable_enabled = demisto.params().get("disable_user_enabled")
    create_if_not_exists = demisto.params().get("create_if_not_exists")

    LOG(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            conn_client_id=client_id,
            conn_client_secret=client_secret,
            conn_username=username,
            conn_password=password,
            ok_codes=(200, 201, 204),
            verify=verify_certificate,
            proxy=proxy
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
            return_results(get_mapping_fields_command(client))

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

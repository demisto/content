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

    def __init__(self, base_url, conn_client_id, conn_client_secret, conn_username, conn_password,
                 ok_codes, verify=True, proxy=False):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes)
        self._conn_client_id = conn_client_id
        self._conn_client_secret = conn_client_secret
        self._conn_username = conn_username
        self._conn_password = conn_password
        self.get_access_token()

    def get_access_token(self):
        uri = '/services/oauth2/token'
        params = {
            "client_id": self._conn_client_id,
            "client_secret": self._conn_client_secret,
            "username": self._conn_username,
            "password": self._conn_password,
            "grant_type": "password"
        }
        """
        res = self._http_request(
            method='POST',
            url_suffix=uri,
            params=params
        )
        token = res.get('access_token')
        """
        token ='00D4K0000039Io4!ARgAQKhu0If0DHLZY0YRgvmE5P8SGWIz2w1E.ctJrJ_PPVeKBLLB6vAPCVOy5urGX0HlfBh0YY0d1WatOunqtZIWec0g2.NN'

        headers = {
            'content-type': 'application/json',
            'Authorization': f'Bearer {token}'
        }

        self._headers = headers

    def get_user_profile(self, user_term):
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

    def get_user_id_by_mail(self, email):
        # check for errors, what id no user is found?
        user_id = ""
        user_where = f"Email='{email}'"
        res = self.search_user_profile(email, user_where)

        search_records = res.get('searchRecords')
        if len(search_records) > 0:
            for search_record in search_records:
                user_id = search_record.get('Id')

        return user_id

    def create_user_profile(self, data):
        uri = URI_PREFIX + 'sobjects/User'
        return self._http_request(
            method='POST',
            url_suffix=uri,
            data=data
        )

    def update_user_profile(self, user_term, data):
        uri = URI_PREFIX + f'sobjects/User/{user_term}'
        params = {"_HttpMethod": "PATCH"}
        return self._http_request(
            method='POST',
            url_suffix=uri,
            params=params,
            data=data
        )


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
    client.http_request(method='GET', url_suffix=uri)
    return 'ok'


def get_user_command(client, args, mapper_in):
    try:
        user_profile = args.get("user-profile")
        iam_user_profile = IAMUserProfile(user_profile=user_profile)

        email = iam_user_profile.get_attribute('email')
        user_id = client.get_user_id_by_mail(email)

        if not user_id:
            error_code, error_message = IAMErrors.USER_DOES_NOT_EXIST
            iam_user_profile.set_result(success=False,
                                        error_message=error_message,
                                        error_code=error_code,
                                        action=IAMActions.GET_USER)
        else:
            res = client.get_user_profile(user_id)
            # make sure res contains all the params
            github_user = res
            iam_user_profile.update_with_app_data(github_user, mapper_in)

            iam_user_profile.set_result(success=True,
                                        iden=res.get('Id'),
                                        email=res.get('Email'),
                                        username=res.get('Username'),
                                        action=IAMActions.GET_USER,
                                        details=res,
                                        active=res.get('IsActive'))

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
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
                create_if_not_exists = False
                iam_user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                                       is_create_enabled, create_if_not_exists)

            else:
                salesforce_user = iam_user_profile.map_object(mapper_name=mapper_out)
                # Removing empty elements from salesforce_user
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.create_user_profile(salesforce_user)
                iam_user_profile.set_result(success=True,
                                            iden=res.get('id'),
                                            email=salesforce_user.get('email'),
                                            username=salesforce_user.get('userName'),
                                            action=IAMActions.CREATE_USER,
                                            details=res,
                                            active=True)

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
            user_profile.set_result(action=IAMActions.UPDATE_USER,
                                    skip=True,
                                    skip_reason='Command is disabled.')

        else:
            email = iam_user_profile.get_attribute('email')
            user_id = client.get_user_id_by_mail(email)

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
                # Removing empty elements from salesforce_user
                salesforce_user = {key: value for key, value in salesforce_user.items() if value is not None}
                res = client.update_user_profile(user_term=user_id, data=salesforce_user)

                iam_user_profile.set_result(success=True,
                                            iden=user_id,
                                            active=True,
                                            action=IAMActions.UPDATE_USER,
                                            details=res
                                            )

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
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
            user_id = client.get_user_id_by_mail(email)

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
                                            details=res.json()
                                            )

        return iam_user_profile

    except Exception as e:
        iam_user_profile.set_result(success=False,
                                    error_message=str(e),
                                    action=IAMActions.DISABLE_USER
                                    )
        return iam_user_profile


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

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    client_id = params.get('consumer_key')
    client_secret = params.get('consumer_secret')
    """
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    secret_token = params.get('secret_token') -> password = password + security token
    """

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
            conn_password=password,
            ok_codes=(200, 201, 204),
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'iam-get-user':
            user_profile = get_user_command(client, args, mapper_in)

        elif command == 'iam-create-user':
            user_profile = create_user_command(client, args, mapper_out, is_create_enabled, is_update_enabled)

        elif command == 'iam-update-user':
            user_profile = update_user_command(client, args, mapper_out, is_update_enabled,
                                               is_create_enabled, create_if_not_exists)

        elif command == 'iam-disable-user':
            user_profile = disable_user_command(client, args, mapper_out, is_enable_disable_enabled)

        elif command == 'test-module':
            test_module(client)

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command(client))

        if user_profile:
            return_results(user_profile)

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

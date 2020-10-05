import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
# IMPORTS
from email.mime.text import MIMEText
from smtplib import SMTP


import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

'''CONSTANTS'''


INCOMING_MAPPER = 'User Profile - Okta (Incoming)'
OUTGOING_MAPPER = 'User Profile - Okta (Outgoing)'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SEARCH_LIMIT = 1000

DEPROVISIONED_STATUS = 'DEPROVISIONED'
SCIM_EXTENSION_SCHEMA = "urn:scim:schemas:extension:custom:1.0:user"
USER_IS_DIABLED_ERROR = "E0000007"

'''CLIENT CLASS'''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify=True, proxy=False, headers=None, auth=None, user_profile=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = headers
        self.auth = auth
        self.iam = IAMCommandHelper(INCOMING_MAPPER, OUTGOING_MAPPER, user_profile)

    def http_request(self, method, url_suffix, full_url=None, params=None, data=None, headers=None):
        if headers is None:
            headers = self.headers
        full_url = full_url if full_url else urljoin(self.base_url, url_suffix)
        res = requests.request(
            method,
            full_url,
            verify=self.verify,
            headers=headers,
            params=params,
            json=data
        )
        return res

    # Getting User Id with a given username
    def get_user_id(self, username):
        uri = 'users'
        query_params = {
            'filter': encode_string_results(f'profile.login eq "{username}"')
        }

        res = self.http_request(
            method='GET',
            url_suffix=uri,
            params=query_params

        )

        return res

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/deactivate'
        return self.http_request(
            method="POST",
            url_suffix=uri
        )

    def activate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/activate'
        return self.http_request(
            method="POST",
            url_suffix=uri
        )

    def get_user(self, user_term):
        uri = f'users/{encode_string_results(user_term)}'
        return self.http_request(
            method='GET',
            url_suffix=uri
        )

    def create_user(self, profile):
        body = {
            'profile': profile,
            'groupIds': [],
            'credentials': {}
        }
        uri = 'users'
        query_params = {
            'activate': 'true',
            'provider': 'true'
        }
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=body,
            params=query_params
        )

    def update_user(self, user_id, profile):
        body = {
            "profile": profile,
            "credentials": {}
        }
        uri = f"users/{user_id}"
        return self.http_request(
            method='POST',
            url_suffix=uri,
            data=body
        )


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


def enable_user_command(client, args):
    if not demisto.params().get("enable-disable-user-enabled"):
        return

    success = False
    app_data = client.iam.map_user_profile_to_app_data()

    res = client.get_user_id(app_data.get('login'))
    res_json = res.json()
    if res.status_code == 200:
        res_json = res.json()
        if not res_json or len(res_json) != 1:
            if args.get('create-if-not-exists') == 'true':
                create_user_command(client, args)
                success = True

        else:
            user_id = res_json[0].get('id')
            res = client.activate_user(user_id)
            res_json = res.json()
            if res.status_code == 200:
                client.iam.return_outputs(success=True,
                                          iden=res_json.get('id'),
                                          email=res_json.get('profile', {}).get('email'),
                                          username=res_json.get('profile', {}).get('login'),
                                          details=res_json,
                                          active=True)
                success = True

    if not success:
        client.iam.return_outputs(success=False,
                                  error_code=res_json.get('errorCode'),
                                  error_message=get_error_details(res_json),
                                  details=res_json)


def disable_user_command(client, args):
    if not demisto.params().get("enable-disable-user-enabled"):
        return

    success = False
    app_data = client.iam.map_user_profile_to_app_data()

    res = client.get_user_id(app_data.get('login'))
    res_json = res.json()
    if res.status_code == 200:
        if not res_json or len(res_json) != 1:
            success = True
        else:
            user_id = res_json[0].get('id')
            res = client.deactivate_user(user_id)
            res_json = res.json()
            if res.status_code == 200:
                client.iam.return_outputs(success=True,
                                          iden=res_json.get('id'),
                                          email=res_json.get('profile', {}).get('email'),
                                          username=res_json.get('profile', {}).get('login'),
                                          details=res_json,
                                          active=False)
                success = True

    if not success:
        client.iam.return_outputs(success=False,
                                  error_code=res_json.get('errorCode'),
                                  error_message=get_error_details(res_json),
                                  details=res_json)


def create_user_command(client, args):

    if not demisto.params().get("create-user-enabled"):
        return

    app_data = client.iam.map_user_profile_to_app_data()
    res = client.create_user(app_data)
    res_json = res.json()

    if res.status_code == 200:
        active = False if res_json.get('status') == DEPROVISIONED_STATUS else True

        client.iam.return_outputs(success=True,
                                  iden=res_json.get('id'),
                                  email=res_json.get('profile', {}).get('email'),
                                  username=res_json.get('profile', {}).get('login'),
                                  details=res_json,
                                  active=active)
    else:
        client.iam.return_outputs(success=False,
                                  error_code=res_json.get('errorCode'),
                                  error_message=get_error_details(res_json),
                                  details=res_json)


def get_user_command(client, args):
    success = False
    app_data = client.iam.map_user_profile_to_app_data()

    res = client.get_user_id(app_data.get('login'))
    res_json = res.json()
    if res.status_code == 200:
        if res_json or len(res_json) == 1:
            user_id = res_json[0].get('id')
            res = client.get_user(user_id)
            res_json = res.json()
            if res.status_code == 200:
                active = False if res_json.get('status') == DEPROVISIONED_STATUS else True
                client.iam.return_outputs(success=True,
                                          iden=res_json.get('id'),
                                          email=res_json.get('profile', {}).get('email'),
                                          username=res_json.get('profile', {}).get('login'),
                                          details=res_json,
                                          active=active)
                success = True

    if not success:
        client.iam.return_outputs(success=False,
                                  error_code=res_json.get('errorCode'),
                                  error_message=get_error_details(res_json),
                                  details=res_json)


def update_user_command(client, args):
    if not demisto.params().get("update-user-enabled"):
        return

    success = False
    app_data = client.iam.map_user_profile_to_app_data()

    res = client.get_user_id(app_data.get('login'))
    res_json = res.json()

    if res.status_code == 200:
        if not res_json or len(res_json) != 1:
            if args.get('create-if-not-exists') == 'true':
                create_user_command(client, args)
                success = True
        else:
            user_id = res_json[0].get('id')
            res = client.update_user(user_id, app_data)
            res_json = res.json()
            if res.status_code == 200:
                active = False if res_json.get('status') == DEPROVISIONED_STATUS else True
                client.iam.return_outputs(success=True,
                                          iden=res_json.get('id'),
                                          email=res_json.get('profile', {}).get('email'),
                                          username=res_json.get('profile', {}).get('login'),
                                          details=res_json,
                                          active=active)
                success = True

    if str(res_json.get('errorCode')) == USER_IS_DIABLED_ERROR:
        # user exists but is disable
        client.iam.return_outputs(success=False,
                                  error_code=res_json.get('errorCode'),
                                  error_message='User is disabled',
                                  details=res_json)

    elif not success:
        client.iam.return_outputs(success=False,
                                  error_code=res_json.get('errorCode'),
                                  error_message=get_error_details(res_json),
                                  details=res_json)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    base_url = urljoin(params['url'].strip('/'), '/api/v1/')
    apitoken = params.get('apitoken')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    LOG(f'Command being called is {command}')

    crud_commands = {
        'get-user': get_user_command,
        'create-user': create_user_command,
        'update-user': update_user_command,
        'disable-user': disable_user_command,
        'enable-user': enable_user_command
    }

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {apitoken}'
        },
        proxy=proxy,
        user_profile=args.get('user-profile'))

    try:
        if command in crud_commands:
            crud_commands[command](client, args)
        elif command == 'test-module':
            test_module(client)

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

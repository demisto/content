import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
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

DEPROVISIONED_STATUS = 'DEPROVISIONED'
USER_IS_DIABLED_ERROR = "E0000007"

'''CLIENT CLASS'''


class Client:
    """
    Okta IAM Client class that implements logic to authenticate with Okta.

    Attributes:
        base_url (str): Okta API's base URL.
        verify (bool): XSOAR insecure parameter.
        headers (dict): Okta API request headers.
        iam (IAMCommandHelper): An IAM Command Helper class object.
        app_data (dict): dsfdsf
        res_json (dict): The last response's json data.
        user_not_found (bool): Whether or not the employee exists in Okta.
        user_id (str): The employee's Okta user ID.
    """

    def __init__(self, base_url, verify=True, token=None, user_profile=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'SSWS {token}'
        }

        self.iam = IAMCommandHelper(INCOMING_MAPPER, OUTGOING_MAPPER, user_profile)
        self.app_data = self.iam.map_user_profile_to_app_data()
        self.res_json = None
        self.user_not_found = False
        self.user_id = self.get_user_id()

    def http_request(self, method, url_suffix, params=None, data=None):
        full_url = urljoin(self.base_url, url_suffix)
        return requests.request(
            method,
            full_url,
            verify=self.verify,
            headers=self.headers,
            params=params,
            json=data
        )

    def get_user_id(self):
        username = self.app_data.get('login')
        if not username:
            return None

        uri = 'users'
        query_params = {
            'filter': encode_string_results(f'profile.login eq "{username}"')
        }

        res = self.http_request(
            method='GET',
            url_suffix=uri,
            params=query_params

        )

        self.res_json = res.json()

        if res.status_code == 200:
            if self.res_json and len(self.res_json) == 1:
                user_id = self.res_json[0].get('id')
                return encode_string_results(user_id)
            else:
                self.user_not_found = True
        return None

    def deactivate_user(self):
        uri = f'users/{self.user_id}/lifecycle/deactivate'
        res = self.http_request(
            method="POST",
            url_suffix=uri
        )
        self.res_json = res.json()
        return res.status_code == 200

    def activate_user(self):
        uri = f'users/{self.user_id}/lifecycle/activate'
        res = self.http_request(
            method="POST",
            url_suffix=uri
        )
        self.res_json = res.json()
        return res.status_code == 200

    def get_user(self):
        uri = f'users/{self.user_id}'
        res = self.http_request(
            method='GET',
            url_suffix=uri
        )
        self.res_json = res.json()
        return res.status_code == 200

    def create_user(self):
        body = {
            'profile': self.app_data,
            'groupIds': [],
            'credentials': {}
        }
        uri = 'users'
        query_params = {
            'activate': 'true',
            'provider': 'true'
        }
        res = self.http_request(
            method='POST',
            url_suffix=uri,
            data=body,
            params=query_params
        )
        self.res_json = res.json()
        return res.status_code == 200

    def update_user(self):
        body = {
            "profile": self.app_data,
            "credentials": {}
        }
        uri = f"users/{self.user_id}"
        res = self.http_request(
            method='POST',
            url_suffix=uri,
            data=body
        )
        self.res_json = res.json()
        return res.status_code == 200

    def iam_command_failure(self):
        if str(self.res_json.get('errorCode')) == USER_IS_DIABLED_ERROR:
            error_msg = 'User is disabled.'
        else:
            error_msg = get_error_details(self.res_json)

        self.iam.return_outputs(success=False,
                                error_code=self.res_json.get('errorCode'),
                                error_message=error_msg,
                                details=self.res_json)

    def iam_command_success(self):
        if demisto.command() == 'disable-user':
            active = False
        elif demisto.command() == 'enable-user':
            active = True
        else:
            active = False if self.res_json.get('status') == DEPROVISIONED_STATUS else True

        self.iam.return_outputs(success=True,
                                iden=self.res_json.get('id'),
                                email=self.res_json.get('profile', {}).get('email'),
                                username=self.res_json.get('profile', {}).get('login'),
                                details=self.res_json,
                                active=active)


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
    if demisto.params().get("enable-disable-user-enabled"):
        if client.user_id:
            success = client.activate_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        else:
            if client.user_not_found and args.get('create-if-not-exists') == 'true':
                create_user_command(client, args)
            else:
                client.iam_command_failure()


def disable_user_command(client, args):
    if demisto.params().get("enable-disable-user-enabled"):
        if client.user_id:
            success = client.deactivate_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        else:
            if client.user_not_found:
                return_outputs('Skipping - user does not exist.')
            else:
                client.iam_command_failure()


def create_user_command(client, args):
    if demisto.params().get("create-user-enabled"):
        if client.user_not_found:
            success = client.create_user()
            if success:
                client.iam_command_success()
            else:
                client.iam_command_failure()

        elif client.user_id:
            return_outputs('Skipping - user already exist.')
        else:
            client.iam_command_failure()


def get_user_command(client, args):
    if client.user_id:
        success = client.get_user()
        if success:
            client.iam_command_success()
        else:
            client.iam_command_failure()

    else:
        if client.user_not_found:
            return_outputs('User does not exist.')
        else:
            client.iam_command_failure()


def update_user_command(client, args):
    if demisto.params().get("update-user-enabled"):
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
    verify_certificate = not params.get('insecure', False)
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
        token=token,
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

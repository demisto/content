from CommonServerPython import *

# IMPORTS
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify, proxy, auth_params):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.client_id = auth_params.get('client_id')
        self.client_secret = auth_params.get('client_secret')
        self.auth_url = auth_params.get('auth_url')
        self._headers = self._request_token()

    def _request_token(self):
        """
        Handles the actual request made to retrieve the access token.
        :return: Access token to be used in the authorization header for each request.
        """
        params = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

        response = self._http_request(
            method='POST',
            full_url=self.auth_url,
            json_data=params
        )
        access_token = response.get('access_token')
        auth_header = {'Authorization': f'Bearer {access_token}'}
        return auth_header

    # Getting Group Id with a given group name
    def get_group_id(self, group_name):
        uri = 'groups'
        query_params = {
            'filter': encode_string_results(f'name eq "{group_name}"')
        }
        res = self._http_request(
            method="GET",
            url_suffix=uri,
            params=query_params
        )
        if res and len(res) == 1:
            return res[0].get('id')

    # Getting User Id with a given username
    def get_user_id(self, username):
        uri = 'users'
        query_params = {
            'filter': encode_string_results(f'username eq "{username}"')
        }
        res = self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params

        )
        if res and len(res) == 1:
            return res[0].get('id')
        raise Exception(f'Failed to find userID for: {username} username.')

    def unlock_user(self, user_id):
        """
        sending a POST request to unlock a specific user
        """
        uri = f'users/{user_id}/unlock'

        return self._http_request(
            method='POST',
            url_suffix=uri,
            headers={
                'Content-Type': 'application/vnd.pingidentity.account.unlock+json'
            }
        )

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/enabled'

        body = {
            "enabled": False
        }

        return self._http_request(
            method="POST",
            url_suffix=uri,
            headers={
                'Content-Type': 'application/json',
            },
            json_data=body

        )

    def activate_user(self, user_id):
        uri = f'users/{user_id}/enable'

        body = {
            "enabled": True
        }

        return self._http_request(
            method="POST",
            url_suffix=uri,
            json_data=body
        )

    def set_password(self, user_id, password, force_change):
        uri = f'users/{user_id}'

        body = {
            "value": password,
            "forceChange": force_change
        }

        return self._http_request(
            method="POST",
            url_suffix=uri,
            headers={
                'Content-Type': 'application/vnd.pingidentity.password.set+json',
            },
            json_data=body
        )

    def add_user_to_group(self, user_id, group_id):
        uri = f'users/{user_id}/memberOfGroups'

        body = {
            "id": group_id
        }

        return self._http_request(
            method="POST",
            url_suffix=uri,
            json_data=body
        )

    def remove_user_from_group(self, user_id, group_id):
        uri = f'users/{user_id}/memberOfGroups/{group_id}'
        return self._http_request(
            method="DELETE",
            url_suffix=uri
        )

    def get_groups_for_user(self, user_id):
        uri = f'users/{user_id}/memberOfGroupNames'

        return self._http_request(
            method="GET",
            url_suffix=uri
        )

    @staticmethod
    def get_readable_group_membership(raw_groups):
        groups = []
        raw_groups = raw_groups if isinstance(raw_groups, list) else [raw_groups]
        raw_groups = raw_groups[0].get('_embedded').get('groupMemberships')

        for group in raw_groups:
            grp = {
                'ID': group.get('id'),
                'Name': group.get('name')
            }
            groups.append(grp)

        return groups

    @staticmethod
    def get_users_context(raw_users):
        users = []
        raw_users = raw_users if isinstance(raw_users, list) else [raw_users]
        for user in raw_users:
            user = {
                'ID': user.get('id'),
                'Username': user.get('username'),
                'DisplayName':
                    user.get('name', {}).get('formatted'),
                'Email': user.get('email'),
                'Enabled': user.get('enabled'),
                'CreatedAt': user.get('createdAt'),
                'UpdatedAt': user.get('updatedAt')
            }
            users.append(user)
        return users

    @staticmethod
    def get_readable_users(raw_users, verbose='false'):
        raw_users = raw_users if isinstance(raw_users, list) else [raw_users]
        if verbose == 'true':
            users_verbose = []
            for user in raw_users:
                attrs = {
                    'ID': user.get('id'),
                    'Username': user.get('username'),
                    'Email': user.get('email'),
                    'First Name': user.get('name', {}).get('given'),
                    'Last Name': user.get('name', {}).get('family'),
                    'Enabled': user.get('enabled'),
                    'Environment': user.get('environment', {}).get('id'),
                    'PopulationID': user.get('population', {}).get('id'),
                    'AccountStatus': user.get('account', {}).get('status'),
                    'CreatedAt': user.get('createdAt'),
                    'UpdatedAt': user.get('updatedAt'),
                    'Groups': user.get('memberOfGroupNames')
                }
                users_verbose.append(attrs)
            return users_verbose

        else:
            users = []
            for user in raw_users:
                attrs = {
                    'ID': user.get('id'),
                    'Username': user.get('username'),
                    'Email': user.get('email'),
                    'First Name': user.get('name', {}).get('given'),
                    'Last Name': user.get('name', {}).get('family'),
                    'Enabled': user.get('enabled')
                }
                users.append(attrs)
            return users

    def get_user(self, user_id):
        uri = f'users/{user_id}'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def create_user(self, username, pop_id):
        uri = 'users'

        body = {
            "population": {
                "id": f'"{pop_id}"'
            },
            "username": f'"{username}'
        }

        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=body
        )

    def update_user(self, user_id, attrs):
        uri = f"users/{user_id}"
        return self._http_request(
            method='PATCH',
            url_suffix=uri,
            json_data=attrs
        )

    def delete_user(self, user_id):
        uri = f"users/{user_id}"
        return self._http_request(
            method="DELETE",
            url_suffix=uri
        )


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    args
    uri = '/'
    client._http_request(method='GET', url_suffix=uri)
    return 'ok', None, None


def unlock_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    raw_response = client.unlock_user(user_id)

    readable_output = f"### {args.get('username')} unlocked"

    return (
        readable_output,
        {},
        raw_response  # raw response - the original response
    )


def activate_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    raw_response = client.activate_user(user_id)

    readable_output = f"### {args.get('username')} is active now"
    return (
        readable_output,
        {},
        raw_response
    )


def deactivate_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    raw_response = client.deactivate_user(user_id)

    readable_output = f"### User {args.get('username')} deactivated"

    return (
        readable_output,
        {},
        raw_response  # raw response - the original response
    )


def suspend_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    raw_response = client.suspend_user(user_id)

    readable_output = f"### {args.get('username')} status is Suspended"
    return (
        readable_output,
        {},
        raw_response
    )


def unsuspend_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    raw_response = client.unsuspend_user(user_id)

    readable_output = f"### {args.get('username')} is no longer SUSPENDED"
    return (
        readable_output,
        {},
        raw_response
    )


def set_password_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    password = args.get('password')

    raw_response = client.set_password(user_id, password, True)
    readable_output = f"{args.get('username')} password was last changed on {raw_response.get('passwordChanged')}"
    return (
        readable_output,
        {},
        raw_response
    )


def add_user_to_group_command(client, args):
    group_id = args.get('groupId')
    user_id = args.get('userId')

    if (not (args.get('username') or user_id)) or (not (args.get('groupName') or group_id)):
        raise Exception("You must supply either 'Username' or 'userId")
    if not user_id:
        user_id = client.get_user_id(args.get('username'))
    if not group_id:
        group_id = client.get_group_id(args.get('groupName'))
    raw_response = client.add_user_to_group(user_id, group_id)
    readable_output = f"User: {user_id} added to group: {args.get('groupName')} successfully"
    return (
        readable_output,
        {},
        raw_response
    )


def remove_from_group_command(client, args):
    group_id = args.get('groupId')
    user_id = args.get('userId')

    if (not (args.get('username') or user_id)) or (not (args.get('groupName') or group_id)):
        raise Exception("You must supply either 'Username' or 'userId' and either 'groupName' or 'groupId'")
    if not user_id:
        user_id = client.get_user_id(args.get('username'))
    if not group_id:
        group_id = client.get_group_id(args.get('groupName'))
    raw_response = client.remove_user_from_group(user_id, group_id)
    readable_output = f"User: {user_id} was removed from group: {args.get('groupName')} successfully"
    return (
        readable_output,
        {},
        raw_response)


def get_groups_for_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    raw_response = client.get_groups_for_user(user_id)
    groups = client.get_readable_group_membership(raw_response)

    context = createContext(groups, removeNull=True)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': {
            'Group': context,
            'ID': args.get('username'),
            'Type': 'PingOne'
        }
    }
    readable_output = f"PingOne groups for user: {args.get('username')}\n {tableToMarkdown('Groups', groups)}"

    return (
        readable_output,
        outputs,
        raw_response
    )


def get_user_command(client, args):
    if not (args.get('username') or args.get('userId')):
        raise Exception("You must supply either 'Username' or 'userId")
    user_term = args.get('userId') if args.get('userId') else args.get('username')
    raw_response = client.get_user(user_term)
    verbose = args.get('verbose')

    user_context = client.get_users_context(raw_response)
    user_readable = client.get_readable_users(raw_response, verbose)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': createContext(user_context)
    }
    readable_output = f"{tableToMarkdown(f'User:{user_term}', user_readable)} "
    return (
        readable_output,
        outputs,
        raw_response
    )


def create_user_command(client, args):
    username = args.get('username')
    pop_id = args.get('populationId')
    raw_response = client.create_user(username, pop_id)
    user_context = client.get_users_context(raw_response)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': createContext(user_context)
    }
    readable_output = tableToMarkdown(f"PingOne User Created: {args.get('username')}:",
                                      client.get_readable_users(raw_response))

    return (
        readable_output,
        outputs,
        raw_response
    )


def update_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    attrs = {}  # type: dict

    raw_response = client.update_user(user_id, attrs)
    readable_output = tableToMarkdown(f"PingOne user: {args.get('username')} Updated:", raw_response.get('id'))

    return (
        readable_output,
        {},
        raw_response
    )


def delete_user_command(client, args):
    if not (args.get('username') or args.get('userId')):
        raise Exception("You must supply either 'Username' or 'userId")
    user_id = args.get('userId')
    raw_response = client.delete_user(user_id)
    readable_output = f"User: {user_id} was Deleted successfully"
    return (
        readable_output,
        {},
        raw_response)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    environment_id = demisto.params().get('environment_id')
    region = demisto.params().get('region')
    tld = '.com'

    if region == 'EU':
        tld = '.eu'
    elif region == 'ASIA':
        tld = '.asia'

    base_url = urljoin(f'https://api.pingone{tld}', f'/v1/environments/{environment_id}/')
    auth_url = urljoin(f'https://auth.pingone{tld}', f'/{environment_id}/as/token')

    client_id = demisto.params().get('client_id')
    client_secret = demisto.params().get('client_secret')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    auth_params = {
        'client_id': client_id,
        'client_secret': client_secret,
        'base_url': base_url,
        'auth_url': auth_url,
    }

    LOG(f'Command being called is {demisto.command()}')

    commands = {
        'test-module': test_module,
        'pingone-unlock-user': unlock_user_command,
        'pingone-deactivate-user': deactivate_user_command,
        'pingone-activate-user': activate_user_command,
        'pingone-set-password': set_password_command,
        'pingone-add-to-group': add_user_to_group_command,
        'pingone-remove-from-group': remove_from_group_command,
        'pingone-get-groups': get_groups_for_user_command,
        'pingone-get-user': get_user_command,
        'pingone-create-user': create_user_command,
        'pingone-update-user': update_user_command,
        'pingone-delete-user': delete_user_command,
    }

    command = demisto.command()

    client = Client(
        auth_params=auth_params,
        base_url=base_url,
        verify=verify_certificate,
        proxy=proxy
    )

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

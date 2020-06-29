from CommonServerPython import *

# IMPORTS
# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SEARCH_LIMIT = 200
PROFILE_ARGS = [
    'firstName',
    'lastName',
    'email',
    'login',
    'secondEmail',
    'middleName',
    'honorificPrefix',
    'honorificSuffix',
    'title',
    'displayName',
    'nickName',
    'profileUrl',
    'primaryPhone',
    'mobilePhone',
    'streetAddress',
    'city',
    'state',
    'zipCode',
    'countryCode',
    'postalAddress',
    'preferredLanguage',
    'locale',
    'timezone',
    'userType',
    'employeeNumber',
    'costCenter',
    'organization',
    'division',
    'department',
    'managerId',
    'manager'
]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    # Getting Group Id with a given group name
    def get_group_id(self, group_name):
        uri = 'groups'
        query_params = {
            'q': encode_string_results(group_name)
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
            'filter': encode_string_results(f'profile.login eq "{username}"')
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
        uri = f'users/{user_id}/lifecycle/unlock'
        return self._http_request(
            method='POST',
            url_suffix=uri
        )

    def deactivate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/deactivate'
        return self._http_request(
            method="POST",
            url_suffix=uri
        )

    def activate_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/activate'
        return self._http_request(
            method="POST",
            url_suffix=uri
        )

    def suspend_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/suspend'
        return self._http_request(
            method="POST",
            url_suffix=uri
        )

    def unsuspend_user(self, user_id):
        uri = f'users/{user_id}/lifecycle/unsuspend'
        return self._http_request(
            method="POST",
            url_suffix=uri
        )

    def get_user_factors(self, user_id):
        uri = f'users/{user_id}/factors'
        return self._http_request(
            method="GET",
            url_suffix=uri
        )

    def reset_factor(self, user_id, factor_id):
        uri = f'users/{user_id}/factors/{factor_id}'
        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            resp_type='text'
        )

    def set_password(self, user_id, password):
        uri = f'users/{user_id}'
        body = {
            "credentials": {
                "password": {"value": password}
            }
        }

        return self._http_request(
            method="POST",
            url_suffix=uri,
            json_data=body
        )

    def add_user_to_group(self, user_id, group_id):
        uri = f'groups/{group_id}/users/{user_id}'
        return self._http_request(
            method="PUT",
            url_suffix=uri,
            resp_type='text'
        )

    def remove_user_from_group(self, user_id, group_id):
        uri = f'groups/{group_id}/users/{user_id}'
        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            resp_type='text'
        )

    def get_groups_for_user(self, user_id):
        uri = f'users/{user_id}/groups'
        return self._http_request(
            method="GET",
            url_suffix=uri
        )

    @staticmethod
    def get_readable_groups(raw_groups):
        groups = []
        raw_groups = raw_groups if isinstance(raw_groups, list) else [raw_groups]
        for group in raw_groups:
            group = {
                'ID': group.get('id'),
                'Created': group.get('created'),
                'ObjectClass': group.get('objectClass'),
                'LastUpdated': group.get('lastUpdated'),
                'LastMembershipUpdated': group.get('lastMembershipUpdated'),
                'Type': group.get('type'),
                'Name': group.get('profile', {}).get('name'),
                'Description': group.get('profile', {}).get('description')
            }
            groups.append(group)
        return groups

    @staticmethod
    def get_readable_logs(raw_logs):
        logs = []
        raw_logs = raw_logs if isinstance(raw_logs, list) else [raw_logs]
        for log in raw_logs:
            if log.get('client', {}).get('userAgent'):
                browser = log.get('client', {}).get('userAgent').get('browser')
                if (not browser) or browser.lower() == 'unknown':
                    browser = 'Unknown browser'
                os = log.get('client', {}).get('userAgent').get('os')
                if (not os) or os.lower() == 'unknown':
                    os = 'Unknown OS'
                device = log.get('client', {}).get('device')
            if (not device) or device.lower() == 'unknown':
                device = 'Unknown device'
            targets = ''
            if log.get('target'):
                for target in log.get('target'):
                    targets += f"{target.get('displayName')} ({target.get('type')})\n"
            time_published = datetime.strptime(log.get('published'), '%Y-%m-%dT%H:%M:%S.%f%z').strftime("%m/%d/%Y, "
                                                                                                        "%H:%M:%S")
            log = {
                'Actor': f"{log.get('actor', {}).get('displayName')} ({log.get('actor', {}).get('type')})",
                'ActorAlternaneId': log.get('actor', {}).get('alternateId'),
                'EventInfo': log.get('displayMessage'),
                'EventOutcome': log.get('outcome', {}).get('result') + (
                    f": {log.get('outcome', {}).get('reason')}" if log.get('outcome', {}).get('reason') else ''),
                'EventSeverity': log.get('severity'),
                'Client': f"{browser} on {os} {device}",
                'RequestIP': log.get('client', {}).get('ipAddress'),
                'ChainIP': log.get('request', {}).get('ipChain')[0].get('ip'),
                'Targets': targets or '-',
                'Time': time_published
            }
            logs.append(log)
        return logs

    @staticmethod
    def get_readable_factors(raw_factors):
        factors = []
        for factor in raw_factors:
            factor = {
                'ID': factor.get('id'),
                'FactorType': factor.get('factorType'),
                'Provider': factor.get('provider'),
                'Status': factor.get('status'),
                'Profile': factor.get('profile')
            }
            factors.append(factor)
        return factors

    def verify_push_factor(self, user_id, factor_id):
        """
        Creates a new transaction and sends an asynchronous push notification to the device for the user to approve or reject.
        You must poll the transaction to determine when it completes or expires.
        """
        uri = f'users/{user_id}/factors/{factor_id}/verify'
        return self._http_request(
            method="POST",
            url_suffix=uri
        )

    def poll_verify_push(self, url):
        """
        Keep polling authentication transactions with WAITING result until the challenge completes or expires.
        time limit defined by us = one minute
        """
        counter = 0
        while counter < 10:
            response = self._http_request(
                method='GET',
                full_url=url,
                url_suffix=''
            )
            if not response.get('factorResult') == 'WAITING':
                return response
            counter += 1
            time.sleep(5)
        response['factorResult'] = "TIMEOUT"
        return response

    def search(self, term, limit):
        uri = "users"
        query_params = {
            'q': encode_string_results(term),
            'limit': limit
        }
        return self._http_request(
            method='GET',
            url_suffix=uri,
            params=query_params
        )

    @staticmethod
    def get_users_context(raw_users):
        users = []
        raw_users = raw_users if isinstance(raw_users, list) else [raw_users]
        for user in raw_users:
            user = {
                'ID': user.get('id'),
                'Username': user.get('profile', {}).get('login'),
                'DisplayName':
                    f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}",
                'Email': user.get('profile', {}).get('email'),
                'Status': user.get('status'),
                'Type': 'Okta',
                'Created': user.get('created'),
                'Activated': user.get('activated'),
                'StatusChanged': user.get('statusChanged'),
                'PasswordChanged': user.get('passwordChanged')
            }
            if user.get('group'):
                user['Group'] = user.get('group')
            users.append(user)
        return users

    @staticmethod
    def get_readable_users(raw_users, verbose='false'):
        raw_users = raw_users if isinstance(raw_users, list) else [raw_users]
        if verbose == 'true':
            users_verbose = ''
            for user in raw_users:
                profile = {
                    'First Name': user.get('profile', {}).get('firstName'),
                    'Last Name': user.get('profile', {}).get('lastName'),
                    'Mobile Phone': user.get('profile', {}).get('mobilePhone'),
                    'Login': user.get('profile', {}).get('login'),
                    'Email': user.get('profile', {}).get('email'),
                    'Second Email': user.get('profile', {}).get('secondEmail'),
                }
                additionalData = {
                    'ID': user.get('id'),
                    'Status': user.get('status'),
                    'Created': user.get('created'),
                    'Activated': user.get('activated'),
                    'Status Changed': user.get('userChanged'),
                    'Last Login': user.get('lastLogin'),
                    'Last Updated': user.get('lastUpdated'),
                    'Password Changed': user.get('passwordChanged'),
                    'Type': user.get('type'),
                    'Credentials': user.get('credentials'),
                    '_links': user.get('_links')
                }
                if user.get('group'):
                    additionalData['Group'] = user.get('group')
                users_verbose += f"### User:{profile.get('Login')}\n" \
                                 f"{tableToMarkdown('Profile', profile)}\n {tableToMarkdown('Additional Data', additionalData)}"
            return users_verbose

        else:
            users = []
            for user in raw_users:
                user = {
                    'ID': user.get('id'),
                    'Login': user.get('profile').get('login'),
                    'First Name': user.get('profile').get('firstName'),
                    'Last Name': user.get('profile').get('lastName'),
                    'Mobile Phone': user.get('profile').get('mobilePhone'),
                    'Last Login': user.get('lastLogin'),
                    'Status': user.get('status')
                }
                users.append(user)
            return users

    def get_user(self, user_term):
        uri = f'users/{encode_string_results(user_term)}'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def create_user(self, cred, profile, group_ids, activate):
        body = {
            'profile': profile,
            'groupIds': group_ids or [],
            'credentials': cred
        }
        uri = 'users'
        query_params = {
            'activate': activate,
            'provider': 'true' if cred.get('provider') else None
        }
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=body,
            params=query_params
        )

    # Build profile dict with pre-defined keys (for user)
    @staticmethod
    def build_profile(args):
        profile = {}
        keys = args.keys()
        for key in PROFILE_ARGS:
            if key in keys:
                profile[key] = args[key]
        return profile

    # Build credentials dict with predefined keys (for user)
    @staticmethod
    def build_credentials(args):
        cred = {}
        if args.get('password'):
            cred['password'] = {"value": args.get('password')}
        if args.get('passwordQuestion') and args.get('passwordAnswer'):
            cred['recovery_question'] = {
                "question": args.get('passwordQuestion'),
                "answer": args.get('passwordAnswer')
            }
        if args.get('providerName') and args.get('providerType'):
            cred['provider'] = {
                'name': args.get('providerName'),
                'type': args.get('providerType')
            }
        return cred

    def update_user(self, user_id, profile, cred):
        body = {
            "profile": profile,
            "credentials": cred
        }
        uri = f"users/{user_id}"
        return self._http_request(
            method='POST',
            url_suffix=uri,
            json_data=body
        )

    def get_paged_results(self, uri, query_param=None):
        response = self._http_request(
            method="GET",
            url_suffix=uri,
            resp_type='response',
            params=query_param
        )
        paged_results = response.json()
        while "next" in response.links and len(response.json()) > 0:
            next_page = response.links.get("next").get("url")
            response = self._http_request(
                method="GET",
                full_url=next_page,
                url_suffix='',
                resp_type='response',
                params=query_param

            )
            paged_results += response.json()
        return paged_results

    def get_group_members(self, group_id, limit):
        uri = f'groups/{group_id}/users'
        if limit:
            query_params = {
                'limit': limit
            }
            return self._http_request(
                method="GET",
                url_suffix=uri,
                params=query_params
            )
        return self.get_paged_results(uri)

    def list_groups(self, args):
        # Base url - if none of the the above specified - returns all the groups (default 200 items)
        uri = "groups"
        query_params = {}
        for key, value in args.items():
            if key == 'query':
                key = 'q'
            query_params[key] = encode_string_results(value)
        if args.get('limit'):
            return self._http_request(
                method='GET',
                url_suffix=uri,
                params=query_params
            )
        return self.get_paged_results(uri, query_params)

    def get_logs(self, args):
        uri = 'logs'
        query_params = {}
        for key, value in args.items():
            if key == 'query':
                key = 'q'
            query_params[key] = encode_string_results(value)
        if args.get('limit'):
            return self._http_request(
                method='GET',
                url_suffix=uri,
                params=query_params
            )
        return self.get_paged_results(uri, query_params)

    def delete_user(self, user_term):
        uri = f"users/{encode_string_results(user_term)}"
        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            resp_type='text'
        )

    def clear_user_sessions(self, user_id):
        uri = f'users/{user_id}/sessions'
        return self._http_request(
            method='DELETE',
            url_suffix=uri,
            resp_type='text'
        )

    def get_zone(self, zoneID):
        uri = f'zones/{zoneID}'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def list_zones(self):
        uri = 'zones'
        return self._http_request(
            method='GET',
            url_suffix=uri
        )

    def update_zone(self, zoneObject):
        zoneID = zoneObject['id']
        uri = f'zones/{zoneID}'

        return self._http_request(
            method='PUT',
            url_suffix=uri,
            data=json.dumps(zoneObject)
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
    uri = 'users/me'
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


def get_user_factors_command(client, args):
    user_id = args.get('userId')

    if not (args.get('username') or user_id):
        raise Exception("You must supply either 'Username' or 'userId")

    if not user_id:
        user_id = client.get_user_id(args.get('username'))

    raw_response = client.get_user_factors(user_id)
    if not raw_response or len(raw_response) == 0:
        raise Exception('No Factors found')

    factors = client.get_readable_factors(raw_response)
    context = createContext(factors, removeNull=True)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': {
            'Factor': context,
            'ID': user_id
        }
    }
    readable_output = f"Factors for user: {user_id}\n {tableToMarkdown('Factors', factors)}"
    return (
        readable_output,
        outputs,
        raw_response
    )


def reset_factor_command(client, args):
    factor_id = args.get('factorId')
    user_id = args.get('userId')

    if not (args.get('username') or user_id):
        raise Exception("You must supply either 'Username' or 'userId")

    if not user_id:
        user_id = client.get_user_id(args.get('username'))

    raw_response = client.reset_factor(user_id, factor_id)

    readable_output = f"Factor: {factor_id} deleted"
    return (
        readable_output,
        {},
        raw_response
    )


def set_password_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    password = args.get('password')

    raw_response = client.set_password(user_id, password)
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
    groups = client.get_readable_groups(raw_response)

    context = createContext(groups, removeNull=True)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': {
            'Group': context,
            'ID': user_id,
            'Type': 'Okta'
        }
    }
    readable_output = f"Okta groups for user: {args.get('username')}\n {tableToMarkdown('Groups', groups)}"

    return (
        readable_output,
        outputs,
        raw_response
    )


def verify_push_factor_command(client, args):
    user_id = args.get('userId')
    factor_id = args.get('factorId')

    raw_response = client.verify_push_factor(user_id, factor_id)
    poll_link = raw_response.get('_links').get('poll')
    if not poll_link:
        raise Exception('No poll link for the push factor challenge')
    poll_response = client.poll_verify_push(poll_link.get('href'))

    outputs = {
        'Account(val.ID && val.ID === obj.ID)': {
            'ID': user_id,
            "VerifyPushResult": poll_response.get('factorResult')
        }
    }
    readable_output = f"Verify push factor result for user {user_id}: {poll_response.get('factorResult')}"
    return (
        readable_output,
        outputs,
        raw_response
    )


def search_command(client, args):
    term = args.get('term')
    limit = args.get('limit') or SEARCH_LIMIT
    verbose = args.get('verbose')
    raw_response = client.search(term, limit)

    if raw_response and len(raw_response) > 0:
        users_context = client.get_users_context(raw_response)
        users_readable = client.get_readable_users(raw_response, verbose)
        context = createContext(users_context, removeNull=True)
        outputs = {
            'Account(val.ID && val.ID === obj.ID)': context
        }
        if verbose == 'true':
            readable_output = f"### Okta users found:\n {users_readable}"
        else:
            readable_output = f"### Okta users found:\n {tableToMarkdown('Users:', users_readable)} "
        return (
            readable_output,
            outputs,
            raw_response
        )
    return 'No users found in Okta', {}, raw_response


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
    readable_output = user_readable if verbose == 'true' else f"{tableToMarkdown(f'User:{user_term}', user_readable)} "
    return (
        readable_output,
        outputs,
        raw_response
    )


def create_user_command(client, args):
    group_ids = args.get('groupIds')
    cred = client.build_credentials(args)
    profile = client.build_profile(args)
    if group_ids:
        group_ids = args.get('groupIds').split(',')
    activate = 'true' if args.get('activate') == 'true' else 'false'
    raw_response = client.create_user(cred, profile, group_ids, activate)
    user_context = client.get_users_context(raw_response)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': createContext(user_context)
    }
    readable_output = tableToMarkdown(f"Okta User Created: {args.get('login')}:",
                                      client.get_readable_users(raw_response))
    return (
        readable_output,
        outputs,
        raw_response
    )


def update_user_command(client, args):
    user_id = client.get_user_id(args.get('username'))
    cred = client.build_credentials(args)
    profile = client.build_profile(args)
    profile['login'] = args.get('username')
    raw_response = client.update_user(user_id, profile, cred)
    readable_output = tableToMarkdown(f"Okta user: {args.get('username')} Updated:", raw_response.get('profile'))
    return (
        readable_output,
        {},
        raw_response
    )


def get_group_members_command(client, args):
    if not (args.get('groupId') or args.get('groupName')):
        raise Exception("You must supply either 'groupName' or 'groupId")
    limit = args.get('limit')
    group_id = args.get('groupId') or client.get_group_id(args.get('groupName'))
    raw_members = client.get_group_members(group_id, limit)
    users_context = client.get_users_context(raw_members)
    users_readable = client.get_readable_users(raw_members, args.get('verbose'))
    context = createContext(users_context, removeNull=True)
    outputs = {
        'Account(val.ID && val.ID === obj.ID)': context
    }
    if args.get('verbose') == 'true':
        return (
            f"### Users for group: {args.get('groupName') or group_id}:\n {users_readable}",
            outputs,
            raw_members
        )
    return (
        tableToMarkdown(f"Users for group: {args.get('groupName') or group_id}", users_readable),
        outputs,
        raw_members
    )


def list_groups_command(client, args):
    raw_response = client.list_groups(args)
    groups = client.get_readable_groups(raw_response)
    context = createContext(groups, removeNull=True)
    outputs = {
        'Okta.Group(val.ID && val.ID === obj.ID)': context
    }
    readable_output = tableToMarkdown('Groups', groups)

    return (
        readable_output,
        outputs,
        raw_response
    )


def get_logs_command(client, args):
    raw_response = client.get_logs(args)
    if not raw_response:
        return 'No logs found', {}, raw_response

    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown('Okta Events', logs)
    outputs = {
        'Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def get_failed_login_command(client, args):
    args['filter'] = 'eventType eq "user.session.start" and outcome.result eq "FAILURE"'
    raw_response = client.get_logs(args)
    if not raw_response:
        return 'No logs found', {}, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown('Failed Login Events', logs)
    outputs = {
        'Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def get_group_assignments_command(client, args):
    args['filter'] = 'eventType eq "group.user_membership.add"'
    raw_response = client.get_logs(args)
    if not raw_response:
        return 'No logs found', {}, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown('Group Assignment Events', logs)
    outputs = {
        'Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def get_application_assignments_command(client, args):
    args['filter'] = 'eventType eq "application.user_membership.add"'
    raw_response = client.get_logs(args)
    if not raw_response:
        return 'No logs found', {}, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown('Application Assignment Events', logs)
    outputs = {
        'Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def get_application_authentication_command(client, args):
    args['filter'] = 'eventType eq "user.authentication.sso"'
    raw_response = client.get_logs(args)
    if not raw_response:
        return 'No logs found', {}, raw_response
    logs = client.get_readable_logs(raw_response)
    readable_output = tableToMarkdown('Application Authentication Events', logs)
    outputs = {
        'Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def delete_user_command(client, args):
    if not (args.get('username') or args.get('userId')):
        raise Exception("You must supply either 'Username' or 'userId")
    user_term = args.get('userId') or args.get('username')
    # Deletes a user permanently. This operation can only be performed on users that have a DEPROVISIONED status.
    # This action cannot be recovered!This operation on a user that hasn't been deactivated
    # causes that user to be deactivated. A second delete operation is required to delete the user.
    user = client.get_user(user_term)
    if user.get('status') != 'DEPROVISIONED':
        client.deactivate_user(args.get('userId') or client.get_user_id(args.get('username')))
    raw_response = client.delete_user(user_term)
    readable_output = f"User: {user_term} was Deleted successfully"
    return (
        readable_output,
        {},
        raw_response)


def clear_user_sessions_command(client, args):
    user_id = args.get('userId')
    raw_response = client.clear_user_sessions(user_id)
    readable_output = f"### User session was cleared for: {user_id}"

    return readable_output, {}, raw_response


def get_zone_command(client, args):
    raw_response = client.get_zone(args.get('zoneID', ''))
    if not raw_response:
        return 'No zones found.', {}, raw_response
    readable_output = tableToMarkdown('Okta Zones', raw_response, headers=[
                                      'name', 'id', 'gateways', 'status', 'system', 'lastUpdated', 'created'])
    outputs = {
        'Okta.Zone(val.id && val.id === obj.id)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def list_zones_command(client, args):
    raw_response = client.list_zones()
    if not raw_response:
        return 'No zones found.', {}, raw_response
    readable_output = tableToMarkdown('Okta Zones', raw_response, headers=[
                                      'name', 'id', 'gateways', 'status', 'system', 'lastUpdated', 'created'])
    outputs = {
        'Okta.Zone(val.id && val.id === obj.id)': createContext(raw_response)
    }
    return (
        readable_output,
        outputs,
        raw_response
    )


def apply_zone_updates(zoneObject, zoneName, gatewayIPs, proxyIPs):
    # If user provided a new zone name - set it
    if zoneName:
        zoneObject["name"] = zoneName

    # Set IPs in CIDR mode. Single IPs will be added as /32.
    if gatewayIPs:
        CIDRs = [f"{ip}/32" if '/' not in ip else f'{ip}' for ip in gatewayIPs]
        zoneObject["gateways"] = [{"type": "CIDR", "value": cidr} for cidr in CIDRs]

    if proxyIPs:
        CIDRs = [f"{ip}/32" if '/' not in ip else f'{ip}' for ip in proxyIPs]
        zoneObject["proxies"] = [{"type": "CIDR", "value": cidr} for cidr in CIDRs]

    return zoneObject


def update_zone_command(client, args):

    if not args.get('zoneName', '') and not args.get('gatewayIPs', '') and not args.get('proxyIPs', ''):
        return (
            'Nothing to update',
            {},
            'Nothing to update'
        )
    zoneID = args.get('zoneID', '')
    zoneObject = client.get_zone(zoneID)
    if zoneID == zoneObject.get('id'):
        zoneName = args.get('zoneName', '')
        gatewayIPs = argToList(args.get('gatewayIPs', ''))
        proxyIPs = argToList(args.get('proxyIPs', ''))
        zoneObject = apply_zone_updates(zoneObject, zoneName, gatewayIPs, proxyIPs)

        raw_response = client.update_zone(zoneObject)
        if not raw_response:
            return 'Got empty response.', {}, raw_response

        readable_output = tableToMarkdown('Okta Zones', raw_response, headers=[
                                          'name', 'id', 'gateways', 'status', 'system', 'lastUpdated', 'created'])
        outputs = {
            'Okta.Zone(val.id && val.id === obj.id)': createContext(raw_response)
        }
        return (
            readable_output,
            outputs,
            raw_response
        )
    else:
        return 'No zone found in Okta with this ID.', {}, {}


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API url
    base_url = urljoin(demisto.params()['url'].strip('/'), '/api/v1/')
    apitoken = demisto.params().get('apitoken')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')

    commands = {
        'test-module': test_module,
        'okta-unlock-user': unlock_user_command,
        'okta-deactivate-user': deactivate_user_command,
        'okta-activate-user': activate_user_command,
        'okta-suspend-user': suspend_user_command,
        'okta-unsuspend-user': unsuspend_user_command,
        'okta-reset-factor': reset_factor_command,
        'okta-set-password': set_password_command,
        'okta-add-to-group': add_user_to_group_command,
        'okta-remove-from-group': remove_from_group_command,
        'okta-get-groups': get_groups_for_user_command,
        'okta-get-user-factors': get_user_factors_command,
        'okta-verify-push-factor': verify_push_factor_command,
        'okta-search': search_command,
        'okta-get-user': get_user_command,
        'okta-create-user': create_user_command,
        'okta-update-user': update_user_command,
        'okta-get-group-members': get_group_members_command,
        'okta-list-groups': list_groups_command,
        'okta-get-logs': get_logs_command,
        'okta-get-failed-logins': get_failed_login_command,
        'okta-get-application-assignments': get_application_assignments_command,
        'okta-get-group-assignments': get_group_assignments_command,
        'okta-get-application-authentication': get_application_authentication_command,
        'okta-delete-user': delete_user_command,
        'okta-clear-user-sessions': clear_user_sessions_command,
        'okta-list-zones': list_zones_command,
        'okta-get-zone': get_zone_command,
        'okta-update-zone': update_zone_command

    }

    command = demisto.command()

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'SSWS {apitoken}'
        },
        proxy=proxy,
        ok_codes=(200, 201, 204))

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# IMPORTS
# Disable insecure warnings
import urllib3

urllib3.disable_warnings()

PROFILE_ARGS = [
    "formatted",
    "given",
    "middle",
    "family",
    "nickname",
    "title",
    "locale",
    "email",
    "primaryPhone",
    "mobilePhone",
    "streetAddress",
    "locality",
    "region",
    "postalCode",
    "countryCode",
    "type",
]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify, proxy, auth_params):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        self.client_id = auth_params.get("client_id")
        self.client_secret = auth_params.get("client_secret")
        self.auth_url = auth_params.get("auth_url")
        self._headers = self._request_token()

    def _request_token(self):
        """
        Handles the actual request made to retrieve the access token.
        :return: Access token to be used in the authorization header for each request.
        """
        params = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret}

        response = self._http_request(
            method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, full_url=self.auth_url, data=params
        )
        access_token = response.get("access_token")
        auth_header = {"Authorization": f"Bearer {access_token}"}
        return auth_header

    # Getting Group Id with a given group name
    def get_group_id(self, group_name):
        uri = "groups"
        query_params = {"filter": encode_string_results(f'name eq "{group_name}"')}
        res = self._http_request(method="GET", url_suffix=uri, params=query_params)

        if "_embedded" in res and len(res.get("_embedded", {}).get("groups")) == 1:
            return res.get("_embedded", {}).get("groups")[0].get("id")
        raise Exception(f"Failed to find groupID for: {group_name} group name.")

    # Return User Id from username
    def get_user_id(self, username):
        uri = "users"
        query_params = {"filter": encode_string_results(f'username eq "{username}"')}
        res = self._http_request(method="GET", url_suffix=uri, params=query_params)

        if "_embedded" in res and len(res.get("_embedded", {}).get("users")) == 1:
            return res.get("_embedded", {}).get("users")[0].get("id")
        raise Exception(f"PingOne error: Failed to find userID for: {username} username.")

    # Return user from username
    def get_user_by_username(self, username):
        uri = "users"
        query_params = {"filter": encode_string_results(f'username eq "{username}"')}
        res = self._http_request(method="GET", url_suffix=uri, params=query_params)

        if "_embedded" in res and len(res.get("_embedded", {}).get("users")) == 1:
            return res.get("_embedded", {}).get("users")[0]
        raise Exception(f"Failed to find user for {username} username.")

    # Return user from id
    def get_user_by_id(self, user_id):
        uri = f"users/{user_id}"

        res = self._http_request(
            method="GET",
            url_suffix=uri,
        )

        if res.get("code") == "NOT_FOUND":
            raise Exception(f"Failed to find user for {user_id}")

        return res

    def unlock_user(self, user_id):
        """
        sending a POST request to unlock a specific user
        """
        uri = f"users/{user_id}"

        new_headers = self._headers
        new_headers["Content-Type"] = "application/vnd.pingidentity.account.unlock+json"

        return self._http_request(method="POST", url_suffix=uri, headers=new_headers)

    def deactivate_user(self, user_id):
        uri = f"users/{user_id}/enabled"

        body = {"enabled": False}

        return self._http_request(method="PUT", url_suffix=uri, json_data=body)

    def activate_user(self, user_id):
        uri = f"users/{user_id}/enabled"

        body = {"enabled": True}

        return self._http_request(method="PUT", url_suffix=uri, json_data=body)

    def set_password(self, user_id, password):
        uri = f"users/{user_id}/password"

        body = {"newPassword": password}

        new_headers = self._headers
        new_headers["Content-Type"] = "application/vnd.pingidentity.password.reset+json"

        return self._http_request(method="PUT", url_suffix=uri, headers=new_headers, json_data=body)

    def add_user_to_group(self, user_id, group_id):
        uri = f"users/{user_id}/memberOfGroups"

        body = {"id": group_id}

        return self._http_request(method="POST", url_suffix=uri, json_data=body)

    def remove_user_from_group(self, user_id, group_id):
        uri = f"users/{user_id}/memberOfGroups/{group_id}"
        self._http_request(
            method="DELETE",
            url_suffix=uri,
            return_empty_response=True,
            ok_codes=(204, 404),  # PingOne returns 404 if the group has already removed which results in a XSOAR error
        )

    def get_groups_for_user(self, user_id):
        uri = f'users/{user_id}/memberOfGroups?expand=group&filter=type eq "DIRECT"'

        query_params = {"expand": "group", "filter": 'username eq "DIRECT"'}

        return self._http_request(method="GET", url_suffix=uri, params=query_params)

    @staticmethod
    def build_user_profile(args):
        profile = {}  # type:ignore
        keys = args.keys()
        for key in PROFILE_ARGS:
            if key in keys:
                if key in ["formatted", "given", "middle", "family"]:
                    if "name" not in profile:
                        profile["name"] = {}
                    profile["name"][key] = args[key]

                elif key in ["streetAddress", "locality", "region", "postalCode", "countryCode"]:
                    if "address" not in profile:
                        profile["address"] = {}
                    profile["address"][key] = args[key]

                else:
                    profile[key] = args[key]
        return profile

    @staticmethod
    def get_readable_group_membership(raw_groups):
        groups = []
        raw_groups = raw_groups.get("_embedded", {}).get("groupMemberships", [])

        for group in raw_groups:
            if group.get("type") == "DIRECT":
                grp = {"ID": group.get("id"), "Name": group.get("name")}
                groups.append(grp)

        return groups

    @staticmethod
    def get_user_context(raw_user):
        user = {
            "ID": raw_user.get("id"),
            "Username": raw_user.get("username"),
            "DisplayName": raw_user.get("name", {}).get("formatted"),
            "Email": raw_user.get("email"),
            "Enabled": raw_user.get("enabled"),
            "CreatedAt": raw_user.get("createdAt"),
            "UpdatedAt": raw_user.get("updatedAt"),
        }
        return user

    @staticmethod
    def get_readable_user(raw_user):
        user_attrs = {
            "ID": raw_user.get("id"),
            "Username": raw_user.get("username"),
            "Email": raw_user.get("email"),
            "First Name": raw_user.get("name", {}).get("given"),
            "Last Name": raw_user.get("name", {}).get("family"),
            "Enabled": raw_user.get("enabled"),
            "Environment": raw_user.get("environment", {}).get("id"),
            "PopulationID": raw_user.get("population", {}).get("id"),
            "AccountStatus": raw_user.get("account", {}).get("status"),
            "CreatedAt": raw_user.get("createdAt"),
            "UpdatedAt": raw_user.get("updatedAt"),
        }
        return user_attrs

    def get_user(self, user_id):
        uri = f"users/{user_id}"
        return self._http_request(method="GET", url_suffix=uri)

    def create_user(self, username, pop_id):
        uri = "users"

        body = {"population": {"id": f"{pop_id}"}, "username": f"{username}"}

        res = self._http_request(method="POST", url_suffix=uri, json_data=body)

        return res

    def update_user(self, user_id, attrs):
        uri = f"users/{user_id}"
        return self._http_request(method="PATCH", url_suffix=uri, json_data=attrs)

    def delete_user(self, user_id):
        uri = f"users/{user_id}"
        return self._http_request(
            method="DELETE",
            url_suffix=uri,
            return_empty_response=True,
            ok_codes=(204, 404),  # PingOne returns 404 if the group has already removed which results in a XSOAR error
        )


def test_module(client, _args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    uri = "/"
    client._http_request(method="GET", url_suffix=uri)
    return "ok", None, None


def unlock_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.unlock_user(user_id)

    readable_output = f"### {args.get('username')} unlocked"

    return (
        readable_output,
        {},
        raw_response,  # raw response - the original response
    )


def activate_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.activate_user(user_id)

    readable_output = f"### {args.get('username')} is active now"
    return (readable_output, {}, raw_response)


def deactivate_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.deactivate_user(user_id)

    readable_output = f"### User {args.get('username')} deactivated"

    return (
        readable_output,
        {},
        raw_response,  # raw response - the original response
    )


def set_password_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    password = args.get("password")

    raw_response = client.set_password(user_id, password)
    readable_output = f"{args.get('username')} password was updated."
    return (readable_output, {}, raw_response)


def add_user_to_group_command(client, args):
    group_id = args.get("groupId")
    user_id = args.get("userId")

    if (not (args.get("username") or user_id)) or (not (args.get("groupName") or group_id)):
        raise Exception("PingOne error: You must supply either 'Username' or 'userId and 'groupName' or 'groupId'.")
    if not user_id:
        user_id = client.get_user_id(args.get("username"))
        user_id_or_name = args.get("username")
    else:
        user_id_or_name = user_id

    if not group_id:
        group_id = client.get_group_id(args.get("groupName"))
        group_id_or_name = args.get("groupName")
    else:
        group_id_or_name = group_id

    raw_response = client.add_user_to_group(user_id, group_id)
    readable_output = f"User: {user_id_or_name} added to group: {group_id_or_name} successfully"
    return (readable_output, {}, raw_response)


def remove_from_group_command(client, args):
    group_id = args.get("groupId")
    user_id = args.get("userId")

    if (not (args.get("username") or user_id)) or (not (args.get("groupName") or group_id)):
        raise Exception("PingOne error: You must supply either 'Username' or 'userId and 'groupName' or 'groupId'.")
    if not user_id:
        user_id = client.get_user_id(args.get("username"))
        user_id_or_name = args.get("username")
    else:
        user_id_or_name = user_id

    if not group_id:
        group_id = client.get_group_id(args.get("groupName"))
        group_id_or_name = args.get("groupName")
    else:
        group_id_or_name = group_id

    client.remove_user_from_group(user_id, group_id)

    readable_output = f"User: {user_id_or_name} was removed from group: {group_id_or_name} successfully"

    return (readable_output, {}, "")


def get_groups_for_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    raw_response = client.get_groups_for_user(user_id)
    groups = client.get_readable_group_membership(raw_response)

    context = createContext(groups, removeNull=True)
    outputs = {"PingOne.Account(val.ID && val.ID === obj.ID)": {"Group": context, "ID": args.get("username"), "Type": "PingOne"}}
    readable_output = f"PingOne groups for user: {args.get('username')}\n {tableToMarkdown('Groups', groups)}"

    return (readable_output, outputs, raw_response)


def get_user_command(client, args):
    if args.get("userId"):
        user_id_or_name = args.get("userId")
        raw_response = client.get_user_by_id(args.get("userId"))
    elif args.get("username"):
        user_id_or_name = args.get("username")
        raw_response = client.get_user_by_username(args.get("username"))
    else:
        raise Exception("PingOne error: You must supply either 'Username' or 'userId")

    user_context = client.get_user_context(raw_response)
    user_readable = client.get_readable_user(raw_response)
    outputs = {"PingOne.Account(val.ID && val.ID === obj.ID)": createContext([user_context])}
    readable_output = f"{tableToMarkdown(f'User:{user_id_or_name}', [user_readable])} "
    return (readable_output, outputs, raw_response)


def create_user_command(client, args):
    username = args.get("username")
    pop_id = args.get("populationId")
    raw_response = client.create_user(username, pop_id)
    user_context = client.get_user_context(raw_response)
    outputs = {"PingOne.Account(val.ID && val.ID === obj.ID)": createContext(user_context)}
    readable_output = tableToMarkdown(f"PingOne user created: {args.get('username')}", client.get_readable_user(raw_response))

    return (readable_output, outputs, raw_response)


def update_user_command(client, args):
    user_id = client.get_user_id(args.get("username"))
    attrs = Client.build_user_profile(args)

    raw_response = client.update_user(user_id, attrs)
    readable_output = tableToMarkdown(f"PingOne user updated: {args.get('username')}", attrs)

    return (readable_output, {}, raw_response)


def delete_user_command(client, args):
    if not (args.get("username") or args.get("userId")):
        raise Exception("PingOne error: You must supply either 'Username' or 'userId")

    if args.get("username"):
        user = client.get_user_by_username(args.get("username"))
        user_id = user.get("id")

        # Output username when possible
        user_id_or_name = args.get("username")
    else:
        user_id = args.get("userId")
        user_id_or_name = user_id

    client.delete_user(user_id)
    readable_output = f"User: {user_id_or_name} was Deleted successfully"
    return (readable_output, {}, "")


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the service API URL
    params = demisto.params()
    environment_id = params.get("environment_id")
    region = params.get("region")
    tld = ".com"

    if region == "EU":
        tld = ".eu"
    elif region == "Asia":
        tld = ".asia"

    base_url = urljoin(f"https://api.pingone{tld}", f"/v1/environments/{environment_id}/")
    auth_url = urljoin(f"https://auth.pingone{tld}", f"/{environment_id}/as/token")

    client_id = demisto.params().get("credentials", {}).get("identifier")
    client_secret = demisto.params().get("credentials", {}).get("password")

    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    auth_params = {
        "client_id": client_id,
        "client_secret": client_secret,
        "base_url": base_url,
        "auth_url": auth_url,
    }

    demisto.debug(f"Command being called is {demisto.command()}")

    commands = {
        "test-module": test_module,
        "pingone-unlock-user": unlock_user_command,
        "pingone-deactivate-user": deactivate_user_command,
        "pingone-activate-user": activate_user_command,
        "pingone-set-password": set_password_command,
        "pingone-add-to-group": add_user_to_group_command,
        "pingone-remove-from-group": remove_from_group_command,
        "pingone-get-groups": get_groups_for_user_command,
        "pingone-get-user": get_user_command,
        "pingone-create-user": create_user_command,
        "pingone-update-user": update_user_command,
        "pingone-delete-user": delete_user_command,
    }

    command = demisto.command()

    client = Client(auth_params=auth_params, base_url=base_url, verify=verify_certificate, proxy=proxy)

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

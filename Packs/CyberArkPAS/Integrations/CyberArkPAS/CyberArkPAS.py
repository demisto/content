import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Tuple

from CommonServerUserPython import *

import urllib3
import traceback

# Disable insecure warnings

urllib3.disable_warnings()
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_date_range_expire_date(date_range):
    """
    Parses date_range string to a tuple date strings (start, end). Input must be in format 'number date_range_unit')
    Examples: (2 hours, 4 minutes, 6 month, 1 day, etc.)

    :type date_range: ``str``
    :param date_range: The date range to be parsed (required)

    :return: The parsed date range forward in sec (and not msec)
    :rtype: ``int``
    """
    range_split = date_range.split(" ")
    if len(range_split) != 2:
        return_error('date_range must be "number date_range_unit", examples: (2 hours, 4 minutes,6 months, 1 day, ' "etc.)")

    number = int(range_split[0])
    if not range_split[1] in ["minute", "minutes", "hour", "hours", "day", "days", "month", "months", "year", "years"]:
        return_error("The unit of date_range is invalid. Must be minutes, hours, days, months or years")

    start_time = datetime.now() + timedelta(hours=0)
    end_time = datetime.now() + timedelta(hours=0)

    unit = range_split[1]
    if "minute" in unit:
        end_time = start_time + timedelta(minutes=number)
    elif "hour" in unit:
        end_time = start_time + timedelta(hours=number)
    elif "day" in unit:
        end_time = start_time + timedelta(days=number)
    elif "month" in unit:
        end_time = start_time + timedelta(days=number * 30)
    elif "year" in unit:
        end_time = start_time + timedelta(days=number * 365)

    return date_to_timestamp(end_time) / 1000


def incident_priority_to_dbot_score(score: float) -> int:
    """Converts the CyberArk score to DBot score representation,
    while the CyberArk score is a value between 0.0-100.0 and the DBot score is 1,2 or 3.
    Can be one of:
        0.0 - 35.0 ->  1
        35.1 - 75.0 ->  2
        75.1 - 100.0 ->  3
    """

    if 0 <= score <= 35:
        return 1
    elif 35 < score <= 75:
        return 2
    elif 75 < score <= 100:
        return 3
    return 0


def order_properties_to_dict(properties: str | dict) -> dict:
    """
    ordering the properties so that they are valid json for the api
    """
    if not properties:
        return {}
    if isinstance(properties, dict):
        return properties
    elif isinstance(properties, str):
        try:
            return json.loads(properties.replace("'", '"'))
        except json.decoder.JSONDecodeError:
            raise ValueError(f"Properties ({properties}) are not valid JSON")
    else:
        raise ValueError(f"Properties must be a JSON string or dictionary (got {properties})")


def filter_by_score(events_data: list, score: int) -> list:
    if score == 0:
        return events_data

    filtered_event_score = []
    for event in events_data:
        if event.get("score") >= score:
            filtered_event_score.append(event)
    return filtered_event_score


class Client(BaseClient):
    """
    Client to use in the CyberArk PAS integration. Uses BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str, use_ssl: bool, proxy: bool, max_fetch: int):
        super().__init__(base_url=server_url, verify=use_ssl, proxy=proxy)
        self._username = username
        self._password = password
        self._max_fetch = max_fetch
        self._token = self._generate_token()
        self._headers = {"Authorization": self._token, "Content-Type": "application/json"}

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            "username": self._username,
            "password": self._password,
        }

        headers = {"Content-Type": "application/json"}
        return self._http_request("POST", "/PasswordVault/API/Auth/CyberArk/Logon", headers=headers, json_data=body)

    def _logout(self):
        self._http_request("POST", "/PasswordVault/API/Auth/Logoff")

    def add_user(
        self,
        username: str,
        user_type: str,
        non_authorized_interfaces: list,
        expiry_date: str,
        password: str,
        change_password_on_the_next_logon: str,
        password_never_expires: str,
        vault_authorization: list,
        description: str,
        email: str,
        first_name: str,
        last_name: str,
        enable_user: str,
        profession: str,
        distinguished_name: str,
        location: str,
    ):
        url_suffix = "/PasswordVault/api/Users"
        body = {
            "username": username,
            "userType": user_type,
            "initialPassword": password,
            "authenticationMethod": ["AuthTypePass"],
            "location": location,
            "unAuthorizedInterfaces": non_authorized_interfaces,
            "expiryDate": expiry_date,
            "vaultAuthorization": vault_authorization,
            "enableUser": enable_user == "true",
            "changePassOnNextLogon": change_password_on_the_next_logon == "true",  # guardrails-disable-line
            "passwordNeverExpires": password_never_expires == "true",  # guardrails-disable-line
            "distinguishedName": distinguished_name,
            "description": description,
            "internet": {
                "businessEmail": email,
            },
            "personalDetails": {
                "profession": profession,
                "firstName": first_name,
                "lastName": last_name,
            },
        }

        return self._http_request("POST", url_suffix, json_data=body)

    def update_user(
        self,
        user_id: str,
        username: str,
        user_type: str,
        non_authorized_interfaces: list,
        expiry_date: str,
        change_password_on_the_next_logon: str,
        password_never_expires: str,
        vault_authorization: list,
        description: str,
        email: str,
        first_name: str,
        last_name: str,
        enable_user: str,
        profession: str,
        distinguished_name: str,
        location: str,
    ):
        url_suffix = f"/PasswordVault/api/Users/{user_id}"
        body = {
            "enableUser": enable_user == "true",
            "changePassOnNextLogon": change_password_on_the_next_logon == "true",  # guardrails-disable-line
            "expiryDate": expiry_date,
            "unAuthorizedInterfaces": non_authorized_interfaces,
            "authenticationMethod": ["AuthTypePass"],
            "passwordNeverExpires": password_never_expires == "true",  # guardrails-disable-line
            "distinguishedName": distinguished_name,
            "description": description,
            "internet": {
                "businessEmail": email,
            },
            "personalDetails": {"profession": profession, "firstName": first_name, "lastName": last_name},
            "id": user_id,
            "username": username,
            "source": "CyberArk",
            "userType": user_type,
            "vaultAuthorization": vault_authorization,
            "location": location,
        }

        return self._http_request("PUT", url_suffix, json_data=body)

    def delete_user(self, user_id: str):
        url_suffix = f"/PasswordVault/api/Users/{user_id}"

        # json is not defined for this response, therefore we wish to get the "text" value back
        self._http_request("DELETE", url_suffix, resp_type="text")

    def get_users(
        self,
        filter: str,
        search: str,
    ):
        url_suffix = "/PasswordVault/api/Users"

        body = {
            "filter": filter,
            "search": search,
        }

        return self._http_request("GET", url_suffix, json_data=body)

    def activate_user(self, user_id: str):
        """
        This function uses the V1 CyberArk PAS api, currently there is no matching function in V2
        """
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Users/{user_id}"

        self._http_request("PUT", url_suffix, resp_type="text")

    def get_list_safes(self):
        url_suffix = "/PasswordVault/api/Safes"

        return self._http_request("GET", url_suffix)

    def get_safe_by_name(self, safe_name: str):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}"

        return self._http_request("GET", url_suffix)

    def add_safe(
        self,
        safe_name: str,
        description: str,
        OLAC_enabled: str,
        managing_cpm: str,
        number_of_versions_retention: str,
        number_of_days_retention: str,
        location: str,
    ):
        url_suffix = "/PasswordVault/api/Safes"

        body = {
            "SafeName": safe_name,
            "Description": description,
            "OLACEnabled": OLAC_enabled == "true",
            "ManagingCPM": managing_cpm,
            "NumberOfVersionsRetention": number_of_versions_retention,
            "NumberOfDaysRetention": number_of_days_retention,
            "Location": location,
        }
        return self._http_request("POST", url_suffix, json_data=body)

    def update_safe(
        self,
        safe_name: str,
        safe_new_name: str,
        description: str,
        OLAC_enabled: str,
        managing_cpm: str,
        number_of_versions_retention: str,
        number_of_days_retention: str,
        location: str = "",
    ):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}"
        if not safe_new_name:
            safe_new_name = safe_name
        body = {
            "SafeName": safe_new_name,
            "Description": description,
            "OLACEnabled": OLAC_enabled == "true",
            "ManagingCPM": managing_cpm,
            "NumberOfVersionsRetention": number_of_versions_retention,
            "NumberOfDaysRetention": number_of_days_retention,
            "Location": location,
        }
        return self._http_request("PUT", url_suffix, json_data=body)

    def delete_safe(
        self,
        safe_name: str,
    ):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}"

        # json is not defined for this response, therefore we wish to get the "text" value back
        return self._http_request("DELETE", url_suffix, resp_type="text")

    def list_safe_members(self, safe_name: str):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}/Members"

        return self._http_request("GET", url_suffix)

    def add_safe_member(
        self,
        safe_name: str,
        member_name: str,
        requests_authorization_level: str,
        membership_expiration_date: str,
        permissions: list,
        search_in: str,
    ):
        """
        This function uses the V1 CyberArk PAS api, currently there is no matching function in V2
        """
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Safes/{safe_name}/Members"

        body = {
            "member": {
                "MemberName": member_name,
                "SearchIn": search_in,
                "MembershipExpirationDate": membership_expiration_date,
                "Permissions": [
                    {"Key": "UseAccounts", "Value": "UseAccounts" in permissions},
                    {"Key": "RetrieveAccounts", "Value": "RetrieveAccounts" in permissions},
                    {"Key": "ListAccounts", "Value": "ListAccounts" in permissions},
                    {"Key": "AddAccounts", "Value": "AddAccounts" in permissions},
                    {"Key": "UpdateAccountContent", "Value": "UpdateAccountContent" in permissions},
                    {"Key": "UpdateAccountProperties", "Value": "UpdateAccountProperties" in permissions},
                    {
                        "Key": "InitiateCPMAccountManagementOperations",
                        "Value": "InitiateCPMAccountManagementOperations" in permissions,
                    },
                    {"Key": "SpecifyNextAccountContent", "Value": "SpecifyNextAccountContent" in permissions},
                    {"Key": "RenameAccounts", "Value": "RenameAccounts" in permissions},
                    {"Key": "DeleteAccounts", "Value": "DeleteAccounts" in permissions},
                    {"Key": "UnlockAccounts", "Value": "UnlockAccounts" in permissions},
                    {"Key": "ManageSafe", "Value": "ManageSafe" in permissions},
                    {"Key": "ManageSafeMembers", "Value": "ManageSafeMembers" in permissions},
                    {"Key": "BackupSafe", "Value": "BackupSafe" in permissions},
                    {"Key": "ViewAuditLog", "Value": "ViewAuditLog" in permissions},
                    {"Key": "ViewSafeMembers", "Value": "ViewSafeMembers" in permissions},
                    {"Key": "RequestsAuthorizationLevel", "Value": int(requests_authorization_level)},
                    {"Key": "AccessWithoutConfirmation", "Value": "AccessWithoutConfirmation" in permissions},
                    {"Key": "CreateFolders", "Value": "CreateFolders" in permissions},
                    {"Key": "DeleteFolders", "Value": "DeleteFolders" in permissions},
                    {"Key": "MoveAccountsAndFolders", "Value": "MoveAccountsAndFolders" in permissions},
                ],
            }
        }
        return self._http_request("POST", url_suffix, json_data=body)

    def add_account(
        self,
        account_name: str,
        address: str,
        username: str,
        platform_id: str,
        safe_name: str,
        password: str,
        secret_type: str,
        properties: dict,
        automatic_management_enabled: str,
        manual_management_reason: str,
        remote_machines: str,
        access_restricted_to_temote_machines: str,
    ):
        url_suffix = "/PasswordVault/api/Accounts"

        body = {
            "name": account_name,
            "address": address,
            "userName": username,
            "platformId": platform_id,
            "safeName": safe_name,
            "secretType": secret_type,
            "secret": password,
            "platformAccountProperties": properties,
            "secretManagement": {
                "automaticManagementEnabled": automatic_management_enabled == "true",
                "manualManagementReason": manual_management_reason,
            },
            "remoteMachinesAccess": {
                "remoteMachines": remote_machines,
                "accessRestrictedToRemoteMachines": access_restricted_to_temote_machines == "true",
            },
        }
        return self._http_request("POST", url_suffix, json_data=body)

    def update_safe_member(
        self,
        safe_name: str,
        member_name: str,
        requests_authorization_level: str,
        membership_expiration_date: str,
        permissions: list,
    ):
        """
        This function uses the V1 CyberArk PAS api, currently there is no matching function in V2
        """
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Safes/{safe_name}/Members/{member_name}"

        body = {
            "member": {
                "MembershipExpirationDate": membership_expiration_date,
                "Permissions": [
                    {"Key": "UseAccounts", "Value": "UseAccounts" in permissions},
                    {"Key": "RetrieveAccounts", "Value": "RetrieveAccounts" in permissions},
                    {"Key": "ListAccounts", "Value": "ListAccounts" in permissions},
                    {"Key": "AddAccounts", "Value": "AddAccounts" in permissions},
                    {"Key": "UpdateAccountContent", "Value": "UpdateAccountContent" in permissions},
                    {"Key": "UpdateAccountProperties", "Value": "UpdateAccountProperties" in permissions},
                    {
                        "Key": "InitiateCPMAccountManagementOperations",
                        "Value": "InitiateCPMAccountManagementOperations" in permissions,
                    },
                    {"Key": "SpecifyNextAccountContent", "Value": "SpecifyNextAccountContent" in permissions},
                    {"Key": "RenameAccounts", "Value": "RenameAccounts" in permissions},
                    {"Key": "DeleteAccounts", "Value": "DeleteAccounts" in permissions},
                    {"Key": "UnlockAccounts", "Value": "UnlockAccounts" in permissions},
                    {"Key": "ManageSafe", "Value": "ManageSafe" in permissions},
                    {"Key": "ManageSafeMembers", "Value": "ManageSafeMembers" in permissions},
                    {"Key": "BackupSafe", "Value": "BackupSafe" in permissions},
                    {"Key": "ViewAuditLog", "Value": "ViewAuditLog" in permissions},
                    {"Key": "ViewSafeMembers", "Value": "ViewSafeMembers" in permissions},
                    {"Key": "RequestsAuthorizationLevel", "Value": int(requests_authorization_level)},
                    {"Key": "AccessWithoutConfirmation", "Value": "AccessWithoutConfirmation" in permissions},
                    {"Key": "CreateFolders", "Value": "CreateFolders" in permissions},
                    {"Key": "DeleteFolders", "Value": "DeleteFolders" in permissions},
                    {"Key": "MoveAccountsAndFolders", "Value": "MoveAccountsAndFolders" in permissions},
                ],
            }
        }
        return self._http_request("PUT", url_suffix, json_data=body)

    def delete_safe_member(
        self,
        safe_name: str,
        member_name: str,
    ):
        """
        This function uses the V1 CyberArk PAS api, currently there is no matching function in V2
        """
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Safes/{safe_name}/Members/{member_name}"

        self._http_request("DELETE", url_suffix, resp_type="text")

    def delete_account(
        self,
        account_id: str,
    ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}"

        self._http_request("DELETE", url_suffix, resp_type="text")

    def get_list_accounts(
        self,
        search: str,
        sort: str,
        offset: str,
        limit: str,
        filter: str,
    ):
        url_suffix = f"/PasswordVault/api/Accounts?search={search}&sort={sort}&offset={offset}&limit={limit}&filter={filter}"
        return self._http_request("GET", url_suffix)

    def get_list_account_activity(
        self,
        account_id: str,
    ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}/Activities"
        return self._http_request("GET", url_suffix)

    def get_account_details(
        self,
        account_id: str,
    ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}"
        return self._http_request("GET", url_suffix)

    def change_credentials_random_password(
        self,
        account_id: str,
    ):
        url_suffix = f"/PasswordVault/API/Accounts/{account_id}/Change"
        body = {"ChangeEntireGroup": "true"}
        self._http_request("POST", url_suffix, json_data=body, resp_type="text")

    def change_credentials_set_new_password(
        self,
        account_id: str,
        new_credentials: str,
    ):
        url_suffix = f"/passwordvault/api/Accounts/{account_id}/SetNextPassword"
        body = {
            "ChangeImmediately": True,
            "NewCredentials": new_credentials,
        }
        self._http_request("POST", url_suffix, json_data=body, resp_type="text")

    def change_credentials_in_vault_only(
        self,
        account_id: str,
        new_credentials: str,
    ):
        url_suffix = f"/passwordvault/api/Accounts/{account_id}/Password/Update"
        body = {
            "NewCredentials": new_credentials,
        }
        self._http_request("POST", url_suffix, json_data=body, resp_type="text")

    def verify_credentials(
        self,
        account_id: str,
    ):
        """
        This function uses the V1 CyberArk PAS api, currently there is no matching function in V2
        """
        url_suffix = f"/PasswordVault/API/Accounts/{account_id}/Verify"

        self._http_request("POST", url_suffix, resp_type="text")

    def reconcile_credentials(
        self,
        account_id: str,
    ):
        url_suffix = f"/PasswordVault/API/Accounts/{account_id}/Reconcile"

        self._http_request("POST", url_suffix, resp_type="text")

    def update_account(
        self,
        account_id: str,
        account_name: str,
        address: str,
        username: str,
        platform_id: str,
    ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}"

        arguments = {"name": account_name, "address": address, "userName": username, "platformId": platform_id}
        body = []
        for key, value in arguments.items():
            if value:
                body.append({"op": "replace", "path": f"/{key}", "value": f"{value}"})

        return self._http_request("PATCH", url_suffix, data=str(body))

    def get_security_events(self, next_run: str):
        url_suffix = "/PasswordVault/API/pta/API/Events/"
        self._headers["lastUpdatedEventDate"] = next_run
        return self._http_request("GET", url_suffix)


def test_module(
    client: Client,
) -> str:
    """
    If a client was made then an accesses token was successfully reached,
    therefor, the username and password are valid and a connection was made
    checks that the fetch command works as well, using the client function -
    :param client: the client object with an access token
    :return: ok if got a valid accesses token
    """
    start, _ = parse_date_range("7 days")
    start_time_timestamp = str(date_to_timestamp(start))
    security_events = client.get_security_events(start_time_timestamp)
    # if there were security events in the last week
    if security_events:
        event = security_events[0]
        if not event.get("id") or not event.get("type") or not event.get("score"):
            raise Exception("Security events from CyberArk PAS are missing mandatory fields.")
    return "ok"


def add_user_command(
    client: Client,
    username: str,
    user_type: str = "EPVUser",
    non_authorized_interfaces: str = "",
    expiry_date: str = "",
    password: str = "",
    change_password_on_the_next_logon: str = "true",
    password_never_expires: str = "false",
    vault_authorization: str = "",
    description: str = "",
    email: str = "",
    first_name: str = "",
    last_name: str = "",
    enable_user: str = "true",
    profession: str = "",
    distinguished_name: str = "",
    location: str = "\\",
) -> CommandResults:
    """Add a new user to the vault.
    :param client: The client object with an access token
    :param username: The name of the user.
    :param user_type: User type according to the license.
    :param non_authorized_interfaces: The CyberArkPAS interfaces that this user is not authorized to.
    :param expiry_date: The date when the user expires as timestamp.
    :param password: The password that the user will use to log on for the first time.
    :param change_password_on_the_next_logon: Whether or not the user must change their password from the second
        log on onward.
    :param password_never_expires: Whether the user’s password will not expire unless they decide
        to change it.
    :param vault_authorization: The user permissions.
    :param description: Notes and comments.
    :param email: The user's email addresses.
    :param first_name: The user's first name.
    :param last_name: The user's last name.
    :param enable_user: Whether the user will be enabled upon creation.
    :param profession: The user’s profession.
    :param distinguished_name: The user’s distinguished name.
    :param location: The location in the vault where the user will be created.
    :return: CommandResults
    """
    non_authorized_interfaces_list = argToList(non_authorized_interfaces)
    vault_authorization_list = argToList(vault_authorization)
    if expiry_date:
        expiry_date_epoch = parse_date_range_expire_date(expiry_date)
    else:
        expiry_date_epoch = ""

    response = client.add_user(
        username,
        user_type,
        non_authorized_interfaces_list,
        expiry_date_epoch,
        password,
        change_password_on_the_next_logon,
        password_never_expires,
        vault_authorization_list,
        description,
        email,
        first_name,
        last_name,
        enable_user,
        profession,
        distinguished_name,
        location,
    )
    results = CommandResults(raw_response=response, outputs_prefix="CyberArkPAS.Users", outputs_key_field="id", outputs=response)
    return results


def update_user_command(
    client: Client,
    user_id: str,
    username: str,
    user_type: str = "EPVUser",
    non_authorized_interfaces: str = "",
    expiry_date: str = "",
    change_password_on_the_next_logon: str = "true",
    password_never_expires: str = "false",
    vault_authorization: str = "",
    description: str = "",
    email: str = "",
    first_name: str = "",
    last_name: str = "",
    enable_user: str = "true",
    profession: str = "",
    distinguished_name: str = "",
    location: str = "\\",
) -> CommandResults:
    """Updates an existing vault user.
    :param client: The client object with an access token
    :param user_id: The user's unique ID.
    :param username: The name of the user.
    :param user_type: User type according to the license.
    :param non_authorized_interfaces: The CyberArkPAS interfaces that this user is not authorized to.
    :param expiry_date: The date when the user expires as timestamp.
    :param change_password_on_the_next_logon: Whether or not the user must change their password from the second
        log on onward.
    :param password_never_expires: Whether the user’s password will not expire unless they decide
        to change it.
    :param vault_authorization: The user permissions.
    :param description: Notes and comments.
    :param email: The user's email addresses.
    :param first_name: The user's first name.
    :param last_name: The user's last name.
    :param enable_user: Whether the user will be enabled upon creation.
    :param profession: The user’s profession.
    :param distinguished_name: The user’s distinguished name.
    :param location: The location in the vault where the user will be created.
    :return: CommandResults
    """
    non_authorized_interfaces_list = argToList(non_authorized_interfaces)
    vault_authorization_list = argToList(vault_authorization)
    if expiry_date:
        expiry_date_epoch = parse_date_range_expire_date(expiry_date)
    else:
        expiry_date_epoch = ""
    response = client.update_user(
        user_id,
        username,
        user_type,
        non_authorized_interfaces_list,
        expiry_date_epoch,
        change_password_on_the_next_logon,
        password_never_expires,
        vault_authorization_list,
        description,
        email,
        first_name,
        last_name,
        enable_user,
        profession,
        distinguished_name,
        location,
    )
    results = CommandResults(raw_response=response, outputs_prefix="CyberArkPAS.Users", outputs_key_field="id", outputs=response)
    return results


def delete_user_command(
    client: Client,
    user_id: str,
) -> CommandResults:
    """Delete a specific user in the vault.
    :param client: The client object with an access token
    :param user_id: The user's unique ID.
    :return: CommandResults
    """
    # the response should be an empty string, if an error raised it would be catch in the main block
    client.delete_user(user_id)
    return CommandResults(
        readable_output=f"User {user_id} was deleted",
        outputs_prefix="CyberArkPAS.Users",
        outputs_key_field="id",
        outputs={"id": user_id, "Deleted": True},
    )


def get_users_command(
    client: Client,
    filter: str = "",
    search: str = "",
) -> CommandResults:
    """Returns a list of all existing users in the vault.
    :param client: The client object with an access token
    :param filter: Retrieve users using filters.
    :param search: Search by the values.
    :return: CommandResults
    """
    response = client.get_users(filter, search)
    total_users = response.get("Total")
    headline = f"There are {total_users} users"
    users = response.get("Users")
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(headline, users),
        outputs_prefix="CyberArkPAS.Users",
        outputs_key_field="id",
        outputs=users,
    )
    return results


def activate_user_command(
    client: Client,
    user_id: str,
) -> str:
    """Activate an existing vault user who was suspended after entering incorrect credentials multiple times.
    :param client: The client object with an access token
    :param user_id: The user's unique ID.
    :return: CommandResults
    """
    # the response should be an empty string, if an error raised it would be catch in the main block
    client.activate_user(user_id)
    return f"User {user_id} was activated"


def get_list_safes_command(
    client: Client,
):
    """Returns information about all of the user’s Safes in the vault.
    :param client: The client object with an access token
    :return: CommandResults
    """
    response = client.get_list_safes()
    # from 12.1 version the response's structure was changed (Total -> count, Safes -> value)
    total_safes = response.get("Total", response.get("count"))
    headline = f"There are {total_safes} safes"
    safes = response.get("Safes", response.get("value"))
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(name=headline, t=safes),
        outputs_prefix="CyberArkPAS.Safes",
        outputs_key_field="SafeName",
        outputs=safes,
    )
    return results


def add_safe_command(
    client: Client,
    safe_name: str,
    description: str = "",
    OLAC_enabled: str = "true",
    managing_cpm: str = "",
    number_of_versions_retention: str = "",
    number_of_days_retention: str = "",
    location: str = "",
) -> CommandResults:
    """Add a new safe to the vault.
    :param client: The client object with an access token
    :param safe_name: Name of a safe to create.
    :param description: Description of the new safe.
    :param OLAC_enabled: Whether or not to enable Object Level Access Control for the new safe.
    :param managing_cpm: The name of the CPM user who will manage the new safe.
    :param number_of_versions_retention: The number of retained versions of every password that is stored in the safe.
    :param number_of_days_retention: The number of days for which password versions are saved in the safe.
    :param location: The location of the safe.
    :return: CommandResults
    """
    response = client.add_safe(
        safe_name, description, OLAC_enabled, managing_cpm, number_of_versions_retention, number_of_days_retention, location
    )
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Safes", outputs_key_field="SafeName", outputs=response
    )
    return results


def update_safe_command(
    client: Client,
    safe_name: str,
    safe_new_name: str = "",
    description: str = "",
    OLAC_enabled: str = "true",
    managing_cpm: str = "",
    number_of_versions_retention: str = "",
    number_of_days_retention: str = "",
    location: str = "",
) -> CommandResults:
    """Update a single safe in the vault.
    :param client: The client object with an access token
    :param safe_name: The name of the safe that will be updated.
    :param safe_new_name: The new name of the safe.
    :param description: Description of the new safe.
    :param OLAC_enabled: Whether or not to enable Object Level Access Control for the new safe.
    :param managing_cpm: The name of the CPM user who will manage the new safe.
    :param number_of_versions_retention: The number of retained versions of every password that is stored in the safe.
    :param number_of_days_retention: The number of days for which password versions are saved in the safe.
    :param location: The location of the safe.
    :return: CommandResults
    """
    response = client.update_safe(
        safe_name,
        safe_new_name,
        description,
        OLAC_enabled,
        managing_cpm,
        number_of_versions_retention,
        number_of_days_retention,
        location,
    )
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Safes", outputs_key_field="SafeName", outputs=response
    )
    return results


def delete_safe_command(
    client: Client,
    safe_name: str,
) -> CommandResults:
    """Delete a safe from the vault.
    :param client: The client object with an access token
    :param safe_name: Name of the safe that will be deleted.
    :return: CommandResults
    """
    # the response should be an empty string, if an error raised it would be catch in the main block
    client.delete_safe(safe_name)
    return CommandResults(
        readable_output=f"Safe {safe_name} was deleted",
        outputs_prefix="CyberArkPAS.Safes",
        outputs_key_field="SafeName",
        outputs={"SafeName": safe_name, "Deleted": True},
    )


def get_safe_by_name_command(
    client: Client,
    safe_name: str,
) -> CommandResults:
    """Return information about a specific safe in the vault.
    :param client: The client object with an access token
    :param safe_name: The name of the safe about which information is returned.
    :return: CommandResults
    """
    response = client.get_safe_by_name(safe_name)
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Safes", outputs_key_field="SafeName", outputs=response
    )
    return results


def list_safe_members_command(client: Client, safe_name: str) -> CommandResults:
    """Return a list of the members of the safe.
    :param client: The client object with an access token
    :param safe_name: The name of the safe whose safe members will be listed.
    :return: CommandResults
    """
    response = client.list_safe_members(safe_name)
    # from 12.1 version the response's structure was changed (Total -> count, SafeMembers -> value)
    total_safe_members = response.get("Total", response.get("count"))
    headline = f"There are {total_safe_members} safe members for {safe_name}"
    members = response.get("SafeMembers", response.get("value"))
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(name=headline, t=members),
        outputs_prefix="CyberArkPAS.Safes.Members",
        outputs_key_field="MemberName",
        outputs=members,
    )
    return results


def add_safe_member_command(
    client: Client,
    safe_name: str,
    member_name: str,
    requests_authorization_level: str = "0",
    membership_expiration_date: str = "",
    permissions: str = "",
    search_in: str = "",
) -> CommandResults:
    """Add an existing user as a safe member.
    :param client: The client object with an access token
    :param safe_name: The name of the safe to add a member to.
    :param member_name: The name of the user to add as a Safe member.
    :param requests_authorization_level: Requests authorization level, can be 0/1/2.
    :param membership_expiration_date: MM|DD|YY or empty if there is no expiration date.
    :param permissions: User’s permissions in the safe.
    :param search_in: Search for the member in the vault or domain.
    :return: CommandResults
    """
    permissions_list = argToList(permissions)
    response = client.add_safe_member(
        safe_name, member_name, requests_authorization_level, membership_expiration_date, permissions_list, search_in
    )
    results = CommandResults(raw_response=response, outputs_prefix="CyberArkPAS.Safes.Members", outputs=response.get("member"))
    return results


def update_safe_member_command(
    client: Client,
    safe_name: str,
    member_name: str,
    requests_authorization_level: str = "0",
    membership_expiration_date: str = "",
    permissions: str = "",
) -> CommandResults:
    """Update an existing safe member.
    :param client: The client object with an access token
    :param safe_name: Name of the safe to which the safe member belongs.
    :param member_name: Member name that will be updated.
    :param requests_authorization_level: Requests authorization level, can be 0/1/2.
    :param membership_expiration_date: MM|DD|YY or empty if there is no expiration date.
    :param permissions: User’s permissions in the safe.
    :return: CommandResults
    """
    permissions_list = argToList(permissions)
    response = client.update_safe_member(
        safe_name, member_name, requests_authorization_level, membership_expiration_date, permissions_list
    )
    results = CommandResults(
        raw_response=response,
        outputs_prefix="CyberArkPAS.Safes.Members",
        outputs_key_field=member_name,
        outputs=response.get("member"),
    )
    return results


def delete_safe_member_command(
    client: Client,
    safe_name: str,
    member_name: str,
) -> CommandResults:
    """Remove a specific member from a safe.
    :param client: The client object with an access token
    :param safe_name: Name of the safe to which the safe member belongs.
    :param member_name: The name of the safe member to delete from the safe’s list of members.
    :return: CommandResults
    """
    # the response should be an empty string, if an error raised it would be catch in the main block
    client.delete_safe_member(safe_name, member_name)
    return CommandResults(
        readable_output=f"Member {member_name} was deleted from {safe_name} safe",
        outputs_prefix="CyberArkPAS.Safes.Members",
        outputs_key_field="MemberName",
        outputs={"MemberName": member_name, "Deleted": True},
    )


def add_account_command(
    client: Client,
    account_name: str = "",
    address: str = "",
    username: str = "",
    platform_id: str = "",
    safe_name: str = "",
    password: str = "",
    secret_type: str = "password",
    properties: dict | str = "",
    automatic_management_enabled: str = "true",
    manual_management_reason: str = "",
    remote_machines: str = "",
    access_restricted_to_remote_machines: str = "true",
) -> CommandResults:
    """Add a new privileged account or SSH key to the vault.
    :param client: The client object with an access token
    :param account_name: The name of the account.
    :param address: The name or address of the machine where the account will be used.
    :param username: The account username.
    :param platform_id: The platform assigned to this account.
    :param safe_name: The safe where the account will be created.
    :param password: The password value.
    :param secret_type: The type of password.
    :param properties: Object containing key-value pairs to associate with the account,
     as defined by the account platform. e.g.- {"Location": "IT", "OwnerName": "MSSPAdmin"}
    :param automatic_management_enabled: Whether the account secret is automatically managed by the CPM.
    :param manual_management_reason: Reason for disabling automatic secret management.
    :param remote_machines: List of remote machines, separated by semicolons.
    :param access_restricted_to_remote_machines: Whether or not to restrict access only to specified remote machines.
    :return: CommandResults
    """
    response = client.add_account(
        account_name,
        address,
        username,
        platform_id,
        safe_name,
        password,
        secret_type,
        order_properties_to_dict(properties),
        automatic_management_enabled,
        manual_management_reason,
        remote_machines,
        access_restricted_to_remote_machines,
    )
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Accounts", outputs_key_field="id", outputs=response
    )
    return results


def update_account_command(
    client: Client,
    account_id: str = "",
    account_name: str = "",
    address: str = "",
    username: str = "",
    platform_id: str = "",
) -> CommandResults:
    """Update an existing account's details.
    :param client: The client object with an access token
    :param account_id: The unique id of the account to update.
    :param account_name: The name of the account.
    :param address: The name or address of the machine where the account will be used.
    :param username: The account username.
    :param platform_id: The platform assigned to this account.
    :return: CommandResults
    """
    response = client.update_account(account_id, account_name, address, username, platform_id)
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Accounts", outputs_key_field="id", outputs=response
    )
    return results


def delete_account_command(
    client: Client,
    account_id: str = "",
) -> CommandResults:
    """Delete a specific account in the vault.
    :param client: The client object with an access token
    :param account_id: The unique id of the account to delete.
    :return: CommandResults
    """
    # the response should be an empty string, if an error raised it would be catch in the main block
    client.delete_account(account_id)
    return CommandResults(
        readable_output=f"Account {account_id} was deleted",
        outputs_prefix="CyberArkPAS.Accounts",
        outputs_key_field="id",
        outputs={"id": account_id, "Deleted": True},
    )


def get_list_accounts_command(
    client: Client,
    search: str = "",
    sort: str = "",
    offset: str = "0",
    limit: str = "50",
    filter: str = "",
) -> CommandResults:
    """Return a list of all the accounts in the vault.
    :param client: The client object with an access token
    :param search: List of keywords to search for in accounts. Separated with a space, e.g- Windows admin
    :param sort: Property or properties by which to sort returned accounts.
    :param offset: Offset of the first account that is returned in the collection of results.
    :param limit: Maximum number of returned accounts.
    :param filter: Search for accounts filtered by a specific safe.
    :return: CommandResults
    """
    response = client.get_list_accounts(search, sort, offset, limit, filter)
    total_accounts = response.get("count")
    accounts = response.get("value")
    headline = f"There are {total_accounts} accounts"
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(headline, accounts),
        outputs_prefix="CyberArkPAS.Accounts",
        outputs_key_field="id",
        outputs=accounts,
    )
    return results


def get_list_account_activity_command(
    client: Client,
    account_id: str = "",
) -> CommandResults:
    """Returns the activities of a specific account that is identified by its account id.
    :param client: The client object with an access token
    :param account_id: The id of the account whose activities will be retrieved.
    :return: CommandResults
    """
    response = client.get_list_account_activity(account_id)
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Activities", outputs_key_field="", outputs=response.get("Activities")
    )
    return results


def get_account_details_command(
    client: Client,
    account_id: str = "",
) -> CommandResults:
    """Returns information of a specific account that is identified by its account id.
    :param client: The client object with an access token
    :param account_id: The id of the account whose details will be retrieved.
    :return: CommandResults
    """
    response = client.get_account_details(account_id)
    results = CommandResults(
        raw_response=response, outputs_prefix="CyberArkPAS.Accounts", outputs_key_field="id", outputs=response
    )
    return results


def change_credentials_random_password_command(
    client: Client,
    account_id: str,
) -> str:
    """Mark an account for an immediate credentials change by the CPM to a new random value.
    :param client: The client object with an access token
    :param account_id: The unique ID of the account.
    :return: Action was succeeded notice
    """
    client.change_credentials_random_password(account_id)
    return f"The password in the account {account_id} was changed"


def change_credentials_set_new_password_command(
    client: Client,
    account_id: str,
    new_credentials: str,
) -> str:
    """Enables users to set the account's credentials to use for the next CPM change.
    :param client: The client object with an access token
    :param account_id: The unique ID of the account.
    :param new_credentials: The new account credentials that will be allocated to the account in the vault.
    :return: Action was succeeded notice
    """
    client.change_credentials_set_new_password(account_id, new_credentials)
    return f"The password in the account {account_id} was changed"


def change_credentials_in_vault_only_command(
    client: Client,
    account_id: str,
    new_credentials: str,
) -> str:
    """Enables users to set account credentials and change them in the vault.
    :param client: The client object with an access token
    :param account_id: The unique ID of the account.
    :param new_credentials: The new account credentials that will be allocated to the account in the vault.
    :return: Action was succeeded notice
    """
    client.change_credentials_in_vault_only(account_id, new_credentials)
    return f"The password in the account {account_id} was changed"


def verify_credentials_command(
    client: Client,
    account_id: str,
) -> str:
    """Mark an account for verification by the CPM.
    :param client: The client object with an access token
    :param account_id: The unique ID of the account.
    :return: Action was succeeded notice
    """
    client.verify_credentials(account_id)
    return f"The account {account_id} was marked for verification by the CPM"


def reconcile_credentials_command(
    client: Client,
    account_id: str,
) -> str:
    """Marks an account for automatic reconciliation by the CPM.
    :param client: The client object with an access token
    :param account_id: The unique ID of the account.
    :return: Action was succeeded notice
    """
    client.reconcile_credentials(account_id)
    return f"The account {account_id} was marked for automatic reconciliation by the CPM."


def get_security_events_command(client: Client, start_time: str, limit: str = "50") -> CommandResults:
    """Returns all PTA security events.
    :param client: The client object with an access token
    :param start_time: The starting date to get the security events from as timestamp.
    :param limit: The number of events that will be shown, from newest to oldest.
    :return: Action was succeeded notice
    """

    start, _ = parse_date_range(start_time)
    start_time_timestamp = str(date_to_timestamp(start))

    events_data = client.get_security_events(start_time_timestamp)

    if not events_data:
        return CommandResults(outputs="No events were found")

    if limit:
        events_data = events_data[0 : int(limit)]

    results = CommandResults(
        outputs=events_data,
        raw_response=events_data,
        outputs_prefix="CyberArkPAS.SecurityEvents",
        outputs_key_field="id",
    )
    return results


def fetch_incidents(
    client: Client, last_run: dict, first_fetch_time: str, score: str, max_fetch: str = "50"
) -> Tuple[dict, list]:
    # if first time fetching
    if not last_run:
        start_time, _ = parse_date_range(first_fetch_time)
        start_time_timestamp = str(date_to_timestamp(start_time))
        next_run = {"time": start_time_timestamp, "last_event_ids": []}
    else:
        next_run = last_run

    events_data = client.get_security_events(str(next_run.get("time")))

    if not events_data:
        return next_run, []

    filtered_events_data = filter_by_score(events_data, int(score))

    # the events are sorted from the newest to the oldest so first we reverse the list
    reverse_events_data = filtered_events_data[::-1]

    incidents = []
    if reverse_events_data:
        last_event_ids = last_run.get("last_event_ids", [])
        new_event_ids = []
        event_updated_time = None

        incidents_num = 0

        for event_data in reverse_events_data:
            # by reversing the list before, we can now go over the items from the oldest to the newest
            event_id = event_data.get("id")

            if event_id not in last_event_ids:  # check that event was not fetched in the last fetch
                incidents_num += 1
                event_updated_time = event_data.get("lastUpdateTime")
                incident = {
                    "name": f"CyberArk PAS Incident: {event_id}.",
                    "occurred": timestamp_to_datestring(event_updated_time),
                    "severity": incident_priority_to_dbot_score(float(event_data.get("score"))),
                    "rawJSON": json.dumps(event_data),
                }
                incidents.append(incident)
                new_event_ids.append(event_id)

            # make sure that there are no more than max_fetch incidents that are being created
            if incidents_num >= int(max_fetch):
                break

        if new_event_ids and event_updated_time:
            next_run = {
                "time": str(event_updated_time),
                "last_event_ids": json.dumps(new_event_ids),  # save the event IDs from the last fetch
            }
    demisto.debug(f"CyberArk PAS last fetch data: {str(next_run)}")
    return next_run, incidents


def main():
    params = demisto.params()
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    url = params.get("url")
    use_ssl = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    max_fetch = min("200", params.get("max_fetch", "200"))
    first_fetch_time = params.get("fetch_time", "3 days").strip()
    score = params.get("score", "0")

    command = demisto.command()
    LOG(f"Command being called in CyberArkPAS is: {command}")
    commands = {
        "test-module": test_module,
        "cyberark-pas-user-add": add_user_command,
        "cyberark-pas-user-update": update_user_command,
        "cyberark-pas-user-delete": delete_user_command,
        "cyberark-pas-users-list": get_users_command,
        "cyberark-pas-user-activate": activate_user_command,
        "cyberark-pas-safe-add": add_safe_command,
        "cyberark-pas-safe-update": update_safe_command,
        "cyberark-pas-safe-delete": delete_safe_command,
        "cyberark-pas-safes-list": get_list_safes_command,
        "cyberark-pas-safe-get-by-name": get_safe_by_name_command,
        "cyberark-pas-safe-member-add": add_safe_member_command,
        "cyberark-pas-safe-member-update": update_safe_member_command,
        "cyberark-pas-safe-member-delete": delete_safe_member_command,
        "cyberark-pas-safe-members-list": list_safe_members_command,
        "cyberark-pas-account-add": add_account_command,
        "cyberark-pas-account-update": update_account_command,
        "cyberark-pas-account-delete": delete_account_command,
        "cyberark-pas-accounts-list": get_list_accounts_command,
        "cyberark-pas-account-get-list-activity": get_list_account_activity_command,
        "cyberark-pas-account-get-details": get_account_details_command,
        "cyberark-pas-credentials-change-random-password": change_credentials_random_password_command,
        "cyberark-pas-credentials-change-set-new-password": change_credentials_set_new_password_command,
        "cyberark-pas-credentials-change-in-vault-only": change_credentials_in_vault_only_command,
        "cyberark-pas-credentials-verify": verify_credentials_command,
        "cyberark-pas-credentials-reconcile": reconcile_credentials_command,
        "cyberark-pas-security-events-get": get_security_events_command,
    }

    try:
        client = Client(
            server_url=url, username=username, password=password, use_ssl=use_ssl, proxy=proxy, max_fetch=int(max_fetch)
        )

        if command in commands:
            return_results(commands[command](client, **demisto.args()))  # type: ignore[operator]
        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client, last_run=demisto.getLastRun(), first_fetch_time=first_fetch_time, score=score, max_fetch=max_fetch
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        else:
            raise NotImplementedError(f"{command} is not an existing CyberArk PAS command")
    except Exception as err:
        return_error(f"Unexpected error: {str(err)}", error=traceback.format_exc())
    finally:
        try:
            client._logout()
        except Exception as err:
            demisto.info(f"CyberArk PAS error: {str(err)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()

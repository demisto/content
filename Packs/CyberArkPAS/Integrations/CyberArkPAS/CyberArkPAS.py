from typing import Dict, Tuple, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
from dateparser import parse

# Disable insecure warnings
urllib3.disable_warnings()
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client(BaseClient):
    """
    Client to use in the CrowdStrikeFalconX integration. Uses BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str, use_ssl: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=use_ssl, proxy=proxy)
        self._username = username
        self._password = password
        self._token = self._generate_token()
        self._headers = {'Authorization': self._token, 'Content-Type': 'application/json'}

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        body = {
            "username": self._username,
            "password": self._password,
        }

        headers = {
            'Content-Type': 'application/json'
        }
        return self._http_request("POST", "/PasswordVault/API/Auth/CyberArkPAS/Logon", headers=headers, json_data=body)

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
            location: str
    ):
        url_suffix = "/PasswordVault/api/Users"
        body = {
            "username": username,
            "userType": user_type,
            "initialPassword": password,
            "authenticationMethod": ["AuthTypePass"],
            "location": location,
            "unAuthorizedInterfaces": non_authorized_interfaces,
            "expiryDate": expiry_date,  # 1577836800
            "vaultAuthorization": vault_authorization,
            "enableUser": enable_user == "true",
            "changePassOnNextLogon": change_password_on_the_next_logon == "true",
            "passwordNeverExpires": password_never_expires == "true",
            "distinguishedName": distinguished_name,
            "description": description,
            "internet":
                {
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
            location: str
    ):
        url_suffix = f"/PasswordVault/api/Users/{user_id}"
        body = {
            "enableUser": enable_user == "true",
            "changePassOnNextLogon": change_password_on_the_next_logon == "true",
            "expiryDate": expiry_date,
            "unAuthorizedInterfaces": non_authorized_interfaces,
            "authenticationMethod": ["AuthTypePass"],
            "passwordNeverExpires": password_never_expires == "true",
            "distinguishedName": distinguished_name,
            "description": description,
            "internet": {
                "businessEmail": email,
            },
            "personalDetails": {
                "profession": profession,
                "firstName": first_name,
                "lastName": last_name
            },
            "id": user_id,
            "username": username,
            "source": "CyberArkPAS",
            "userType": user_type,
            "vaultAuthorization": vault_authorization,
            "location": location,
        }

        return self._http_request("PUT", url_suffix, json_data=body)

    def delete_user(self,
                    user_id: str
                    ):
        url_suffix = f"/PasswordVault/api/Users/{user_id}"

        # json is not defined for this response, therefore we wish to get the "text" value back
        return self._http_request("DELETE", url_suffix, resp_type='text')

    def get_users(self,
                  filter: str,
                  search: str,
                  ):
        url_suffix = "/PasswordVault/api/Users"

        body = {
            "filter": filter,
            "search": search,
        }

        return self._http_request("GET", url_suffix, json_data=body)

    def activate_user(self,
                      user_id: str
                      ):
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Users/{user_id}"

        return self._http_request("PUT", url_suffix, resp_type='text')

    def get_list_safes(self):
        url_suffix = "/PasswordVault/api/Safes"

        return self._http_request("GET", url_suffix)

    def get_safe_by_name(self, safe_name: str):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}"

        return self._http_request("GET", url_suffix)

    def add_safe(self,
                 safe_name: str,
                 description: str,
                 OLAC_enabled: str,
                 managing_cmp: str,
                 number_of_versions_retention: str,
                 number_of_days_retention: str,
                 location: str
                 ):
        url_suffix = "/PasswordVault/api/Safes"

        body = {
            "SafeName": safe_name,
            "Description": description,
            "OLACEnabled": OLAC_enabled == "true",
            "ManagingCPM": managing_cmp,
            "NumberOfVersionsRetention": number_of_versions_retention,
            "NumberOfDaysRetention": number_of_days_retention,
            "Location": location
        }
        return self._http_request("POST", url_suffix, json_data=body)

    def update_safe(self,
                    safe_name: str,
                    safe_new_name: str,
                    description: str,
                    OLAC_enabled: str,
                    managing_cmp: str,
                    number_of_versions_retention: str,
                    number_of_days_retention: str,
                    location: str = ""
                    ):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}"
        if not safe_new_name:
            safe_new_name = safe_name
        body = {
            "SafeName": safe_new_name,
            "Description": description,
            "OLACEnabled": OLAC_enabled == "true",
            "ManagingCPM": managing_cmp,
            "NumberOfVersionsRetention": number_of_versions_retention,
            "NumberOfDaysRetention": number_of_days_retention,
            "Location": location
        }
        return self._http_request("PUT", url_suffix, json_data=body)

    def delete_safe(self,
                    safe_name: str,
                    ):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}"

        # json is not defined for this response, therefore we wish to get the "text" value back
        return self._http_request("DELETE", url_suffix, resp_type='text')

    def list_safe_members(self,
                          safe_name: str
                          ):
        url_suffix = f"/PasswordVault/api/Safes/{safe_name}/Members"

        return self._http_request("GET", url_suffix)

    def add_safe_member(self,
                        safe_name: str,
                        member_name: str,
                        requests_authorization_level: str,
                        membership_expiration_date: str,
                        permissions: list,
                        search_in: str,
                        ):
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Safes/{safe_name}/Members"

        body = {
            "member": {
                "MemberName": member_name,
                "SearchIn": search_in,
                "MembershipExpirationDate": membership_expiration_date,
                "Permissions":
                    [
                        {"Key": "UseAccounts", "Value": "UseAccounts" in permissions},
                        {"Key": "RetrieveAccounts", "Value": "RetrieveAccounts" in permissions},
                        {"Key": "ListAccounts", "Value": "ListAccounts" in permissions},
                        {"Key": "AddAccounts", "Value": "AddAccounts" in permissions},
                        {"Key": "UpdateAccountContent", "Value": "UpdateAccountContent" in permissions},
                        {"Key": "UpdateAccountProperties", "Value": "UpdateAccountProperties" in permissions},
                        {"Key": "InitiateCPMAccountManagementOperations",
                         "Value": "InitiateCPMAccountManagementOperations" in permissions},
                        {"Key": "SpecifyNextAccountContent", "Value": "SpecifyNextAccountContent" in permissions},
                        {"Key": "RenameAccounts", "Value": "RenameAccounts" in permissions},
                        {"Key": "DeleteAccounts", "Value": "DeleteAccounts" in permissions},
                        {"Key": "UnlockAccounts", "Value": "UnlockAccounts" in permissions},
                        {"Key": "ManageSafe", "Value": "ManageSafe" in permissions},
                        {"Key": "ManageSafeMembers", "Value": "xxx" in permissions},
                        {"Key": "BackupSafe", "Value": "BackupSafe" in permissions},
                        {"Key": "ViewAuditLog", "Value": "ViewAuditLog" in permissions},
                        {"Key": "ViewSafeMembers", "Value": "ViewSafeMembers" in permissions},
                        {"Key": "RequestsAuthorizationLevel", "Value": int(requests_authorization_level)},
                        {"Key": "AccessWithoutConfirmation", "Value": "AccessWithoutConfirmation" in permissions},
                        {"Key": "CreateFolders", "Value": "CreateFolders" in permissions},
                        {"Key": "DeleteFolders", "Value": "DeleteFolders" in permissions},
                        {"Key": "MoveAccountsAndFolders", "Value": "MoveAccountsAndFolders" in permissions},
                    ]

            }
        }
        return self._http_request("POST", url_suffix, json_data=body)

    def add_account(self,
                    account_name: list,
                    address: str,
                    username: str,
                    platform_id: str,
                    safe_name: str,
                    password: str,
                    secret_type: str,
                    properties: str,
                    automatic_management_enabled: str,
                    manual_management_reason: str,
                    remote_machines: str,
                    access_restricted_to_temote_machines: str
                    ):
        url_suffix = f"/PasswordVault/api/Accounts"

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
                "manualManagementReason": manual_management_reason
            },
            "remoteMachinesAccess": {
                "remoteMachines": remote_machines,
                "accessRestrictedToRemoteMachines": access_restricted_to_temote_machines == "true"
            }
        }
        return self._http_request("POST", url_suffix, json_data=body)

    def update_safe_member(self,
                           safe_name: str,
                           member_name: str,
                           requests_authorization_level: str,
                           membership_expiration_date: str,
                           permissions: list,
                           ):
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Safes/{safe_name}/Members/{member_name}"

        body = {
            "member": {
                "MembershipExpirationDate": membership_expiration_date,
                "Permissions":
                    [
                        {"Key": "UseAccounts", "Value": "UseAccounts" in permissions},
                        {"Key": "RetrieveAccounts", "Value": "RetrieveAccounts" in permissions},
                        {"Key": "ListAccounts", "Value": "ListAccounts" in permissions},
                        {"Key": "AddAccounts", "Value": "AddAccounts" in permissions},
                        {"Key": "UpdateAccountContent", "Value": "UpdateAccountContent" in permissions},
                        {"Key": "UpdateAccountProperties", "Value": "UpdateAccountProperties" in permissions},
                        {"Key": "InitiateCPMAccountManagementOperations",
                         "Value": "InitiateCPMAccountManagementOperations" in permissions},
                        {"Key": "SpecifyNextAccountContent", "Value": "SpecifyNextAccountContent" in permissions},
                        {"Key": "RenameAccounts", "Value": "RenameAccounts" in permissions},
                        {"Key": "DeleteAccounts", "Value": "DeleteAccounts" in permissions},
                        {"Key": "UnlockAccounts", "Value": "UnlockAccounts" in permissions},
                        {"Key": "ManageSafe", "Value": "ManageSafe" in permissions},
                        {"Key": "ManageSafeMembers", "Value": "xxx" in permissions},
                        {"Key": "BackupSafe", "Value": "BackupSafe" in permissions},
                        {"Key": "ViewAuditLog", "Value": "ViewAuditLog" in permissions},
                        {"Key": "ViewSafeMembers", "Value": "ViewSafeMembers" in permissions},
                        {"Key": "RequestsAuthorizationLevel", "Value": int(requests_authorization_level)},
                        {"Key": "AccessWithoutConfirmation", "Value": "AccessWithoutConfirmation" in permissions},
                        {"Key": "CreateFolders", "Value": "CreateFolders" in permissions},
                        {"Key": "DeleteFolders", "Value": "DeleteFolders" in permissions},
                        {"Key": "MoveAccountsAndFolders", "Value": "MoveAccountsAndFolders" in permissions},
                    ]
            }
        }
        return self._http_request("PUT", url_suffix, json_data=body)

    def delete_safe_member(self,
                           safe_name: str,
                           member_name: str,
                           ):
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Safes/{safe_name}/Members/{member_name}"

        return self._http_request("DELETE", url_suffix, resp_type='text')

    def delete_account(self,
                       account_id: str,
                       ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}"

        return self._http_request("DELETE", url_suffix, resp_type='text')

    def get_list_accounts(self,
                          search: str,
                          sort: str,
                          offset: str,
                          limit: str,
                          filter: str,
                          ):
        url_suffix = f"/PasswordVault/api/Accounts?search={search}&sort={sort}&offset={offset}&limit={limit}&filter={filter}"
        return self._http_request("GET", url_suffix)

    def get_list_account_activity(self,
                                  account_id: str,
                                  ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}/Activities"
        return self._http_request("GET", url_suffix)

    def change_credentials_random_password(self,
                                           account_id: str,
                                           ):
        url_suffix = f"/PasswordVault/API/Accounts/{account_id}/Change"
        body = {
            "ChangeEntireGroup": "true"
        }
        return self._http_request("POST", url_suffix, json_data=body, resp_type='text')

    def change_credentials_set_new_password(self,
                                            account_id: str,
                                            new_credentials: str,
                                            ):
        url_suffix = f"/passwordvault/api/Accounts/{account_id}/SetNextPassword"
        body = {
            "ChangeImmediately": "true" == "true",
            "NewCredentials": new_credentials,
        }
        return self._http_request("POST", url_suffix, json_data=body, resp_type='text')

    def change_credentials_in_vault_only(self,
                                         account_id: str,
                                         new_credentials: str,
                                         ):
        url_suffix = f"/passwordvault/api/Accounts/{account_id}/Password/Update"
        body = {
            "NewCredentials": new_credentials,
        }
        return self._http_request("POST", url_suffix, json_data=body, resp_type='text')

    def verify_credentials(self,
                           account_id: str,
                           ):
        url_suffix = f"/PasswordVault/WebServices/PIMServices.svc/Accounts/{account_id}/VerifyCredentials"

        return self._http_request("POST", url_suffix, resp_type='text')

    def reconcile_credentials(self,
                              account_id: str,
                              ):
        url_suffix = f"/PasswordVault/API/Accounts/{account_id}/Reconcile"

        return self._http_request("POST", url_suffix, resp_type='text')

    def update_account(self,
                       account_id: str,
                       account_name: str,
                       address: str,
                       username: str,
                       platform_id: str,
                       ):
        url_suffix = f"/PasswordVault/api/Accounts/{account_id}"

        arguments = {"name": account_name,
                     "address": address,
                     "userName": username,
                     "platformId": platform_id}
        body = []
        for key, value in arguments.items():
            if value:
                body.append(
                    {
                        "op": "replace",
                        "path": f"/{key}",
                        "value": f"{value}"
                    }
                )

        return self._http_request("PATCH", url_suffix, data=str(body))

    def get_security_events(self,
                            ):

        url_suffix = "/PasswordVault/API/pta/API/Events/"
        return self._http_request("GET", url_suffix)


def test_module(
        client: Client,
) -> str:
    """
    If a client was made then an accesses token was successfully reached,
    therefor the username and password are valid and a connection was made
    additionally, checks if not using all the optional quota
    :param client: the client object with an access token
    :return: ok if got a valid accesses token and not all the quota is used at the moment
    """
    client._logout()
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
        location: str = "\\"
):
    non_authorized_interfaces_list = argToList(non_authorized_interfaces)
    vault_authorization_list = argToList(vault_authorization)

    response = client.add_user(username, user_type, non_authorized_interfaces_list, expiry_date, password,
                               change_password_on_the_next_logon, password_never_expires, vault_authorization_list,
                               description, email, first_name, last_name, enable_user, profession, distinguished_name,
                               location)
    id = response.get("id")
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Users.{id}',
        outputs_key_field='id',
        outputs=response
    )
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
        location: str = "\\"
):
    non_authorized_interfaces_list = argToList(non_authorized_interfaces)
    vault_authorization_list = argToList(vault_authorization)

    response = client.update_user(user_id, username, user_type, non_authorized_interfaces_list, expiry_date,
                                  change_password_on_the_next_logon, password_never_expires, vault_authorization_list,
                                  description, email, first_name, last_name, enable_user, profession,
                                  distinguished_name,
                                  location)
    user_id = response.get("id")
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Users.{user_id}',
        outputs_key_field='id',
        outputs=response
    )
    return results


def delete_user_command(
        client: Client,
        user_id: str,
):
    response = client.delete_user(user_id)
    # the response should be an empty string, if an error raised it would be catch in the main block
    # should never enter to the else block, extra precautions if something want wrong
    if not response:
        return CommandResults(
            readable_output=f"User {user_id} was deleted",
            outputs_prefix=f'CyberArkPAS.Users.{user_id}',
            outputs_key_field='id',
            outputs={"id": user_id, "deleted": True}
        )
    else:
        return response


def get_users_command(
        client: Client,
        filter: str = "",
        search: str = "",
):
    response = client.get_users(filter, search)
    total_users = response.get("Total")
    headline = f"There are {total_users} users"
    users = response.get("Users")
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(headline, users),
        outputs_prefix='CyberArkPAS.Users',
        outputs_key_field='id',
        outputs=users,
    )
    return results


def activate_user_command(
        client: Client,
        user_id: str,
):
    response = client.activate_user(user_id)
    if not response:
        return f"User {user_id} was activated"
    else:
        return response


def get_list_safes_command(
        client: Client,
):
    response = client.get_list_safes()
    total_safes = response.get("Total")
    headline = f"There are {total_safes} safes"
    safes = response.get("Safes")
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(headline, safes),
        outputs_prefix=f'CyberArkPAS.Safes',
        outputs_key_field='SafeName',
        outputs=safes
    )
    return results


def get_safe_by_name_command(
        client: Client,
        safe_name: str,
):
    response = client.get_safe_by_name(safe_name)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Safes.{safe_name}',
        outputs_key_field='SafeName',
        outputs=response
    )
    return results


def add_safe_command(
        client: Client,
        safe_name: str,
        description: str = "",
        OLAC_enabled: str = "true",
        managing_cmp: str = "",
        number_of_versions_retention: str = "",
        number_of_days_retention: str = "",
        location: str = ""
):
    response = client.add_safe(safe_name, description, OLAC_enabled, managing_cmp, number_of_versions_retention,
                               number_of_days_retention, location)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Safes.{safe_name}',
        outputs_key_field='SafeName',
        outputs=response
    )
    return results


def update_safe_command(
        client: Client,
        safe_name: str,
        safe_new_name: str = "",
        description: str = "",
        OLAC_enabled: str = "true",
        managing_cmp: str = "",
        number_of_versions_retention: str = "",
        number_of_days_retention: str = "",
        location: str = ""
):
    response = client.update_safe(safe_name, safe_new_name, description, OLAC_enabled, managing_cmp,
                                  number_of_versions_retention,
                                  number_of_days_retention, location)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Safes.{safe_name}',
        outputs_key_field='SafeName',
        outputs=response
    )
    return results


def delete_safe_command(
        client: Client,
        safe_name: str,
):
    response = client.delete_safe(safe_name)
    # the response should be an empty string, if an error raised it would be catch in the main block
    # should never enter to the else block, extra precautions if something want wrong
    if not response:
        return CommandResults(
            readable_output=f"Safe {safe_name} was deleted",
            outputs_prefix=f'CyberArkPAS.Safes.{safe_name}',
            outputs_key_field='SafeName',
            outputs={"SafeName": safe_name, "deleted": True}
        )
    else:
        return response


def list_safe_members_command(
        client: Client,
        safe_name: str
):
    response = client.list_safe_members(safe_name)
    total_safe_members = response.get("Total")
    headline = f"There are {total_safe_members} safe members for {safe_name}"
    members = response.get("SafeMembers")
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(headline, members),
        outputs_prefix=f'CyberArkPAS.{safe_name}.Members',
        outputs_key_field='MemberName',
        outputs=members
    )
    return results


def add_safe_member_command(
        client: Client,
        safe_name: str,
        member_name: str,
        requests_authorization_level: str = "0",
        membership_expiration_date: str = "",
        permissions: str = "",
        search_in: str = ""
):
    permissions_list = argToList(permissions)
    response = client.add_safe_member(safe_name, member_name, requests_authorization_level, membership_expiration_date,
                                      permissions_list, search_in)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.{safe_name}.{member_name}',
        outputs_key_field=member_name,
        outputs=response.get("member")
    )
    return results


def update_safe_member_command(
        client: Client,
        safe_name: str,
        member_name: str,
        requests_authorization_level: str = "0",
        membership_expiration_date: str = "",
        permissions: str = "",
):
    permissions_list = argToList(permissions)
    response = client.update_safe_member(safe_name, member_name, requests_authorization_level,
                                         membership_expiration_date, permissions_list)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.{safe_name}.{member_name}',
        outputs_key_field=member_name,
        outputs=response.get("member")
    )
    return results


def delete_safe_member_command(
        client: Client,
        safe_name: str,
        member_name: str,
):
    response = client.delete_safe_member(safe_name, member_name)
    # the response should be an empty string, if an error raised it would be catch in the main block
    # should never enter to the else block, extra precautions if something want wrong
    if not response:
        return CommandResults(
            readable_output=f"Member {member_name} was deleted from {safe_name} safe",
            outputs_prefix=f'CyberArkPAS.{safe_name}.{member_name}',
            outputs_key_field='MemberName',
            outputs={"MemberName": member_name, "deleted": True}
        )
    else:
        return response


def add_account_command(
        client: Client,
        account_name: list = "",
        address: str = "",
        username: str = "",
        platform_id: str = "",
        safe_name: str = "",
        password: str = "",
        secret_type: str = "password",
        properties: str = "",
        automatic_management_enabled: str = "true",
        manual_management_reason: str = "",
        remote_machines: str = "",
        access_restricted_to_temote_machines: str = "true"
):
    response = client.add_account(account_name, address, username, platform_id, safe_name, password, secret_type,
                                  properties, automatic_management_enabled, manual_management_reason, remote_machines,
                                  access_restricted_to_temote_machines)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Accounts.{response.get("id")}',
        outputs_key_field='id',
        outputs=response
    )
    return results


def update_account_command(
        client: Client,
        account_id: str = "",
        account_name: str = "",
        address: str = "",
        username: str = "",
        platform_id: str = "",
):
    response = client.update_account(account_id, account_name, address, username, platform_id)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.Accounts.{response.get("id")}',
        outputs_key_field='id',
        outputs=response
    )
    return results


def delete_account_command(
        client: Client,
        account_id: str = "",
):
    response = client.delete_account(account_id)
    # the response should be an empty string, if an error raised it would be catch in the main block
    # should never enter to the else block, extra precautions if something want wrong
    if not response:
        return CommandResults(
            readable_output=f"Account {account_id} was deleted",
            outputs_prefix=f'CyberArkPAS.Accounts.{account_id}',
            outputs_key_field='id',
            outputs={"id": account_id, "deleted": True}
        )
    else:
        return response


def get_list_accounts_command(
        client: Client,
        search: str = "",
        sort: str = "",
        offset: str = "0",
        limit: str = "50",
        filter: str = "",
):
    response = client.get_list_accounts(search, sort, offset, limit, filter)
    total_accounts = response.get("count")
    accounts = response.get("value")
    headline = f"There are {total_accounts} accounts"
    results = CommandResults(
        raw_response=response,
        readable_output=tableToMarkdown(headline, accounts),
        outputs_prefix=f'CyberArkPAS.Accounts',
        outputs_key_field='id',
        outputs=accounts
    )
    return results


def get_list_account_activity_command(
        client: Client,
        accountID: str = "",
):
    response = client.get_list_account_activity(accountID)
    results = CommandResults(
        raw_response=response,
        outputs_prefix=f'CyberArkPAS.{accountID}.Activities',
        outputs_key_field='',
        outputs=response.get("Activities")
    )
    return results


def change_credentials_random_password_command(
        client: Client,
        account_id: str,
):
    response = client.change_credentials_random_password(account_id)
    if not response:
        return f"The password in the account {account_id} was changed"
    else:
        return response


def change_credentials_set_new_password_command(
        client: Client,
        account_id: str,
        new_credentials: str,
):
    response = client.change_credentials_set_new_password(account_id, new_credentials)
    if not response:
        return f"The password in the account {account_id} was changed"
    else:
        return response


def change_credentials_in_vault_only_command(
        client: Client,
        account_id: str,
        new_credentials: str,
):
    response = client.change_credentials_in_vault_only(account_id, new_credentials)
    if not response:
        return f"The password in the account {account_id} was changed"
    else:
        return response


def verify_credentials_command(
        client: Client,
        account_id: str,
):
    response = client.verify_credentials(account_id)
    if not response:
        return f"The account {account_id} was marked for verification by the CPM"
    else:
        return response


def reconcile_credentials_command(
        client: Client,
        account_id: str,
):
    response = client.reconcile_credentials(account_id)
    if not response:
        return f"The account {account_id} was marked for automatic reconciliation by the CPM."
    else:
        return response


def fetch_incidents(client: Client, last_run: dict,  first_fetch_time: str,  max_fetch: str = '50') -> Tuple[dict, list]:

    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    if not last_run:  # if first time fetching
        next_run = {
            'time': parse_date_range(first_fetch_time, date_format=timestamp_format)[0],
            'last_event_ids': []
        }
    else:
        next_run = last_run

    events_data = client.get_security_events()
    events_data_length = len(events_data)
    if events_data_length > int(max_fetch):
        events_data = events_data[events_data_length-1-int(max_fetch):events_data_length-1]
    incidents = []

    if events_data:
        last_event_ids = last_run.get('last_event_ids', [])
        new_event_ids = []
        last_event_created_time = None
        for event_data in events_data:
            event_id = event_data.get('id')

            if event_id not in last_event_ids:  # check that event was not fetched in the last fetch
                last_event_created_time = parse(event_data.get('createTime'))
                incident = {
                    'id': event_data.get('id'),
                    'type': event_data.get('type'),
                    'score': event_data.get('score'),
                    'mStatus': event_data.get('mStatus'),
                    'rawJSON': json.dumps(event_data)
                }
                incidents.extend([incident])
                new_event_ids.extend([event_id])

        if new_event_ids and last_event_created_time:
            next_run = {
                'time': last_event_created_time.strftime(timestamp_format),
                'last_event_ids': json.dumps(new_event_ids)  # save the event IDs from the last fetch
            }

    demisto.debug(f'CyberArk PAS last fetch data: {str(next_run)}')
    return next_run, incidents


def main():
    params = demisto.params()

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    url = params.get('url')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    max_fetch = min('50', params.get('max_fetch', '50'))
    first_fetch_time = params.get('fetch_time', '3 days').strip()

    command = demisto.command()
    LOG(f'Command being called in CyberArkPAS is: {command}')
    commands = {
        'test-module': test_module,

        'cyberark-pas-add-user': add_user_command,
        'cyberark-pas-update-user': update_user_command,
        'cyberark-pas-delete-user': delete_user_command,
        'cyberark-pas-get-users': get_users_command,
        'cyberark-pas-activate-user': activate_user_command,

        'cyberark-pas-add-safe': add_safe_command,
        'cyberark-pas-update-safe': update_safe_command,
        'cyberark-pas-delete-safe': delete_safe_command,
        'cyberark-pas-get-list-safes': get_list_safes_command,
        'cyberark-pas-get-safe-by-name': get_safe_by_name_command,

        'cyberark-pas-add-safe-member': add_safe_member_command,
        'cyberark-pas-update-safe-member': update_safe_member_command,
        'cyberark-pas-delete-safe-member': delete_safe_member_command,
        'cyberark-pas-list-safe-members': list_safe_members_command,

        'cyberark-pas-add-account': add_account_command,
        'cyberark-pas-update-account': update_account_command,
        'cyberark-pas-delete-account': delete_account_command,
        'cyberark-pas-get-list-accounts': get_list_accounts_command,
        'cyberark-pas-get-list-account-activity': get_list_account_activity_command,

        'cyberark-pas-change-credentials-random-password': change_credentials_random_password_command,
        'cyberark-pas-change-credentials-set-new-password': change_credentials_set_new_password_command,
        'cyberark-pas-change-credentials-in-vault-only': change_credentials_in_vault_only_command,
        'cyberark-pas-verify-credentials': verify_credentials_command,
        'cyberark-pas-reconcile-credentials': reconcile_credentials_command,

    }

    try:
        client = Client(server_url=url, username=username, password=password, use_ssl=use_ssl, proxy=proxy)

        if command in commands:
            return_results(commands[command](client, **demisto.args()))  # type: ignore[operator]
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                max_fetch=max_fetch
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        else:
            raise NotImplementedError(f'{command} is not an existing CyberArk PAS command')
    except Exception as err:
        return_error(f'Unexpected error: {str(err)}', error=traceback.format_exc())
    finally:
        try:
            client._logout()
        except Exception as err:
            demisto.info("CyberArk PAS error: " + str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

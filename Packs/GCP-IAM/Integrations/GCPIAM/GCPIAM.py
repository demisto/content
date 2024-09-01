import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# pylint: disable=no-member
import copy
from collections.abc import Callable
from googleapiclient import discovery
from oauth2client import service_account
import httplib2
from urllib.parse import urlparse


class Client:
    def __init__(self, client_secret: str, proxy: bool = False, verify_certificate: bool = False):
        client_secret = json.loads(client_secret)
        scopes = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloud-identity',
                  'https://www.googleapis.com/auth/iam', ]
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(client_secret, scopes=scopes)

        proxies = handle_proxy()

        if proxy or verify_certificate:
            http_client = credentials.authorize(self.get_http_client_with_proxy(
                proxies, disable_ssl_certificate=not verify_certificate))
            self.cloud_identity_service = discovery.build('cloudidentity', 'v1', http=http_client)
            self.cloud_resource_manager_service = discovery.build('cloudresourcemanager', 'v3', http=http_client)
            self.iam_service = discovery.build('iam', 'v1', http=http_client)
            self.iam_credentials = discovery.build('iamcredentials', 'v1', http=http_client)

        else:
            self.cloud_identity_service = discovery.build('cloudidentity', 'v1', credentials=credentials)
            self.cloud_resource_manager_service = discovery.build('cloudresourcemanager', 'v3', credentials=credentials)
            self.iam_service = discovery.build('iam', 'v1', credentials=credentials)
            self.iam_credentials = discovery.build('iamcredentials', 'v1', credentials=credentials)

    def get_http_client_with_proxy(self, proxies: dict, disable_ssl_certificate: bool = False):
        proxy_info = None
        if proxies:
            if not proxies or not proxies['https']:
                raise Exception('https proxy value is empty. Check Demisto server configuration')
            https_proxy = proxies['https']
            if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
                https_proxy = 'https://' + https_proxy
            parsed_proxy = urlparse(https_proxy)
            proxy_info = httplib2.ProxyInfo(
                proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
                proxy_host=parsed_proxy.hostname,
                proxy_port=parsed_proxy.port,
                proxy_user=parsed_proxy.username,
                proxy_pass=parsed_proxy.password)
        return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=disable_ssl_certificate)

    def gcp_iam_tagbindings_list_request(self, parent: str, limit: int = None) -> dict:
        """
        List tag bindings (key value pair) applied to a project/folder/organization object.
        Args:
            parent (str): The name of the parent resource to list projects under.
            limit (int): The number of results to retrieve.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=parent, pageSize=limit)

        request = self.cloud_resource_manager_service.tagBindings().list(**params)
        response = request.execute()

        return response

    def gcp_iam_tagvalues_get_request(self, name: str) -> dict:
        """
        Retrieves a TagValue.
        Args:
            name (str): Resource name for TagValue in the format `tagValues/456`.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(name=name)

        request = self.cloud_resource_manager_service.tagValues().get(**params)
        response = request.execute()

        return response

    def gcp_iam_tagkeys_get_request(self, name: str) -> dict:
        """
        Retrieves a TagKey.
        Args:
            name (str): A resource name in the format `tagKeys/{id}`, such as `tagKeys/123`.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(name=name)

        request = self.cloud_resource_manager_service.tagKeys().get(**params)
        response = request.execute()

        return response

    def gcp_iam_project_list_request(self, parent: str, limit: int = None, page_token: str = None,
                                     show_deleted: bool = False) -> dict:
        """
        List projects under the specified parent.
        Args:
            parent (str): The name of the parent resource to list projects under.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.
            show_deleted (bool): Indicate that projects in the DELETE_REQUESTED state should also be retrieved.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=parent, pageSize=limit, pageToken=page_token, showDeleted=show_deleted)

        request = self.cloud_resource_manager_service.projects().list(**params)
        response = request.execute()

        return response

    def gcp_iam_project_get_request(self, project_name: str) -> dict:
        """
        Retrieve project information.
        Args:
            project_name (str): The project name to retrieve.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(name=project_name)

        request = self.cloud_resource_manager_service.projects().get(**params)
        response = request.execute()

        return response

    def gcp_iam_project_iam_policy_get_request(self, project_name: str) -> dict:
        """
        Retrieve the IAM access control policy for the specified project.
        Args:
            project_name (str): The project name for which the policy is being requested.

        Returns:
            dict: API response from GCP.

        """

        params = assign_params(resource=project_name)

        request = self.cloud_resource_manager_service.projects().getIamPolicy(**params)
        response = request.execute()

        return response

    def gcp_iam_project_iam_test_permission_request(self, project_name: str, permissions: list) -> dict:
        """
        Returns permissions that a caller has on the specified project.
        Args:
            project_name (str): The project name for which the permissions is being tested.
            permissions (list): Permissions names to validate.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "permissions": permissions
        }

        request = self.cloud_resource_manager_service.projects().testIamPermissions(resource=project_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_project_iam_policy_set_request(self, project_name: str, policy: list) -> dict:
        """
        Sets the IAM access control policy for the specified project.
        Args:
            project_name (str): The name of the project for which the policy is being specified.
            policy (list): Policy objects to set.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "policy": {
                "bindings": policy
            }
        }

        request = self.cloud_resource_manager_service.projects().setIamPolicy(resource=project_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_folder_list_request(self, parent: str, limit: int = None, page_token: str = None,
                                    show_deleted: bool = False) -> dict:
        """
        List folders under the specified parent.
        Args:
            parent (str): The name of the parent resource to list folders under.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.
            show_deleted (bool): Indicate that folders in the DELETE_REQUESTED state should also be retrieved.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=parent, pageSize=limit, pageToken=page_token, showDeleted=show_deleted)

        request = self.cloud_resource_manager_service.folders().list(**params)
        response = request.execute()

        return response

    def gcp_iam_folder_get_request(self, folder_name: str) -> dict:
        """
        Retrieve folder information.
        Args:
            folder_name (str): The name of the folder to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.cloud_resource_manager_service.folders().get(name=folder_name)
        response = request.execute()

        return response

    def gcp_iam_folder_iam_policy_get_request(self, folder_name: str) -> dict:
        """
        Retrieve the IAM access control policy for the specified folder.
        Args:
            folder_name (str): The folder name for which the policy is being requested.

        Returns:
            dict: API response from GCP.

        """

        params = assign_params(resource=folder_name)

        request = self.cloud_resource_manager_service.folders().getIamPolicy(**params)
        response = request.execute()

        return response

    def gcp_iam_folder_iam_test_permission_request(self, folder_name: str, permissions: list) -> dict:
        """
        Returns permissions that a caller has on the specified folder.
        Args:
            folder_name (str): The folder name for which the permissions is being tested.
            permissions (list): Permissions names to validate.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "permissions": permissions
        }

        request = self.cloud_resource_manager_service.folders().testIamPermissions(resource=folder_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_folder_iam_policy_set_request(self, folder_name: str, policy: list) -> dict:
        """
        Sets the IAM access control policy for the specified folder.
        Args:
            folder_name (str): The name of the folder for which the policy is being specified.
            policy (list): Policy objects to set.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "policy": {
                "bindings": policy
            }
        }

        request = self.cloud_resource_manager_service.folders().setIamPolicy(resource=folder_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_organization_list_request(self, limit: int = None, page_token: str = None) -> dict:
        """
        List organization resources that are visible to the caller.
        Args:
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(pageSize=limit, pageToken=page_token)

        request = self.cloud_resource_manager_service.organizations().search(**params)
        response = request.execute()

        return response

    def gcp_iam_organization_get_request(self, organization_name: str) -> dict:
        """
        Retrieve organization information.
        Args:
            organization_name (str): The name of the organization to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.cloud_resource_manager_service.organizations().get(name=organization_name)
        response = request.execute()

        return response

    def gcp_iam_organization_iam_policy_get_request(self, organization_name: str) -> dict:
        """
        Retrieve the IAM access control policy for the specified organization.
        Args:
            organization_name (str): The organization name for which the policy is being requested.

        Returns:
            dict: API response from GCP.

        """
        request = self.cloud_resource_manager_service.organizations().getIamPolicy(resource=organization_name)
        response = request.execute()

        return response

    def gcp_iam_organization_iam_test_permission_request(self, organization_name: str, permissions: list) -> dict:
        """
        Returns permissions that a caller has on the specified organization.
        Args:
            organization_name (str): The organization name for which the permissions is being tested.
            permissions (list): Permissions names to validate.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "permissions": permissions
        }

        request = self.cloud_resource_manager_service.organizations().testIamPermissions(resource=organization_name,
                                                                                         body=body)
        response = request.execute()

        return response

    def gcp_iam_organization_iam_policy_set_request(self, organization_name: str, policy: list) -> dict:
        """
        Sets the IAM access control policy for the specified organization.
        Args:
            organization_name (str): The name of the organization for which the policy is being specified.
            policy (list): Policy objects to set.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "policy": {
                "bindings": policy
            }
        }

        request = self.cloud_resource_manager_service.organizations().setIamPolicy(resource=organization_name,
                                                                                   body=body)
        response = request.execute()

        return response

    def gcp_iam_group_create_request(self, parent: str, display_name: str, group_email_address: str,
                                     description: str = None):
        """
        Create a new group.
        Args:
            parent (str): The parent resource of the groups to create.
            display_name (str): The display name of the group.
            group_email_address (str): The group unique email address.
            description (str): The description of the group.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(initialGroupConfig='WITH_INITIAL_OWNER')

        body = remove_empty_elements({
            "parent": parent,
            "description": description,
            "displayName": display_name,
            "labels": {
                "cloudidentity.googleapis.com/groups.discussion_forum": ""
            },
            "groupKey": {
                "id": group_email_address
            }
        })

        request = self.cloud_identity_service.groups().create(**params, body=body)
        response = request.execute()

        return response

    def gcp_iam_group_list_request(self, parent: str, limit: int = None, page_token: str = None) -> dict:
        """
        List groups under the specified parent.
        Args:
            parent (str): The parent resource of the groups to retrieve
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=parent, pageSize=limit, pageToken=page_token)

        request = self.cloud_identity_service.groups().list(**params)
        response = request.execute()

        return response

    def gcp_iam_group_get_request(self, group_name: str) -> dict:
        """
        Retrieve a group information.
        Args:
            group_name (str): The name of the group to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.cloud_identity_service.groups().get(name=group_name)
        response = request.execute()

        return response

    def gcp_iam_group_delete_request(self, group_name: str):
        """
         Delete group.
         Args:
             group_name (str): The name of the group to delete.

         Returns:
             dict: API response from GCP.

         """
        request = self.cloud_identity_service.groups().delete(name=group_name)
        response = request.execute()

        return response

    def gcp_iam_group_membership_create_request(self, group_name: str, member_email: str, roles: list) -> dict:
        """
        Create a group membership
        Args:
            group_name (str): The name of the group which will contain the membership.
            member_email (str): The email address of the user to add to the group.
            roles (list): Roles to apply to the membership.

         Returns:
             dict: API response from GCP.

        """
        body_roles = [{"name": role} for role in roles]
        body = {
            "preferredMemberKey": {
                "id": member_email
            },
            "roles": body_roles
        }

        request = self.cloud_identity_service.groups().memberships().create(parent=group_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_group_membership_list_request(self, group_name: str, limit: int = None, page_token: str = None) -> dict:
        """
        List group memberships.
        Args:
            group_name (str): The name of the group which contains the membership.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=group_name, pageSize=limit, pageToken=page_token)

        request = self.cloud_identity_service.groups().memberships().list(**params)
        response = request.execute()

        return response

    def gcp_iam_group_membership_get_request(self, membership_name: str):
        """
        Retrieve group membership information.
        Args:
            membership_name (str): The name of the group membership to retrieve.

        Returns:
            dict: API response from GCP.

        """

        request = self.cloud_identity_service.groups().memberships().get(name=membership_name)
        response = request.execute()

        return response

    def gcp_iam_group_membership_role_add_request(self, membership_name: str, roles: list) -> dict:
        """
        Add group membership role.
        Args:
            membership_name (str): The name of the group membership to update.
            roles (list): Membership roles to add to the membership.

        Returns:
            dict: API response from GCP.

        """
        body_roles = [{"name": role} for role in roles]
        body = {
            "addRoles": body_roles
        }

        request = self.cloud_identity_service.groups().memberships().modifyMembershipRoles(name=membership_name,
                                                                                           body=body)
        response = request.execute()

        return response

    def gcp_iam_group_membership_role_remove_request(self, membership_name: str, roles: list) -> dict:
        """
        Remove group membership role.
        Args:
            membership_name (str): The name of the group membership to update.
            roles (list): Membership roles to remove from the membership.

        Returns:
            dict: API response from GCP.

        """
        body = {
            "removeRoles": roles
        }

        request = self.cloud_identity_service.groups().memberships().modifyMembershipRoles(name=membership_name,
                                                                                           body=body)
        response = request.execute()

        return response

    def gcp_iam_group_membership_delete_request(self, membership_name: str) -> dict:
        """
        Delete group membership.
        Args:
            membership_name (str): The resource name of the membership to delete.

        Returns:
            dict: API response from GCP.

        """

        request = self.cloud_identity_service.groups().memberships().delete(name=membership_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_create_request(self, project_name: str, service_account_id: str,
                                               display_name: str = None, description: str = None):
        """
        Create a service account in project.
        Args:
            project_name (str): The name of the project associated with the service account.
            service_account_id (str): The account ID that is used to generate the service account email address,
                                   and a stable unique ID.
            display_name (str): Human readable name for the created service account.
            description (str): Human readable description for created the service account.

        Returns:
            dict: API response from GCP.

        """
        body = remove_empty_elements({"accountId": service_account_id,
                                      "serviceAccount":
                                          {
                                              "displayName": display_name,
                                              "description": description
                                          }
                                      })

        request = self.iam_service.projects().serviceAccounts().create(name=project_name, body=body)

        response = request.execute()

        return response

    def gcp_iam_service_account_update_request(self, service_account_name: str, fields_to_update: str,
                                               display_name: str = None, description: str = None) -> dict:
        """
        Update service account.
        Args:
            service_account_name (str): The name of the service account to update.
            fields_to_update (str): Comma-separated names of the fields to update.
            display_name (str): Human readable name for the updated service account.
            description (str): Human readable description for updated the service account.

        Returns:
            dict: API response from GCP.

        """
        body = remove_empty_elements({
            "serviceAccount":
                {"displayName": display_name,
                 "description": description
                 },
            "updateMask": fields_to_update
        })

        request = self.iam_service.projects().serviceAccounts().patch(name=service_account_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_service_account_list_request(self, project_name: str, limit: int = None,
                                             page_token: str = None) -> dict:
        """
        List service accounts in project.
        Args:
            project_name (str): The name of the project associated with the service accounts to retrieve.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(name=project_name, pageSize=limit, pageToken=page_token)

        request = self.iam_service.projects().serviceAccounts().list(**params)
        response = request.execute()

        return response

    def gcp_iam_service_account_get_request(self, service_account_name: str) -> dict:
        """
        Retrieve project service account information.
        Args:
            service_account_name (str): The name of service account to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().get(name=service_account_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_enable_request(self, service_account_name: str) -> dict:
        """
        Enable project service account.
        Args:
            service_account_name (str): The name of service account to enable.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().enable(name=service_account_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_disable_request(self, service_account_name: str) -> dict:
        """
        Disable project service account.
        Args:
            service_account_name (str): The name of service account to disable.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().disable(name=service_account_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_delete_request(self, service_account_name: str) -> dict:
        """
        Delete service account key.
        Args:
            service_account_name (str): The name of service account to delete.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().delete(name=service_account_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_key_create_request(self, service_account_name: str, key_algorithm: str) -> dict:
        """
        Create a service account key.
        Args:
            service_account_name (str): The name of the service account associated with the key.
            key_algorithm (str): The RSA key algorithm.

        Returns:
            dict: API response from GCP.

        """
        body = assign_params(keyAlgorithm=key_algorithm)

        request = self.iam_service.projects().serviceAccounts().keys().create(name=service_account_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_service_account_key_list_request(self, service_account_name: str) -> dict:
        """
        List service accounts keys.
        Args:
            service_account_name (str): The name of the service account associated with the keys.

        Returns:
            dict: API response from GCP.

        """

        request = self.iam_service.projects().serviceAccounts().keys().list(name=service_account_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_key_get_request(self, key_name: str) -> dict:
        """
        Retrieve service account key information.
        Args:
            key_name (str): The resource name of the service account key to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().keys().get(name=key_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_key_enable_request(self, key_name: str) -> dict:
        """
        Enable service account key.
        Args:
            key_name (str): The resource name of the service account key to enable.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().keys().enable(name=key_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_key_disable_request(self, key_name: str) -> dict:
        """
        Disable service account key.
        Args:
            key_name (str): The resource name of the service account key to disable.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().keys().disable(name=key_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_key_delete_request(self, key_name: str) -> dict:
        """
        Delete service account key.
        Args:
            key_name (str): The resource name of the service account key to delete.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().serviceAccounts().keys().delete(name=key_name)
        response = request.execute()

        return response

    def gcp_iam_service_account_generate_access_token_request(self, service_account_email: str, lifetime: str) -> dict:
        """
        Create a short-lived access token
        Args:
            service_account_email (str): E-Mail of the Service Account for wich the token should be generated

            lifetime (str): Lifetime of the token in seconds. Like 3600

        Returns:
            dict: API response from GCP.

        """
        resource_name = f"projects/-/serviceAccounts/{service_account_email}"
        body = {
            "scope": [
                "https://www.googleapis.com/auth/cloud-platform"
            ],
            "lifetime": f"{arg_to_number(lifetime, required=True)}s"
        }

        request = self.iam_credentials.projects().serviceAccounts().generateAccessToken(name=resource_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_organization_role_create_request(self, organization_name: str, role_id: str, stage: str = None,
                                                 description: str = None, title: str = None,
                                                 permissions: list = None) -> dict:
        """
        Create a custom organization role.
        Args:
            organization_name (str): The name of the organization which contains the custom role.
            role_id (str): The unique ID of the role to create.
            stage (str): The current launch stage of the role.
            description (str): The description of the role to create.
            title (str): The title of the role to create.
            permissions (list): Permissions the role grants when bound in an IAM policy.

        Returns:
            dict: API response from GCP.

        """
        body = remove_empty_elements({
            "roleId": role_id,
            "role": {
                "title": title,
                "description": description,
                "includedPermissions": permissions,
                "stage": stage
            }
        })

        request = self.iam_service.organizations().roles().create(parent=organization_name, body=body)
        response = request.execute()

        return response

    def gcp_iam_organization_role_update_request(self, role_name: str, description: str = None,
                                                 title: str = None, permissions: list = None,
                                                 stage: str = None, fields_to_update: str = None) -> dict:
        """
        Update a custom organization role.
        Args:
            role_name (str): The name of the role to update.
            description (str): The updated description of the role.
            title (str): The updated title of the role.
            permissions (list): Permissions the role grants when bound in an IAM policy.
            stage (str): The current launch stage of the role.
            fields_to_update (str): Comma-separated names of the fields to update.

        Returns:
            dict: API response from GCP.

        """
        body = remove_empty_elements({
            "title": title,
            "description": description,
            "includedPermissions": permissions,
            "stage": stage
        })

        request = self.iam_service.organizations().roles().patch(name=role_name, body=body, updateMask=fields_to_update)
        response = request.execute()

        return response

    def gcp_iam_organization_role_list_request(self, parent: str, include_permissions: bool,
                                               limit: int, page_token: str = None, show_deleted: bool = False) -> dict:
        """
        List organization custom roles.
        Args:
            parent (str): The name of the organization which contains the custom roles.
            include_permissions (bool): Indicates whether to include permissions in the response.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.
            show_deleted (bool): Indicate that roles that have been deleted should also be retrieved.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=parent, pageSize=limit, pageToken=page_token, showDeleted=show_deleted,
                               view="FULL" if include_permissions else "BASIC")

        request = self.iam_service.organizations().roles().list(**params)
        response = request.execute()

        return response

    def gcp_iam_predefined_role_list_request(self, include_permissions: bool,
                                             limit: int, page_token: str = None, show_deleted: bool = False) -> dict:
        """
        List GCP IAM predefined roles.
        Args:
            include_permissions (bool): Indicates whether to include permissions in the response.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.
            show_deleted (bool): Indicate that roles that have been deleted should also be retrieved.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(pageSize=limit, pageToken=page_token, showDeleted=show_deleted,
                               view="FULL" if include_permissions else "BASIC")

        request = self.iam_service.roles().list(**params)
        response = request.execute()

        return response

    def gcp_iam_organization_role_get_request(self, role_name: str) -> dict:
        """
        Retrieve organization role information.
        Args:
            role_name (str): The resource name of the role to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.organizations().roles().get(name=role_name)
        response = request.execute()

        return response

    def gcp_iam_organization_role_delete_request(self, role_name: str) -> dict:
        """
        Delete a custom organization role.
        Args:
            (str): The name of the role to delete.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.organizations().roles().delete(name=role_name)
        response = request.execute()

        return response

    def gcp_iam_project_role_create_request(self, project_id: str, role_id: str, stage: str = None,
                                            description: str = None, title: str = None,
                                            permissions: list = None) -> dict:
        """
        Create a custom project role.
        Args:
            project_id (str): The ID of the project which contains the custom role.
            role_id (str): The unique ID of the role to create.
            stage (str): The current launch stage of the role.
            description (str): The description of the role to create.
            title (str): The title of the role to create.
            permissions (list): Permissions the role grants when bound in an IAM policy.

        Returns:
            dict: API response from GCP.

        """
        body = remove_empty_elements({
            "roleId": role_id,
            "role": {
                "title": title,
                "description": description,
                "includedPermissions": permissions,
                "stage": stage
            }
        })

        request = self.iam_service.projects().roles().create(parent=f'projects/{project_id}', body=body)
        response = request.execute()

        return response

    def gcp_iam_project_role_update_request(self, role_name: str, description: str = None,
                                            title: str = None, permissions: list = None,
                                            stage: str = None, fields_to_update: str = None) -> dict:
        """
        Update a custom project role.
        Args:
            role_name (str): The name of the role to update.
            description (str): The updated description of the role.
            title (str): The updated title of the role.
            permissions (list): Permissions the role grants when bound in an IAM policy.
            stage (str): The current launch stage of the role.
            fields_to_update (str): Comma-separated names of the fields to update.

        Returns:
            dict: API response from GCP.

        """
        body = remove_empty_elements({
            "title": title,
            "description": description,
            "includedPermissions": permissions,
            "stage": stage
        })

        request = self.iam_service.projects().roles().patch(name=role_name, body=body, updateMask=fields_to_update)
        response = request.execute()

        return response

    def gcp_iam_project_role_list_request(self, parent: str, include_permissions: bool,
                                          limit: int, page_token: str = None, show_deleted: bool = False) -> dict:
        """
        List project custom roles.
        Args:
            parent (str): The ID of the project which contains the custom roles.
            include_permissions (bool): Indicates whether to include permissions in the response.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.
            show_deleted (bool): Indicate that roles that have been deleted should also be retrieved.

        Returns:
            dict: API response from GCP.

        """
        params = assign_params(parent=f'projects/{parent}', pageSize=limit, pageToken=page_token,
                               showDeleted=show_deleted,
                               view="FULL" if include_permissions else "BASIC")

        request = self.iam_service.projects().roles().list(**params)
        response = request.execute()

        return response

    def gcp_iam_project_role_get_request(self, role_name: str) -> dict:
        """
        Retrieve project role information.
        Args:
            role_name (str): The resource name of the role to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().roles().get(name=role_name)
        response = request.execute()

        return response

    def gcp_iam_predefined_role_get_request(self, role_name: str) -> dict:
        """
        Retrieve GCP IAM predefined role information.
        Args:
            role_name (str): The resource name of the role to retrieve.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.roles().get(name=role_name)
        response = request.execute()

        return response

    def gcp_iam_project_role_delete_request(self, role_name: str) -> dict:
        """
        Delete a custom project role.
        Args:
            (str): The name of the role to delete.

        Returns:
            dict: API response from GCP.

        """
        request = self.iam_service.projects().roles().delete(name=role_name)
        response = request.execute()

        return response

    def gcp_iam_testable_permission_list_request(self, full_resource_name: str, limit: int = None,
                                                 page_token: str = None) -> dict:
        """
        Lists permissions that can be tested on a resource.
        Args:
            full_resource_name (str): The full resource name to query from the list of testable permissions.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.

        Returns:
            dict: API response from GCP.

        """
        body = assign_params(fullResourceName=full_resource_name, pageSize=limit, pageToken=page_token)

        request = self.iam_service.permissions().queryTestablePermissions(body=body)
        response = request.execute()

        return response

    def gcp_iam_grantable_role_list_request(self, full_resource_name: str, limit: int = None,
                                            page_token: str = None) -> dict:
        """
        Lists roles that can be granted on a Google Cloud resource.
        Args:
            full_resource_name (str): The full resource name to query from the list of grantable roles.
            limit (int): The number of results to retrieve.
            page_token (str): Pagination token returned from a previous request.

        Returns:
            dict: API response from GCP.

        """
        body = assign_params(fullResourceName=full_resource_name, pageSize=limit, pageToken=page_token)

        request = self.iam_service.roles().queryGrantableRoles(body=body)
        response = request.execute()

        return response


def get_pagination_readable_message(header: str, limit: int, page: int) -> str:
    """
    Generate pagination commands readable message.
    Args:
        header (str): Message header
        limit (int): Number of elements to retrieve.
        page (int): Page number.

    Returns:
        str: Readable message.

    """
    readable_message = f'{header}\n Current page size: {limit}\n Showing page {page} out of others that may exist.'

    return readable_message


def get_next_page_token(limit: int, page: int, client_request: Callable, args: dict) -> str:
    """
    Get next request page token for request pagination.
    Args:
        limit (int): Number of elements to retrieve.
        page (int): Page number.
        client_request (Callable): Client request function.
        args (dict): Request function arguments.

    Returns:
        str: Continuation token.

    """
    offset = limit * (page - 1)
    response = client_request(limit=offset, **args)
    return response.get('nextPageToken')


def validate_pagination_arguments(limit: int, page: int) -> None:
    """
    Validate pagination arguments values.
    Args:
        limit (int): Number of elements to retrieve.
        page (int): Page number.

    """
    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 0.')


def update_time_format(data: Union[dict, list], keys: list) -> list:
    """
    Update dictionary time values to appropriate XSOAR system time format.
    Args:
        data (dict/list): Information to update.
        keys (list): Keys to update.

    Returns:
        list: Updated information.

    """
    if not isinstance(data, list):
        data = [data]

    for item in data:
        for key in keys:
            if key in item:
                item[key] = arg_to_datetime(item[key]).isoformat()  # type: ignore[union-attr]

    return data


def generate_iam_policy_command_output(response: dict, resource_name: str = None,
                                       readable_header: str = None, limit: int = None,
                                       page: int = None, roles: list = None) -> CommandResults:
    """
    Generate command output for iam-policy commands.
    Args:
        response (dict): API response from GCP.
        resource_name (str): The resource for which the policy is being specified.
        readable_header (str): Readable message header for XSOAR war room.
        limit (int): Number of elements to retrieve.
        page (int): Page number.
        role (list): List of potential GCP IAM roles

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if not readable_header:
        readable_header = f'{resource_name} IAM policy information:'
    outputs = copy.deepcopy(response)
    outputs['name'] = resource_name
    bindings = outputs.get("bindings", [])
    if roles and bindings:
        bindings_roles_only = []
        for index, entry in enumerate(bindings):
            if entry.get("role") in roles:
                bindings_roles_only.append(bindings[index])

        bindings = bindings_roles_only

    if limit and page:
        start = (page - 1) * limit
        end = start + limit
        outputs["bindings"] = bindings[start:end]
        if len(bindings) < limit:
            resource_type = readable_header.split(' ')[0]
            readable_header = f'{resource_type} {resource_name} IAM Policy List:\n Current page size: {len(bindings)}'

    readable_output = tableToMarkdown(
        readable_header,
        outputs.get('bindings'),
        headers=['role', 'members'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Policy',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def generate_group_membership_readable_output(outputs: list, readable_header: str) -> str:
    """
    Generate command readable output for group membership commands.
    Args:
        outputs (dict): API response from GCP.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        tableToMarkdown: XSOAR war room output.

    """
    readable_information = []
    for membership in outputs:
        readable_information.append({
            "name": membership.get('name'),
            "roles": [role.get('name') for role in membership.get('roles')],
            "preferredMemberKey": dict_safe_get(membership, ['preferredMemberKey', 'id'])
        })

    headers = ['name', 'roles']

    if len(readable_information) > 0 and readable_information[0].get("preferredMemberKey"):
        headers.append("preferredMemberKey")

    readable_output = tableToMarkdown(readable_header,
                                      readable_information,
                                      headers=headers,
                                      headerTransform=pascalToSpace
                                      )

    return readable_output


def generate_group_membership_command_output(response: dict, output_key: str = None,
                                             readable_header: str = 'Membership information:') -> CommandResults:
    """
    Generate command output for group membership commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if output_key:
        outputs = copy.deepcopy(response.get(output_key, []))
    else:
        outputs = copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    outputs = update_time_format(outputs, ['createTime', 'updateTime'])

    readable_output = generate_group_membership_readable_output(outputs, readable_header)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Membership',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def remove_members_from_policy(role: str, iam_policy: list, members: list, command_name: str) -> list:
    """
    Remove members from policy role.
    Args:
        role (str): The name of policy role.
        iam_policy (list): IAM policies.
        members (list): Members to remove from policy.
        command_name (str): An alternative  command that will be displayed to the user in case of an error.

    Returns:
        list: Updated policies.

    """
    role_found = False
    for policy in iam_policy:
        if policy.get('role') == role:
            for member in members:
                try:
                    policy['members'].remove(member)
                except ValueError:
                    raise Exception(f'The member {member} is not part of the project IAM policies members.'
                                    f'If you wish to add a new policy, consider using the {command_name} command.')
            role_found = True
            break

    if not role_found:
        raise Exception('The provided role is not part of the project IAM policies.'
                        f'If you wish to add a new policy, consider using the {command_name} command.')

    return iam_policy


def add_members_to_policy(role: str, iam_policy: list, members: list, command_name: str) -> list:
    """
    Append members to policy role members.
    Args:
        role (str): The name of policy role.
        iam_policy (list): IAM policies.
        members (list): Members to append to policy.
        command_name (str): An alternative  command that will be displayed to the user in case of an error.

    Returns:
        list: Updated policies.

    """
    role_found = False
    for policy in iam_policy:
        if policy.get('role') == role:
            policy['members'].extend(members)
            role_found = True
            break

    if not role_found:
        raise Exception('The provided role is not part of the project IAM policies.'
                        f'If you wish to add a new policy, consider using the {command_name} command.')

    return iam_policy


def generate_service_account_command_output(response: dict, output_key: str = None,
                                            readable_header: str = 'Service account information:') -> CommandResults:
    """
    Generate command output for service account commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if output_key:
        outputs = copy.deepcopy(response.get(output_key, []))
    else:
        outputs = copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    for output in outputs:
        output["disabled"] = output.get("disabled", False)

    readable_output = tableToMarkdown(readable_header,
                                      outputs,
                                      headers=["name", "displayName", "description", "projectId"],
                                      headerTransform=pascalToSpace
                                      )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.ServiceAccount',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def generate_project_command_output(response: dict, output_key: str = None,
                                    readable_header: str = 'Project information:') -> CommandResults:
    """
    Generate command output for project commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if output_key:
        outputs = copy.deepcopy(response.get(output_key, []))
    else:
        outputs = copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    outputs = update_time_format(outputs, ['createTime', 'updateTime', 'deleteTime'])

    readable_output = tableToMarkdown(
        readable_header,
        outputs,
        headers=['name', 'parent', 'projectId', 'displayName', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Project',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_projects_get_command(client: Client, args: Dict[str, Any]) -> list:
    """
    List projects under the specified parent, or retrieve specific project information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """

    project_name = argToList(args.get('project_name'))

    command_results_list: List[CommandResults] = []

    if project_name:  # Retrieve specific project information.

        for project in project_name:
            readable_message = f'Project {project} information:'
            try:
                response = client.gcp_iam_project_get_request(project)

                command_results = generate_project_command_output(response=response, readable_header=readable_message)

                command_results_list.append(command_results)

            except Exception as exception:
                error = CommandResults(
                    readable_output=f'An error occurred while retrieving {project}.\n {exception}'
                )
                command_results_list.append(error)

    else:  # List project resources.
        parent = args.get('parent')
        show_deleted = argToBoolean(args.get('show_deleted', False))

        if not parent:
            raise Exception("One of the arguments: 'parent' or 'project_name' must be provided.")
        limit = arg_to_number(args.get('limit')) or 50
        page = arg_to_number(args.get('page')) or 1
        max_limit = 100

        validate_pagination_arguments(limit, page)
        if limit > max_limit:
            raise Exception("The limit argument is out of range. It must be between 1 and 100.")

        readable_message = get_pagination_readable_message(header='Projects List:', limit=limit, page=page)

        if page > 1:
            response = get_pagination_request_result(limit, page, max_limit,
                                                     client.gcp_iam_project_list_request,
                                                     parent=parent,
                                                     show_deleted=show_deleted)

        else:
            response = client.gcp_iam_project_list_request(parent=parent, limit=limit, show_deleted=show_deleted)

        command_results = generate_project_command_output(response=response, output_key='projects',
                                                          readable_header=readable_message)

        command_results_list.append(command_results)

    return command_results_list


def gcp_iam_project_iam_policy_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the IAM access control policy for the specified project.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    roles = argToList(args.get('roles', []))
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header=f'Project {project_name} IAM Policy List:',
                                                       limit=limit, page=page)

    response = client.gcp_iam_project_iam_policy_get_request(project_name)
    return generate_iam_policy_command_output(response, project_name, readable_header=readable_message,
                                              limit=limit, page=page, roles=roles)


def generate_test_permission_command_output(response: dict, readable_header: str) -> CommandResults:
    """
    Generate command output for test permission commands.
    Args:
        response (dict): API response from GCP.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    outputs = [{"name": permission} for permission in copy.deepcopy(response.get('permissions', []))]

    readable_output = tableToMarkdown(
        readable_header,
        outputs,
        headers=['name'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Permission',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_project_iam_test_permission_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve permissions that a caller has on the specified project.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    permissions = argToList(args.get('permissions'))

    response = client.gcp_iam_project_iam_test_permission_request(project_name, permissions)

    return generate_test_permission_command_output(response, readable_header=f'Project {project_name} permissions:')


def gcp_iam_project_iam_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add members to project policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    role = args.get('role', '')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_project_iam_policy_get_request(project_name).get("bindings", [])
    updated_policies = add_members_to_policy(role=role, iam_policy=iam_policy, members=members,
                                             command_name='gcp-iam-project-iam-policy-create')

    client.gcp_iam_project_iam_policy_set_request(project_name, updated_policies)

    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_project_iam_member_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove members from project policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    role = args.get('role', '')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_project_iam_policy_get_request(project_name).get("bindings", [])
    updated_policies = remove_members_from_policy(role=role, iam_policy=iam_policy, members=members,
                                                  command_name='gcp-iam-project-iam-policy-create')

    client.gcp_iam_project_iam_policy_set_request(project_name, updated_policies)

    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_project_iam_policy_set_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Sets the IAM access control policy for the specified project.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    policy = args.get('policy')
    if isinstance(policy, str):
        policy = policy.replace("\'", "\"")
        if policy and not policy.startswith('['):
            policy = '[' + policy + ']'

    policy = safe_load_json(policy)

    response = client.gcp_iam_project_iam_policy_set_request(project_name, policy)
    return generate_iam_policy_command_output(response, project_name,
                                              readable_header=f'{project_name} IAM policy updated successfully.')


def gcp_iam_project_iam_policy_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add new project IAM policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    role = args.get('role')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_project_iam_policy_get_request(project_name).get("bindings", [])
    policy = {
        "role": role,
        "members": members
    }

    iam_policy.append(policy)

    client.gcp_iam_project_iam_policy_set_request(project_name, iam_policy)
    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def generate_folder_command_output(response: dict, output_key: str = None,
                                   readable_header: str = 'Folder information:') -> CommandResults:
    """
    Generate command output for folder commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if output_key:
        outputs = copy.deepcopy(response.get(output_key, []))
    else:
        outputs = copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    outputs = update_time_format(outputs, ['createTime', 'updateTime', 'deleteTime'])

    readable_output = tableToMarkdown(
        readable_header,
        outputs,
        headers=['name', 'parent', 'displayName', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Folder',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_folders_get_command(client: Client, args: Dict[str, Any]) -> list:
    """
    List folders under the specified parent, or retrieve specific folder information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = argToList(args.get('folder_name'))

    command_results_list: List[CommandResults] = []

    if folder_name:  # Retrieve specific folder information

        for folder in folder_name:
            readable_message = f'Folder {folder} information:'
            try:
                response = client.gcp_iam_folder_get_request(folder)

                command_results = generate_folder_command_output(response=response, readable_header=readable_message)

                command_results_list.append(command_results)

            except Exception as exception:
                error = CommandResults(
                    readable_output=f'An error occurred while retrieving {folder}.\n {exception}'
                )
                command_results_list.append(error)

    else:  # List folder under the specified parent.

        parent = args.get('parent')
        show_deleted = argToBoolean(args.get('show_deleted', False))

        if not parent:
            raise Exception("One of the arguments: 'parent' or 'folder_name' must be provided.")

        limit = arg_to_number(args.get('limit')) or 50
        page = arg_to_number(args.get('page')) or 1
        max_limit = 100

        validate_pagination_arguments(limit, page)
        if limit > max_limit:
            raise Exception("The limit argument is out of range. It must be between 1 and 100.")

        readable_message = get_pagination_readable_message(header='Folders List:', limit=limit, page=page)

        if page > 1:
            response = get_pagination_request_result(limit, page, max_limit,
                                                     client.gcp_iam_folder_list_request,
                                                     parent=parent,
                                                     show_deleted=show_deleted)

        else:
            response = client.gcp_iam_folder_list_request(parent=parent, limit=limit, show_deleted=show_deleted)

        command_results = generate_folder_command_output(response=response, output_key='folders',
                                                         readable_header=readable_message)

        command_results_list.append(command_results)

    return command_results_list


def gcp_iam_folder_iam_policy_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the IAM access control policy for the specified folder.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header=f'Folder {folder_name} IAM Policy List:',
                                                       limit=limit, page=page)

    response = client.gcp_iam_folder_iam_policy_get_request(folder_name)
    return generate_iam_policy_command_output(response, folder_name, readable_header=readable_message,
                                              limit=limit, page=page)


def gcp_iam_folder_iam_test_permission_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve permissions that a caller has on the specified folder.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    permissions = argToList(args.get('permissions'))

    response = client.gcp_iam_folder_iam_test_permission_request(folder_name, permissions)
    return generate_test_permission_command_output(response, readable_header=f'Folder {folder_name} permissions:')


def gcp_iam_folder_iam_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add members to folder policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    role = args.get('role', '')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_folder_iam_policy_get_request(folder_name).get("bindings", [])
    updated_policies = add_members_to_policy(role=role, iam_policy=iam_policy, members=members,
                                             command_name='gcp-iam-folder-iam-policy-create')

    client.gcp_iam_folder_iam_policy_set_request(folder_name, updated_policies)

    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_folder_iam_member_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove members from folder policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    role = args.get('role', '')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_folder_iam_policy_get_request(folder_name).get("bindings", [])
    updated_policies = remove_members_from_policy(role=role, iam_policy=iam_policy, members=members,
                                                  command_name='gcp-iam-folder-iam-policy-create')

    client.gcp_iam_folder_iam_policy_set_request(folder_name, updated_policies)

    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_folder_iam_policy_set_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Sets the IAM access control policy for the specified folder.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    policy = args.get('policy')
    if isinstance(policy, str):
        policy = policy.replace("\'", "\"")
        if policy and not policy.startswith('['):
            policy = '[' + policy + ']'

    policy = safe_load_json(policy)

    response = client.gcp_iam_folder_iam_policy_set_request(folder_name, policy)
    return generate_iam_policy_command_output(response, folder_name,
                                              readable_header=f'{folder_name} IAM policy updated successfully.')


def gcp_iam_folder_iam_policy_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add new folder IAM policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    role = args.get('role')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_folder_iam_policy_get_request(folder_name).get("bindings", [])
    policy = {
        "role": role,
        "members": members
    }

    iam_policy.append(policy)

    client.gcp_iam_folder_iam_policy_set_request(folder_name, iam_policy)
    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def generate_organization_command_output(response: dict, output_key: str = None,
                                         readable_header: str = 'Organization information:') -> CommandResults:
    """
    Generate command output for group commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if output_key:
        outputs = copy.deepcopy(response.get(output_key, []))
    else:
        outputs = copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    outputs = update_time_format(outputs, ['createTime', 'updateTime'])

    readable_output = tableToMarkdown(
        readable_header,
        outputs,
        headers=['name', 'displayName', 'directoryCustomerId', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Organization',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_organizations_get_command(client: Client, args: Dict[str, Any]) -> list:
    """
    List organization resources that are visible to the caller, or retrieve organization information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = argToList(args.get('organization_name'))
    command_results_list: List[CommandResults] = []

    if organization_name:  # Retrieve specific organization information

        for organization in organization_name:
            readable_message = f'Organizations {organization} information:'
            try:
                response = client.gcp_iam_organization_get_request(organization)
                command_results = generate_organization_command_output(response=response,
                                                                       readable_header=readable_message)

                command_results_list.append(command_results)

            except Exception as exception:
                error = CommandResults(
                    readable_output=f'An error occurred while retrieving {organization}.\n {exception}'
                )
                command_results_list.append(error)

    else:  # List organization resources that are visible to the caller.
        limit = arg_to_number(args.get('limit')) or 50
        page = arg_to_number(args.get('page')) or 1
        max_limit = 50

        validate_pagination_arguments(limit, page)
        if limit > max_limit:
            raise Exception("The limit argument is out of range. It must be between 1 and 100.")

        readable_message = get_pagination_readable_message(header='Organizations List:', limit=limit, page=page)

        if page > 1:
            response = get_pagination_request_result(limit, page, max_limit,
                                                     client.gcp_iam_organization_list_request)

        else:
            response = client.gcp_iam_organization_list_request(limit=limit)

        command_results = generate_organization_command_output(response=response, output_key='organizations',
                                                               readable_header=readable_message)

        command_results_list.append(command_results)

    return command_results_list


def gcp_iam_organization_iam_policy_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the IAM access control policy for the specified organization.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header=f'Organization {organization_name} IAM Policy List:',
                                                       limit=limit, page=page)

    response = client.gcp_iam_organization_iam_policy_get_request(organization_name)

    return generate_iam_policy_command_output(response, organization_name, readable_header=readable_message,
                                              limit=limit, page=page)


def gcp_iam_organization_iam_test_permission_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve permissions that a caller has on the specified organization.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    permissions = argToList(args.get('permissions'))

    response = client.gcp_iam_organization_iam_test_permission_request(organization_name, permissions)

    return generate_test_permission_command_output(response,
                                                   readable_header=f'Organization {organization_name} permissions:')


def gcp_iam_organization_iam_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add members to organization policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    role = args.get('role', '')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_organization_iam_policy_get_request(organization_name).get("bindings", [])
    updated_policies = add_members_to_policy(role=role, iam_policy=iam_policy, members=members,
                                             command_name='gcp-iam-organization-iam-policy-create')

    client.gcp_iam_organization_iam_policy_set_request(organization_name, updated_policies)

    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_organization_iam_member_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove members from organization policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    role = args.get('role', '')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_organization_iam_policy_get_request(organization_name).get("bindings", [])
    updated_policies = remove_members_from_policy(role=role, iam_policy=iam_policy, members=members,
                                                  command_name='gcp-iam-organization-iam-policy-create')

    client.gcp_iam_organization_iam_policy_set_request(organization_name, updated_policies)

    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_organization_iam_policy_set_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Sets the IAM access control policy for the specified organization.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    policy = args.get('policy')
    if isinstance(policy, str):
        policy = policy.replace("\'", "\"")
        if policy and not policy.startswith('['):
            policy = '[' + policy + ']'

    policy = safe_load_json(policy)

    response = client.gcp_iam_organization_iam_policy_set_request(organization_name, policy)
    return generate_iam_policy_command_output(response, organization_name,
                                              readable_header=f'{organization_name} IAM policy updated successfully.')


def gcp_iam_organization_iam_policy_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add new organization IAM policy.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    role = args.get('role')
    members = argToList(args.get('members'))

    iam_policy = client.gcp_iam_organization_iam_policy_get_request(organization_name).get("bindings", [])
    policy = {
        "role": role,
        "members": members
    }

    iam_policy.append(policy)

    client.gcp_iam_organization_iam_policy_set_request(organization_name, iam_policy)
    command_results = CommandResults(
        readable_output=f'Role {role} updated successfully.'
    )
    return command_results


def gcp_iam_group_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a new group.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    parent = args.get('parent', '')
    description = args.get('description', '')
    display_name = args.get('display_name', '')
    group_email_address = args.get('group_email_address', '')

    response = client.gcp_iam_group_create_request(parent, display_name, group_email_address, description)

    outputs = copy.deepcopy(response.get('response'))
    created_group_name = outputs.get("name")
    outputs = update_time_format(outputs, ['createTime', 'updateTime'])

    readable_output = tableToMarkdown(
        f'Successfully Created Group "{created_group_name}"',
        outputs,
        headers=['name', 'groupKey', 'parent', 'displayName', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Group',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_group_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List groups under the specified parent.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    parent = args.get('parent', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1

    page_token = None
    readable_message = get_pagination_readable_message(header='Groups List:', limit=limit, page=page)

    validate_pagination_arguments(limit, page)
    if limit > 500:
        raise Exception("The limit argument is out of range. It must be between 1 and 500.")

    if page > 1:
        page_token = get_next_page_token(limit, page, client.gcp_iam_group_list_request, args={"parent": parent})

        if not page_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='GCPIAM.Group',
                outputs=[],
                raw_response=[]
            )

    response = client.gcp_iam_group_list_request(parent, limit, page_token)

    readable_output = tableToMarkdown(
        readable_message,
        response.get('groups'),
        headers=['name', 'groupKey', 'displayName'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Group',
        outputs_key_field='name',
        outputs=response.get('groups'),
        raw_response=response
    )

    return command_results


def gcp_iam_group_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve group information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    group_name = args.get('group_name', '')

    response = client.gcp_iam_group_get_request(group_name)
    outputs = copy.deepcopy(response)
    outputs = update_time_format(outputs, ['createTime', 'updateTime'])

    readable_output = tableToMarkdown(
        'Group information:',
        outputs,
        headers=['name', 'groupKey', 'parent', 'displayName', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Group',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_group_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete group.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    group_name = args.get('group_name', '')

    result = client.gcp_iam_group_delete_request(group_name)

    if not result.get('done'):
        raise Exception('Operation failed.')
    readable_output = f'Group {group_name} was successfully deleted.'
    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def gcp_iam_group_membership_create_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Create a group membership.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    groups_name = argToList(args.get('groups_name'))
    member_email = args.get('member_email', '')
    role = argToList(args.get('role'))

    command_results_list: List[CommandResults] = []
    for name in groups_name:
        try:
            response = client.gcp_iam_group_membership_create_request(name, member_email, role)
            command_results_list.append(generate_group_membership_command_output(response, 'response'))

        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while creating membership in group {name}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_group_membership_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List group memberships.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    group_name = args.get('group_name', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    page_token = None
    readable_message = get_pagination_readable_message(header='Membership List:', limit=limit, page=page)

    validate_pagination_arguments(limit, page)
    if limit > 500:
        raise Exception("The limit argument is out of range. It must be between 1 and 500.")

    if page > 1:
        page_token = get_next_page_token(limit, page, client.gcp_iam_group_membership_list_request,
                                         args={"group_name": group_name})

        if not page_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='GCPIAM.Membership',
                outputs=[],
                raw_response=[]
            )

    response = client.gcp_iam_group_membership_list_request(group_name, limit, page_token)

    return generate_group_membership_command_output(response, "memberships", readable_message)


def gcp_iam_group_membership_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve group membership information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    membership_name = args.get('membership_name', '')

    response = client.gcp_iam_group_membership_get_request(membership_name)
    return generate_group_membership_command_output(response)


def gcp_iam_group_membership_role_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add group membership role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    membership_name = args.get('membership_name', '')
    role = argToList(args.get('role'))

    client.gcp_iam_group_membership_role_add_request(membership_name, role)
    command_results = CommandResults(
        readable_output=f'Membership {membership_name} updated successfully.'
    )
    return command_results


def gcp_iam_group_membership_role_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove group membership role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    membership_name = args.get('membership_name', '')
    role = argToList(args.get('role'))

    client.gcp_iam_group_membership_role_remove_request(membership_name, role)
    command_results = CommandResults(
        readable_output=f'Membership {membership_name} updated successfully.'
    )
    return command_results


def gcp_iam_group_membership_delete_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Delete group membership.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    membership_names = argToList(args.get('membership_names'))
    command_results_list: List[CommandResults] = []

    for membership in membership_names:
        try:
            client.gcp_iam_group_membership_delete_request(membership)
            command_results = CommandResults(
                readable_output=f'Membership {membership} deleted successfully.'
            )
            command_results_list.append(command_results)
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while deleting the membership {membership}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_service_account_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a service account in project.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    service_account_id = args.get('service_account_id', '')
    display_name = args.get('display_name', '')
    description = args.get('description', '')

    if not 6 <= len(service_account_id) <= 30:
        raise Exception('Service account ID length has to be between 6-30 characters.')

    response = client.gcp_iam_service_account_create_request(
        project_name, service_account_id, display_name, description)

    return generate_service_account_command_output(response)


def gcp_iam_service_account_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update service account.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_name = args.get('service_account_name', '')
    display_name = args.get('display_name', '')
    description = args.get('description', '')
    fields_to_update = args.get('fields_to_update', '')

    client.gcp_iam_service_account_update_request(service_account_name, fields_to_update, display_name, description)
    command_results = CommandResults(
        readable_output=f'Service account {service_account_name} updated successfully.'
    )
    return command_results


def get_pagination_request_result(limit: int, page: int, max_page_size: int, client_request: Callable,
                                  **kwargs) -> dict:
    """
    Perform API request for pagination utility.
    Args:
        limit (int): The number of results to retrieve.
        page (int): The page number of the results to retrieve.
        max_page_size (int): API maximum page size limitation.
        client_request (int): API Client function.

    Returns:
        dict: API response from GCP.

    """
    offset = (page - 1) * limit
    page_token = None

    steps = max_page_size if offset > max_page_size else offset

    for _i in range(0, offset, steps):
        response = client_request(limit=steps, page_token=page_token, **kwargs)

        page_token = response.get('nextPageToken')

        if not page_token:
            return {}

    return client_request(limit=limit, page_token=page_token, **kwargs)


def gcp_iam_service_accounts_get_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, list]:
    """
    List service accounts in project, or retrieve specific project service account information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_name = argToList(args.get('service_account_name'))

    if service_account_name:  # Retrieve specific service accounts information,
        command_results_list: List[CommandResults] = []
        for account in service_account_name:
            try:
                response = client.gcp_iam_service_account_get_request(account)
                command_results_list.append(generate_service_account_command_output(response))
            except Exception as exception:
                error = CommandResults(
                    readable_output=f'An error occurred while retrieving {account}.\n {exception}'
                )
                command_results_list.append(error)

        return command_results_list

    else:  # List service accounts in project.
        project_name = args.get('project_name')

        if not project_name:
            raise Exception("One of the arguments: 'service_account_name' or 'project_name' must be provided.")

        limit = arg_to_number(args.get('limit')) or 50
        page = arg_to_number(args.get('page')) or 1
        max_limit = 100

        validate_pagination_arguments(limit, page)
        if limit > max_limit:
            raise Exception("The limit argument is out of range. It must be between 1 and 100.")

        readable_message = get_pagination_readable_message(header='Service Account List:', limit=limit, page=page)

        if page > 1:
            response = get_pagination_request_result(limit, page, max_limit,
                                                     client.gcp_iam_service_account_list_request,
                                                     project_name=project_name)

        else:
            response = client.gcp_iam_service_account_list_request(project_name=project_name, limit=limit)

        return generate_service_account_command_output(response, output_key="accounts",
                                                       readable_header=readable_message)


def gcp_iam_service_account_enable_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Enable project service account.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_name = argToList(args.get('service_account_name'))
    command_results_list: List[CommandResults] = []

    for account in service_account_name:
        try:
            client.gcp_iam_service_account_enable_request(account)
            command_results_list.append(CommandResults(
                readable_output=f'Service account {account} updated successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to enable {account}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_service_account_disable_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Disable project service account.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_name = argToList(args.get('service_account_name'))
    command_results_list: List[CommandResults] = []

    for account in service_account_name:
        try:
            client.gcp_iam_service_account_disable_request(account)
            command_results_list.append(CommandResults(
                readable_output=f'Service account {account} updated successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to disable {account}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_service_account_delete_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Delete service account key.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_name = argToList(args.get('service_account_name'))
    command_results_list: List[CommandResults] = []

    for account in service_account_name:
        try:
            client.gcp_iam_service_account_delete_request(account)
            command_results_list.append(CommandResults(
                readable_output=f'Service account {account} deleted successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to delete {account}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def generate_service_account_key_command_output(response: dict, output_key: str = None,
                                                readable_header: str = 'Service account key information:') -> CommandResults:
    """
    Generate command output for service account key commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if output_key:
        outputs = copy.deepcopy(response.get(output_key, []))
    else:
        outputs = copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    for output in outputs:
        output["disabled"] = output.get("disabled", False)

    outputs = update_time_format(outputs, ['validAfterTime', 'validBeforeTime'])

    readable_output = tableToMarkdown(readable_header,
                                      outputs,
                                      headers=["name", "validAfterTime", "validBeforeTime", "disabled", "keyType"],
                                      headerTransform=pascalToSpace
                                      )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.ServiceAccountKey',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a service account key.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_name = args.get('service_account_name', '')
    key_algorithm = args.get('key_algorithm', '')

    response = client.gcp_iam_service_account_key_create_request(service_account_name, key_algorithm)
    return generate_service_account_key_command_output(response)


def gcp_iam_service_account_keys_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List service accounts keys, or retrieve service account key information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    key_name = args.get('key_name')

    if key_name:  # Retrieve specific service account key information.
        response = client.gcp_iam_service_account_key_get_request(key_name)
        return generate_service_account_key_command_output(response)

    else:

        service_account_name = args.get('service_account_name')
        if not service_account_name:
            raise Exception("One of the arguments: 'service_account_name' or 'key_name' must be provided.")

        limit = arg_to_number(args.get('limit')) or 50
        page = arg_to_number(args.get('page')) or 1
        validate_pagination_arguments(limit, page)
        response = client.gcp_iam_service_account_key_list_request(service_account_name)

        readable_message = get_pagination_readable_message(header='Service Account Keys List:', limit=limit, page=page)
        start = (page - 1) * limit
        end = start + limit

        outputs = []

        keys = response.get('keys', [])
        if keys and len(keys) >= start:
            min_index = min(len(keys), end)
            for key in keys[start:min_index]:
                outputs.append(dict(key))

        for output in outputs:
            output["disabled"] = output.get("disabled", False)

        outputs = update_time_format(outputs, ['validAfterTime', 'validBeforeTime'])

        readable_output = tableToMarkdown(readable_message,
                                          outputs,
                                          headers=["name", "validAfterTime", "validBeforeTime", "disabled", "keyType"],
                                          headerTransform=pascalToSpace
                                          )

        command_results = CommandResults(
            readable_output=readable_output,
            outputs_prefix='GCPIAM.ServiceAccountKey',
            outputs_key_field='name',
            outputs=outputs,
            raw_response=response
        )

        return command_results


def gcp_iam_service_account_key_enable_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Enable service account key.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    key_name = argToList(args.get('key_name'))
    command_results_list: List[CommandResults] = []

    for key in key_name:
        try:
            client.gcp_iam_service_account_key_enable_request(key)
            command_results_list.append(CommandResults(
                readable_output=f'Service account key {key} updated successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to enable {key}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_service_account_key_disable_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Disable service account key.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    key_name = argToList(args.get('key_name'))
    command_results_list: List[CommandResults] = []

    for key in key_name:
        try:
            client.gcp_iam_service_account_key_disable_request(key)
            command_results_list.append(CommandResults(
                readable_output=f'Service account key {key} updated successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to disable {key}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_service_account_generate_access_token_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a serivce account short-lived access token

    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    service_account_email = args['service_account_email']
    lifetime = args['lifetime']

    response = client.gcp_iam_service_account_generate_access_token_request(service_account_email, lifetime)

    readable_output = tableToMarkdown(f"Access token for {service_account_email}:",
                                      response,
                                      headers=["accessToken", "expireTime"],
                                      headerTransform=pascalToSpace,
                                      )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.ServiceAccountAccessToken',
        outputs_key_field='name',
        outputs=response,
        raw_response=response
    )


def gcp_iam_service_account_key_delete_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Delete service account key.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    key_name = argToList(args.get('key_name'))
    command_results_list: List[CommandResults] = []

    for key in key_name:
        try:
            client.gcp_iam_service_account_key_delete_request(key)
            command_results_list.append(CommandResults(
                readable_output=f'Service account key {key} deleted successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to delete {key}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def generate_role_command_output(response: dict, output_key: str = None,
                                 readable_header: str = 'Role information:',
                                 outputs: list = None) -> CommandResults:
    """
    Generate command output for role commands.
    Args:
        response (dict): API response from GCP.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.
        outputs (list): Command output. If not provided, the command will set this argument.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if not outputs and not isinstance(outputs, list):
        if output_key:
            outputs = copy.deepcopy(response.get(output_key, []))
        else:
            outputs = [copy.deepcopy(response)]

    if not isinstance(outputs, list):
        outputs = [outputs]

    for role in outputs:
        role["stage"] = role.get('stage', 'ALPHA')
        role["includedPermissions"] = role.get('includedPermissions', [])
        role["deleted"] = role.get('deleted', False)

    readable_output = tableToMarkdown(readable_header,
                                      outputs,
                                      headers=["name", "includedPermissions", "title", "description"],
                                      headerTransform=pascalToSpace
                                      )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Role',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def create_custom_role(client_request_method: Callable, resource_identifier_key: str, args: Dict[str, Any]):
    """
    Create a custom role.
    Args:
        client_request_method (Callable): The GCP Client method which create the required resource (organization/project) role.
        resource_identifier_key (str): The ID of the required resource which contains the custom role.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    resource_identifier = args.get(resource_identifier_key)
    role_id = args.get('role_id')
    description = args.get('description')
    title = args.get('title')
    stage = args.get('stage')
    permissions = argToList(args.get('permissions'))

    response = client_request_method(resource_identifier, role_id, stage, description, title, permissions)

    role_name = response.get('name')

    return generate_role_command_output(response, readable_header=f'Role {role_name} information:')


def update_custom_role(client_request_method: Callable, args: Dict[str, Any]):
    """
    Update custom role.
    Args:
        client_request_method (Callable): The GCP Client method which update the required resource (organization/project) role.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = args.get('role_name')
    description = args.get('description')
    title = args.get('title')
    permissions = argToList(args.get('permissions'))
    stage = args.get('stage')
    fields_to_update = args.get('fields_to_update')

    client_request_method(role_name, description, title, permissions, stage, fields_to_update)
    command_results = CommandResults(
        readable_output=f'Role {role_name} updated successfully.'
    )
    return command_results


def add_custom_role_permissions(client_request_get_method: Callable, client_request_update_method: Callable,
                                args: Dict[str, Any]):
    """
    Add permissions to custom role.
    Args:
        client_request_get_method (Callable): The GCP Client method which retrieved
                                              the required resource (organization/project) role.
        client_request_update_method (Callable): The GCP Client method which update
                                                 the required resource (organization/project) role.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = args.get('role_name')
    permissions = argToList(args.get('permissions'))

    role_permissions = client_request_get_method(role_name).get('includedPermissions', [])

    for permission in permissions:
        role_permissions.append(permission)

    client_request_update_method(role_name, permissions=role_permissions, fields_to_update="includedPermissions")
    command_results = CommandResults(
        readable_output=f'Role {role_name} updated successfully.'
    )
    return command_results


def remove_custom_role_permissions(client_request_get_method: Callable, client_request_update_method: Callable,
                                   args: Dict[str, Any]):
    """
    Remove permissions from custom project role.
    Args:
        client_request_get_method (Callable): The GCP Client method which retrieved
                                              the required resource (organization/project) role.
        client_request_update_method (Callable): The GCP Client method which update
                                                 the required resource (organization/project) role.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = args.get('role_name')
    permissions = argToList(args.get('permissions'))

    role_permissions = client_request_get_method(role_name).get('includedPermissions', [])

    for permission in permissions:
        try:
            role_permissions.remove(permission)
        except ValueError:
            raise Exception(f'The permission {permission} is not part of the custom resource permissions.'
                            f'If you wish to add a new permission, '
                            f'consider using gcp-iam-organization-role-permission-add '
                            f'or gcp-iam-project-role-permission-add command.')

    client_request_update_method(role_name, permissions=role_permissions, fields_to_update="includedPermissions")
    command_results = CommandResults(
        readable_output=f'Role {role_name} updated successfully.'
    )
    return command_results


def list_filtered_role(client_request_method: Callable, command_arguments: dict, limit: int, page: int,
                       max_limit: int, title_filter: str = None, permission_filter: list = None) -> tuple:
    """
    List and filter roles.
    Args:
        client_request_method (Callable): The GCP Client method which list the required resource
                                          (predefined/organization/project) role.
        command_arguments (dict): Client method arguments.
        limit (int): The number of results to retrieve.
        page (int): The page number of the results to retrieve.
        max_limit (int): GCP API max limit.
        title_filter (str): Used to filter the retrieved roles by the rule title.
        permission_filter (list): Used to filter the retrieved roles by their permissions.

    Returns:
        response , outputs.

    """
    if permission_filter:
        command_arguments["include_permissions"] = True

    response = client_request_method(limit=max_limit, **command_arguments)

    max_result_offset = page * limit
    offset = (page - 1) * limit
    outputs = []
    response_roles = response.get("roles", [])

    roles_remain = True

    while roles_remain and response_roles:
        for role in response_roles:
            if (title_filter and title_filter.lower() in role.get("title", "").lower()) or (permission_filter and all(
                    item in role.get("includedPermissions", []) for item in permission_filter)):
                outputs.append(role)

            if len(outputs) >= max_result_offset:
                roles_remain = False
                break

        if roles_remain:
            if response.get('nextPageToken'):
                response = client_request_method(limit=max_limit, page_token=response.get('nextPageToken'),
                                                 **command_arguments)
                response_roles = response.get("roles", [])
            else:
                roles_remain = False

    return response, outputs[offset: max_result_offset]


def list_roles(client_request_method: Callable, args: Dict[str, Any],
               readable_header: str, resource_identifier_key: str = None):
    """
    List custom roles.
    Args:
        client_request_method (Callable): The GCP Client method which list the required resource
                                          (predefined/organization/project) role.
        resource_identifier_key (str): The ID of the required resource which contains the custom role.
        args (dict): Command arguments from XSOAR.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if resource_identifier_key:
        resource_identifier = args.get(resource_identifier_key)
    include_permissions = argToBoolean(args.get('include_permissions', True))
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    show_deleted = argToBoolean(args.get('show_deleted', False))

    title_filter = args.get('title_filter')
    permission_filter = argToList(args.get('permission_filter'))

    max_limit = 1000

    validate_pagination_arguments(limit, page)
    if limit > max_limit:
        raise Exception("The limit argument is out of range. It must be between 1 and 1000.")

    readable_message = get_pagination_readable_message(header=readable_header, limit=limit, page=page)

    if resource_identifier_key:
        command_arguments = {'parent': resource_identifier, 'include_permissions': include_permissions,
                             'show_deleted': show_deleted}
    else:
        command_arguments = {'include_permissions': include_permissions, 'show_deleted': show_deleted}

    if title_filter or permission_filter:
        response, outputs = list_filtered_role(client_request_method, command_arguments, limit, page, max_limit,
                                               title_filter, permission_filter)

        return generate_role_command_output(response, readable_header=readable_message, outputs=outputs)

    if page > 1:
        response = get_pagination_request_result(limit, page, max_limit,
                                                 client_request_method,
                                                 **command_arguments)
    else:
        response = client_request_method(limit=limit, **command_arguments)

    return generate_role_command_output(response, output_key="roles", readable_header=readable_message)


def gcp_iam_organization_role_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a custom organization role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return create_custom_role(client_request_method=client.gcp_iam_organization_role_create_request,
                              resource_identifier_key='organization_name', args=args)


def gcp_iam_organization_role_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update an organization custom role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return update_custom_role(client_request_method=client.gcp_iam_organization_role_update_request, args=args)


def gcp_iam_organization_role_permission_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add permissions to custom organization role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return add_custom_role_permissions(client_request_get_method=client.gcp_iam_organization_role_get_request,
                                       client_request_update_method=client.gcp_iam_organization_role_update_request,
                                       args=args)


def gcp_iam_organization_role_permission_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove permissions from custom organization role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return remove_custom_role_permissions(client_request_get_method=client.gcp_iam_organization_role_get_request,
                                          client_request_update_method=client.gcp_iam_organization_role_update_request,
                                          args=args)


def gcp_iam_organization_role_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List organization custom roles.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return list_roles(client_request_method=client.gcp_iam_organization_role_list_request,
                      resource_identifier_key='organization_name', args=args,
                      readable_header='Custom Organization Roles list:')


def gcp_iam_organization_role_get_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Retrieve organization role information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = argToList(args.get('role_name'))
    command_results_list: List[CommandResults] = []

    for role in role_name:
        try:
            response = client.gcp_iam_organization_role_get_request(role)
            retrieved_role_name = response.get('name')
            command_results_list.append(
                generate_role_command_output(response, readable_header=f'Role {retrieved_role_name} information:'))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while retrieving {role}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_organization_role_delete_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Delete a custom organization role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = argToList(args.get('role_name'))
    command_results_list: List[CommandResults] = []

    for role in role_name:
        try:
            client.gcp_iam_organization_role_delete_request(role)
            command_results_list.append(CommandResults(
                readable_output=f'Role {role} deleted successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to delete {role}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_project_role_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Create a custom project role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return create_custom_role(client_request_method=client.gcp_iam_project_role_create_request,
                              resource_identifier_key='project_id', args=args)


def gcp_iam_project_role_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Update an project custom role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return update_custom_role(client_request_method=client.gcp_iam_project_role_update_request, args=args)


def gcp_iam_project_role_permission_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add permissions to custom project role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    return add_custom_role_permissions(client_request_get_method=client.gcp_iam_project_role_get_request,
                                       client_request_update_method=client.gcp_iam_project_role_update_request,
                                       args=args)


def gcp_iam_project_role_permission_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove permissions from custom project role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return remove_custom_role_permissions(client_request_get_method=client.gcp_iam_project_role_get_request,
                                          client_request_update_method=client.gcp_iam_project_role_update_request,
                                          args=args)


def gcp_iam_project_role_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List custom project roles.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return list_roles(client_request_method=client.gcp_iam_project_role_list_request,
                      resource_identifier_key='project_id', args=args,
                      readable_header='Custom Project Roles list:')


def gcp_iam_project_role_get_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Retrieve project role information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = argToList(args.get('role_name'))
    command_results_list: List[CommandResults] = []

    for role in role_name:
        try:
            response = client.gcp_iam_project_role_get_request(role)
            retrieved_role_name = response.get('name')
            command_results_list.append(
                generate_role_command_output(response, readable_header=f'Role {retrieved_role_name} information:'))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while retrieving {role}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_project_role_delete_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Delete custom project role.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = argToList(args.get('role_name'))
    command_results_list: List[CommandResults] = []

    for role in role_name:
        try:
            client.gcp_iam_project_role_delete_request(role)
            command_results_list.append(CommandResults(
                readable_output=f'Role {role} deleted successfully.'
            ))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while trying to delete {role}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_predefined_role_get_command(client: Client, args: Dict[str, Any]) -> list:
    """
    Retrieve GCP IAM predefined role information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    role_name = argToList(args.get('role_name'))
    command_results_list: List[CommandResults] = []

    for role in role_name:
        try:
            response = client.gcp_iam_predefined_role_get_request(role)
            retrieved_role_name = response.get('name')
            command_results_list.append(
                generate_role_command_output(response, readable_header=f'Role {retrieved_role_name} information:'))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while retrieving {role}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def gcp_iam_predefined_role_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Lists every predefined Role that IAM supports.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    return list_roles(client_request_method=client.gcp_iam_predefined_role_list_request, args=args,
                      readable_header='GCP IAM Predefined Roles list:')


def gcp_iam_testable_permission_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Lists permissions that can be tested on a resource.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    resource_name = args.get('resource_name')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    full_resource_name = f'//cloudresourcemanager.googleapis.com/{resource_name}'
    page_token = None
    readable_message = get_pagination_readable_message(header=f'{resource_name} testable permissions list:',
                                                       limit=limit, page=page)
    max_limit = 1000

    validate_pagination_arguments(limit, page)
    if limit > max_limit:
        raise Exception("The limit argument is out of range. It must be between 1 and 1000.")

    if page > 1:
        page_token = get_next_page_token(limit, page, client.gcp_iam_testable_permission_list_request,
                                         args={"full_resource_name": full_resource_name})

        if not page_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='GCPIAM.Permission',
                outputs=[],
                raw_response=[]
            )

    response = client.gcp_iam_testable_permission_list_request(full_resource_name, limit, page_token)

    readable_output = tableToMarkdown(
        readable_message,
        response.get("permissions"),
        headers=['name', 'stage'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Permission',
        outputs_key_field='name',
        outputs=response.get("permissions"),
        raw_response=response
    )

    return command_results


def gcp_iam_grantable_role_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Lists roles that can be granted on a Google Cloud resource.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    resource_name = args.get('resource_name')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    full_resource_name = f'//cloudresourcemanager.googleapis.com/{resource_name}'
    page_token = None
    readable_message = get_pagination_readable_message(header=f'{resource_name} grantable roles list:',
                                                       limit=limit, page=page)

    max_limit = 1000

    validate_pagination_arguments(limit, page)
    if limit > max_limit:
        raise Exception("The limit argument is out of range. It must be between 1 and 1000.")

    if page > 1:
        page_token = get_next_page_token(limit, page, client.gcp_iam_grantable_role_list_request,
                                         args={"full_resource_name": full_resource_name})

        if not page_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='GCPIAM.Roles',
                outputs=[],
                raw_response=[]
            )

    response = client.gcp_iam_grantable_role_list_request(full_resource_name, limit, page_token)

    readable_output = tableToMarkdown(
        readable_message,
        response.get("roles"),
        headers=['name', 'title', 'description'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.Roles',
        outputs_key_field='name',
        outputs=response.get("roles"),
        raw_response=response
    )

    return command_results


def gcp_iam_project_iam_policy_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove policy from project IAM policies.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name', '')
    role = argToList(args.get('role'))

    iam_policy = client.gcp_iam_project_iam_policy_get_request(project_name).get("bindings", [])

    updated_policies = [policy for policy in iam_policy if policy.get('role') not in role]

    client.gcp_iam_project_iam_policy_set_request(project_name, updated_policies)
    command_results = CommandResults(
        readable_output=f'Project {project_name} IAM policies updated successfully.'
    )
    return command_results


def gcp_iam_organization_iam_policy_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove policy from organization IAM policies.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    organization_name = args.get('organization_name', '')
    role = argToList(args.get('role'))

    iam_policy = client.gcp_iam_organization_iam_policy_get_request(organization_name).get("bindings", [])

    updated_policies = [policy for policy in iam_policy if policy.get('role') not in role]

    client.gcp_iam_organization_iam_policy_set_request(organization_name, updated_policies)
    command_results = CommandResults(
        readable_output=f'Organization {organization_name} IAM policies updated successfully.'
    )
    return command_results


def gcp_iam_folder_iam_policy_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove policy from folder IAM policies.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    folder_name = args.get('folder_name', '')
    role = argToList(args.get('role'))

    iam_policy = client.gcp_iam_folder_iam_policy_get_request(folder_name).get("bindings", [])

    updated_policies = [policy for policy in iam_policy if policy.get('role') not in role]

    client.gcp_iam_folder_iam_policy_set_request(folder_name, updated_policies)
    command_results = CommandResults(
        readable_output=f'Folder {folder_name} IAM policies updated successfully.'
    )
    return command_results


def gcp_iam_tagbindings_list_command(client: Client, args: Dict[str, Any]) -> Union[CommandResults, str]:
    """
    List tag bindings (key value pair) applied to a project/folder/organization object.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """

    parent = args.get('parent')

    if not parent:
        raise Exception("Argument 'parent' must be provided.")
    max_limit = 100

    res_binding = client.gcp_iam_tagbindings_list_request(parent=parent, limit=max_limit)
    if not res_binding:
        return "No tag bindingds found"
    if not res_binding.get('tagBindings', [{}])[0].get('tagValue'):
        return "No tag bindingds found"
    val_list = []
    for value in res_binding.get('tagBindings', {}):
        res_value = client.gcp_iam_tagvalues_get_request(name=value.get('tagValue'))
        res_key = client.gcp_iam_tagkeys_get_request(name=res_value.get('parent', ''))
        kv = {'key': res_key['shortName'], 'value': res_value['shortName']}
        val_list.append(kv)

    readable_output = tableToMarkdown(
        "Keys and Values",
        val_list,
        headers=['key', 'value'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCPIAM.TagBindings',
        outputs_key_field='key',
        outputs=val_list,
        raw_response=val_list
    )

    return command_results


def test_module(service_account_key: str, proxy: bool, verify_certificate: bool) -> None:
    try:
        client: Client = Client(client_secret=service_account_key, proxy=proxy, verify_certificate=verify_certificate)
        client.gcp_iam_predefined_role_list_request(include_permissions=False, limit=1)
    except Exception as e:
        demisto.error(f'Error when running test-module {e}')
        return return_results('Authorization Error: make sure API Service Account Key is valid.')

    return_results('ok')
    return None


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    service_account_key = params['credentials']['password']
    verify_certificate: bool = not argToBoolean(params.get('insecure', False))
    proxy: bool = params.get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:

        if command == 'test-module':
            return test_module(service_account_key, proxy=proxy, verify_certificate=verify_certificate)

        client: Client = Client(client_secret=service_account_key, proxy=proxy, verify_certificate=verify_certificate)

        commands = {
            'gcp-iam-projects-get': gcp_iam_projects_get_command,
            'gcp-iam-project-iam-policy-get': gcp_iam_project_iam_policy_get_command,
            'gcp-iam-project-iam-permission-test': gcp_iam_project_iam_test_permission_command,
            'gcp-iam-project-iam-member-add': gcp_iam_project_iam_member_add_command,
            'gcp-iam-project-iam-member-remove': gcp_iam_project_iam_member_remove_command,
            'gcp-iam-project-iam-policy-set': gcp_iam_project_iam_policy_set_command,
            'gcp-iam-project-iam-policy-create': gcp_iam_project_iam_policy_add_command,
            'gcp-iam-project-iam-policy-remove': gcp_iam_project_iam_policy_remove_command,
            'gcp-iam-folders-get': gcp_iam_folders_get_command,
            'gcp-iam-folder-iam-policy-get': gcp_iam_folder_iam_policy_get_command,
            'gcp-iam-folder-iam-permission-test': gcp_iam_folder_iam_test_permission_command,
            'gcp-iam-folder-iam-member-add': gcp_iam_folder_iam_member_add_command,
            'gcp-iam-folder-iam-member-remove': gcp_iam_folder_iam_member_remove_command,
            'gcp-iam-folder-iam-policy-set': gcp_iam_folder_iam_policy_set_command,
            'gcp-iam-folder-iam-policy-create': gcp_iam_folder_iam_policy_add_command,
            'gcp-iam-folder-iam-policy-remove': gcp_iam_folder_iam_policy_remove_command,
            'gcp-iam-organizations-get': gcp_iam_organizations_get_command,
            'gcp-iam-organization-iam-policy-get': gcp_iam_organization_iam_policy_get_command,
            'gcp-iam-organization-iam-permission-test': gcp_iam_organization_iam_test_permission_command,
            'gcp-iam-organization-iam-member-add': gcp_iam_organization_iam_member_add_command,
            'gcp-iam-organization-iam-member-remove': gcp_iam_organization_iam_member_remove_command,
            'gcp-iam-organization-iam-policy-set': gcp_iam_organization_iam_policy_set_command,
            'gcp-iam-organization-iam-policy-create': gcp_iam_organization_iam_policy_add_command,
            'gcp-iam-organization-iam-policy-remove': gcp_iam_organization_iam_policy_remove_command,
            'gcp-iam-group-create': gcp_iam_group_create_command,
            'gcp-iam-group-list': gcp_iam_group_list_command,
            'gcp-iam-group-get': gcp_iam_group_get_command,
            'gcp-iam-group-delete': gcp_iam_group_delete_command,
            'gcp-iam-group-membership-create': gcp_iam_group_membership_create_command,
            'gcp-iam-group-membership-list': gcp_iam_group_membership_list_command,
            'gcp-iam-group-membership-get': gcp_iam_group_membership_get_command,
            'gcp-iam-group-membership-role-add': gcp_iam_group_membership_role_add_command,
            'gcp-iam-group-membership-role-remove': gcp_iam_group_membership_role_remove_command,
            'gcp-iam-group-membership-delete': gcp_iam_group_membership_delete_command,
            'gcp-iam-service-account-create': gcp_iam_service_account_create_command,
            'gcp-iam-service-account-update': gcp_iam_service_account_update_command,
            'gcp-iam-service-accounts-get': gcp_iam_service_accounts_get_command,
            'gcp-iam-service-account-enable': gcp_iam_service_account_enable_command,
            'gcp-iam-service-account-disable': gcp_iam_service_account_disable_command,
            'gcp-iam-service-account-delete': gcp_iam_service_account_delete_command,
            'gcp-iam-service-account-key-create': gcp_iam_service_account_key_create_command,
            'gcp-iam-service-account-keys-get': gcp_iam_service_account_keys_get_command,
            'gcp-iam-service-account-key-enable': gcp_iam_service_account_key_enable_command,
            'gcp-iam-service-account-key-disable': gcp_iam_service_account_key_disable_command,
            'gcp-iam-service-account-generate-access-token': gcp_iam_service_account_generate_access_token_command,
            'gcp-iam-service-account-key-delete': gcp_iam_service_account_key_delete_command,
            'gcp-iam-organization-role-create': gcp_iam_organization_role_create_command,
            'gcp-iam-organization-role-update': gcp_iam_organization_role_update_command,
            'gcp-iam-organization-role-permission-add': gcp_iam_organization_role_permission_add_command,
            'gcp-iam-organization-role-permission-remove': gcp_iam_organization_role_permission_remove_command,
            'gcp-iam-organization-role-list': gcp_iam_organization_role_list_command,
            'gcp-iam-organization-role-get': gcp_iam_organization_role_get_command,
            'gcp-iam-organization-role-delete': gcp_iam_organization_role_delete_command,
            'gcp-iam-project-role-create': gcp_iam_project_role_create_command,
            'gcp-iam-project-role-update': gcp_iam_project_role_update_command,
            'gcp-iam-project-role-permission-add': gcp_iam_project_role_permission_add_command,
            'gcp-iam-project-role-permission-remove': gcp_iam_project_role_permission_remove_command,
            'gcp-iam-project-role-list': gcp_iam_project_role_list_command,
            'gcp-iam-project-role-get': gcp_iam_project_role_get_command,
            'gcp-iam-project-role-delete': gcp_iam_project_role_delete_command,
            'gcp-iam-testable-permission-list': gcp_iam_testable_permission_list_command,
            'gcp-iam-grantable-role-list': gcp_iam_grantable_role_list_command,
            'gcp-iam-role-get': gcp_iam_predefined_role_get_command,
            'gcp-iam-role-list': gcp_iam_predefined_role_list_command,
            'gcp-iam-tagbindings-list': gcp_iam_tagbindings_list_command
        }

        if command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

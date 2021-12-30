# type: ignore
import copy
from typing import Callable

from googleapiclient import discovery
# from google.oauth2 import service_account
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# from googleapiclient import discovery
from oauth2client import service_account


class Client(BaseClient):
    def __init__(self, client_secret: str):
        client_secret = json.loads(client_secret)
        scopes = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloud-identity',
                  'https://www.googleapis.com/auth/iam', ]
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(client_secret, scopes=scopes)

        self.cloud_identity_service = discovery.build('cloudidentity', 'v1', credentials=credentials)
        self.cloud_resource_manager_service = discovery.build('cloudresourcemanager', 'v3', credentials=credentials)
        self.iam_service = discovery.build('iam', 'v1', credentials=credentials)

    def gcp_iam_project_list_request(self, parent: str, limit: int = None, page_token=None,
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

    def gcp_iam_folder_list_request(self, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_get_request(self, folder_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_iam_policy_get_request(self, folder_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_iam_test_permission_request(self, folder_name, permissions):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_iam_member_add_request(self, folder_name, role, members):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_iam_member_remove_request(self, folder_name, role, members):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_iam_policy_set_request(self, folder_name, policy):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_folder_iam_policy_add_request(self, folder_name, role, members):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_list_request(self, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_get_request(self, organization_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_iam_policy_get_request(self, organization_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_iam_test_permission_request(self, organization_name, permissions):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_iam_member_add_request(self, organization_name, role, members):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_iam_member_remove_request(self, organization_name, role, members):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_iam_policy_set_request(self, organization_name, policy):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_iam_policy_add_request(self, organization_name, role, members):
        # TODO

        response = self._http_request('GET')

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

    def gcp_iam_group_list_request(self, parent: str, limit: int, page_token: str = None) -> dict:
        """
        List groups under the specified parent.
        Args:
            parent (): The parent resource of the groups to retrieve
            limit (): The number of results to retrieve.
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

    def gcp_iam_group_membership_create_request(self, name, member_email, role):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_group_membership_list_request(self, name, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_group_membership_get_request(self, name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_group_membership_role_add_request(self, membership_name, role):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_group_membership_role_remove_request(self, membership_name, role):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_group_membership_delete_request(self, membership_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_create_request(self, project_name, service_account_id, display_name, description):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_update_request(self, service_account_name, display_name, description):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_list_request(self, project_name, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_get_request(self, service_account_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_enable_request(self, service_account_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_disable_request(self, service_account_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_key_create_request(self, service_account_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_key_list_request(self, service_account_name, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_key_get_request(self, key_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_key_enable_request(self, key_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_key_disable_request(self, key_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_key_delete_request(self, key_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_create_request(self, organization_name, role_id, description, title, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_update_request(self, role_name, description, title, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_permission_add_request(self, role_name, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_permission_remove_request(self, role_name, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_list_request(self, organization_name, included_permissions, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_get_request(self, role_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_organization_role_delete_request(self, role_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_create_request(self, project_name, role_id, description, title, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_update_request(self, role_name, description, title, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_permission_add_request(self, role_name, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_permission_remove_request(self, role_name, permission):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_list_request(self, project_name, included_permissions, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_get_request(self, role_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_project_role_delete_request(self, role_name):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_testable_permission_list_request(self, resource_name, limit, page):
        # TODO

        response = self._http_request('GET')

        return response

    def gcp_iam_service_account_delete_request(self, service_account_name):
        # TODO

        response = self._http_request('GET')

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
    readable_message = f'{header}\n Current page size: {limit}\n Showing page {page} out others that may exist.'

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
                item[key] = arg_to_datetime(item[key]).isoformat()

    return data


def generate_iam_policy_command_output(response: dict, resource_name: str = None,
                                       readable_header: str = None, limit: int = None,
                                       page: int = None) -> CommandResults:
    """
    Generate command output for iam-policy commands.
    Args:
        response (dict): API response from GCP.
        resource_name (str): The resource for which the policy is being specified.
        readable_header (str): Readable message header for XSOAR war room.
        limit (int): Number of elements to retrieve.
        page (int): Page number.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if not readable_header:
        readable_header = f'{resource_name} IAM policy information:'
    outputs = copy.deepcopy(response)
    outputs['name'] = resource_name

    if limit:
        start = (page - 1) * limit
        end = start + limit

        bindings = outputs.get("bindings", [])
        outputs["bindings"] = bindings[start:end]

    readable_output = tableToMarkdown(
        readable_header,
        outputs.get('bindings'),
        headers=['role', 'members'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCP.IAM.Policy',
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


def gcp_iam_projects_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List projects under the specified parent, or retrieve specific project information.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    project_name = args.get('project_name')

    if project_name:  # Retrieve specific project information.
        readable_message = f'Project {project_name} information:'
        response = client.gcp_iam_project_get_request(project_name)
        outputs = copy.deepcopy(response)

    else:  # List project resources.
        parent = args.get('parent')
        show_deleted = argToBoolean(args.get('show_deleted', False))

        if not parent:
            raise Exception('One of the arguments: ''parent'' or ''project_name'' must be provided.')
        limit = arg_to_number(args.get('limit') or '50')
        page = arg_to_number(args.get('page') or '1')
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

        outputs = copy.deepcopy(response.get('projects', []))

    outputs = update_time_format(outputs, ['createTime', 'updateTime', 'deleteTime'])

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headers=['name', 'parent', 'projectId', 'displayName', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCP.IAM.Project',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def gcp_iam_project_iam_policy_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the IAM access control policy for the specified project.
    Args:
        client (Client): GCP API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project_name = args.get('project_name')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header=f'Project {project_name} IAM Policy List:',
                                                       limit=limit, page=page)

    response = client.gcp_iam_project_iam_policy_get_request(project_name)
    return generate_iam_policy_command_output(response, project_name, readable_header=readable_message,
                                              limit=limit, page=page)


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
        outputs_prefix='GCP.IAM.Permission',
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
    project_name = args.get('project_name')
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
    project_name = args.get('project_name')
    role = args.get('role')
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
    project_name = args.get('project_name')
    role = args.get('role')
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
    project_name = args.get('project_name')
    policy = args.get('policy')
    if policy and not policy.startswith('['):
        policy = '[' + policy + ']'

    policy = json.loads(policy)

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
    project_name = args.get('project_name')
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


def gcp_iam_folder_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_folder_list_request(limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')

    response = client.gcp_iam_folder_get_request(folder_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_iam_policy_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')

    response = client.gcp_iam_folder_iam_policy_get_request(folder_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_iam_test_permission_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')
    permissions = args.get('permissions')

    response = client.gcp_iam_folder_iam_test_permission_request(folder_name, permissions)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_iam_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')
    role = args.get('role')
    members = args.get('members')

    response = client.gcp_iam_folder_iam_member_add_request(folder_name, role, members)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_iam_member_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')
    role = args.get('role')
    members = args.get('members')

    response = client.gcp_iam_folder_iam_member_remove_request(folder_name, role, members)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_iam_policy_set_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')
    policy = args.get('policy')

    response = client.gcp_iam_folder_iam_policy_set_request(folder_name, policy)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_folder_iam_policy_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    folder_name = args.get('folder_name')
    role = args.get('role')
    members = args.get('members')

    response = client.gcp_iam_folder_iam_policy_add_request(folder_name, role, members)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_organization_list_request(limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')

    response = client.gcp_iam_organization_get_request(organization_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_iam_policy_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')

    response = client.gcp_iam_organization_iam_policy_get_request(organization_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_iam_test_permission_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    permissions = args.get('permissions')

    response = client.gcp_iam_organization_iam_test_permission_request(organization_name, permissions)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_iam_member_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    role = args.get('role')
    members = args.get('members')

    response = client.gcp_iam_organization_iam_member_add_request(organization_name, role, members)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_iam_member_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    role = args.get('role')
    members = args.get('members')

    response = client.gcp_iam_organization_iam_member_remove_request(organization_name, role, members)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_iam_policy_set_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    policy = args.get('policy')

    response = client.gcp_iam_organization_iam_policy_set_request(organization_name, policy)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_iam_policy_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    role = args.get('role')
    members = args.get('members')

    response = client.gcp_iam_organization_iam_policy_add_request(organization_name, role, members)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
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
    parent = args.get('parent')
    description = args.get('description')
    display_name = args.get('display_name')
    group_email_address = args.get('group_email_address')

    response = client.gcp_iam_group_create_request(parent, display_name, group_email_address, description)

    outputs = copy.deepcopy(response.get('response'))
    outputs = update_time_format(outputs, ['createTime', 'updateTime'])

    readable_output = tableToMarkdown(
        'Group information:',
        outputs,
        headers=['name', 'groupKey', 'parent', 'displayName', 'createTime', 'updateTime'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GCP.IAM.Group',
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
    parent = args.get('parent')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    page_token = None
    readable_message = get_pagination_readable_message(header='Groups List:', limit=limit, page=page)

    validate_pagination_arguments(limit, page)
    if page > 1:
        page_token = get_next_page_token(limit, page, client.gcp_iam_group_list_request, args={"parent": parent})

        if not page_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='GCP.IAM.Group',
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
        outputs_prefix='GCP.IAM.Group',
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
    group_name = args.get('group_name')

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
        outputs_prefix='GCP.IAM.Group',
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
    group_name = args.get('group_name')

    client.gcp_iam_group_delete_request(group_name)
    readable_output = f'Group {group_name} was successfully deleted.'
    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def gcp_iam_group_membership_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    group_name = args.get('group_name')
    member_email = args.get('member_email')
    role = args.get('role')

    response = client.gcp_iam_group_membership_create_request(group_name, member_email, role)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_group_membership_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_group_membership_list_request(name, limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_group_membership_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')

    response = client.gcp_iam_group_membership_get_request(name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_group_membership_role_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    membership_name = args.get('membership_name')
    role = args.get('role')

    response = client.gcp_iam_group_membership_role_add_request(membership_name, role)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_group_membership_role_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    membership_name = args.get('membership_name')
    role = args.get('role')

    response = client.gcp_iam_group_membership_role_remove_request(membership_name, role)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_group_membership_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    membership_name = args.get('membership_name')

    response = client.gcp_iam_group_membership_delete_request(membership_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    project_name = args.get('project_name')
    service_account_id = args.get('service_account_id')
    display_name = args.get('display_name')
    description = args.get('description')

    response = client.gcp_iam_service_account_create_request(
        project_name, service_account_id, display_name, description)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')
    display_name = args.get('display_name')
    description = args.get('description')

    response = client.gcp_iam_service_account_update_request(service_account_name, display_name, description)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
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

    for i in range(0, offset, steps):
        response = client_request(limit=steps, page_token=page_token, **kwargs)

        page_token = response.get('nextPageToken')

        if not page_token:
            return {}

    return client_request(limit=limit, page_token=page_token, **kwargs)


def gcp_iam_service_account_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    project_name = args.get('project_name')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_service_account_list_request(project_name, limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')

    response = client.gcp_iam_service_account_get_request(service_account_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_enable_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')

    response = client.gcp_iam_service_account_enable_request(service_account_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_disable_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')

    response = client.gcp_iam_service_account_disable_request(service_account_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')

    response = client.gcp_iam_service_account_delete_request(service_account_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')

    response = client.gcp_iam_service_account_key_create_request(service_account_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_account_name = args.get('service_account_name')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_service_account_key_list_request(service_account_name, limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    key_name = args.get('key_name')

    response = client.gcp_iam_service_account_key_get_request(key_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_enable_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    key_name = args.get('key_name')

    response = client.gcp_iam_service_account_key_enable_request(key_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_disable_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    key_name = args.get('key_name')

    response = client.gcp_iam_service_account_key_disable_request(key_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_service_account_key_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    key_name = args.get('key_name')

    response = client.gcp_iam_service_account_key_delete_request(key_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    role_id = args.get('role_id')
    description = args.get('description')
    title = args.get('title')
    permission = args.get('permission')

    response = client.gcp_iam_organization_role_create_request(
        organization_name, role_id, description, title, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')
    description = args.get('description')
    title = args.get('title')
    permission = args.get('permission')

    response = client.gcp_iam_organization_role_update_request(role_name, description, title, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_permission_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')
    permission = args.get('permission')

    response = client.gcp_iam_organization_role_permission_add_request(role_name, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_permission_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')
    permission = args.get('permission')

    response = client.gcp_iam_organization_role_permission_remove_request(role_name, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    organization_name = args.get('organization_name')
    included_permissions = args.get('included_permissions')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_organization_role_list_request(organization_name, included_permissions, limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')

    response = client.gcp_iam_organization_role_get_request(role_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_organization_role_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')

    response = client.gcp_iam_organization_role_delete_request(role_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    project_name = args.get('project_name')
    role_id = args.get('role_id')
    description = args.get('description')
    title = args.get('title')
    permission = args.get('permission')

    response = client.gcp_iam_project_role_create_request(project_name, role_id, description, title, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')
    description = args.get('description')
    title = args.get('title')
    permission = args.get('permission')

    response = client.gcp_iam_project_role_update_request(role_name, description, title, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_permission_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')
    permission = args.get('permission')

    response = client.gcp_iam_project_role_permission_add_request(role_name, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_permission_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')
    permission = args.get('permission')

    response = client.gcp_iam_project_role_permission_remove_request(role_name, permission)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    project_name = args.get('project_name')
    included_permissions = args.get('included_permissions')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_project_role_list_request(project_name, included_permissions, limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')

    response = client.gcp_iam_project_role_get_request(role_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_project_role_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    role_name = args.get('role_name')

    response = client.gcp_iam_project_role_delete_request(role_name)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def gcp_iam_testable_permission_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    resource_name = args.get('resource_name')
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    response = client.gcp_iam_testable_permission_list_request(resource_name, limit, page)
    command_results = CommandResults(
        outputs_prefix='GCP.IAM',
        outputs_key_field='',
        outputs=response,
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
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')
    full_resource_name = f'//cloudresourcemanager.googleapis.com/{resource_name}'
    page_token = None
    readable_message = get_pagination_readable_message(header=f'{resource_name} grantable roles list:',
                                                       limit=limit, page=page)

    validate_pagination_arguments(limit, page)
    if page > 1:
        page_token = get_next_page_token(limit, page, client.gcp_iam_grantable_role_list_request,
                                         args={"full_resource_name": full_resource_name})

        if not page_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='GCP.IAM.Roles',
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
        outputs_prefix='GCP.IAM.Roles',
        outputs_key_field='name',
        outputs=response.get("roles"),
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    service_account_key = params['credentials']['password']
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        if command == 'test-module':
            return test_module(service_account_key)

        client: Client = Client(client_secret=service_account_key)
        commands = {
            'gcp-iam-projects-get': gcp_iam_projects_get_command,
            'gcp-iam-project-iam-policy-get': gcp_iam_project_iam_policy_get_command,
            'gcp-iam-project-iam-permission-test': gcp_iam_project_iam_test_permission_command,
            'gcp-iam-project-iam-member-add': gcp_iam_project_iam_member_add_command,
            'gcp-iam-project-iam-member-remove': gcp_iam_project_iam_member_remove_command,
            'gcp-iam-project-iam-policy-set': gcp_iam_project_iam_policy_set_command,
            'gcp-iam-project-iam-policy-create': gcp_iam_project_iam_policy_add_command,
            'gcp-iam-folders-get': gcp_iam_folder_get_command,
            'gcp-iam-folder-iam-policy-get': gcp_iam_folder_iam_policy_get_command,
            'gcp-iam-folder-iam-permission-test': gcp_iam_folder_iam_test_permission_command,
            'gcp-iam-folder-iam-member-add': gcp_iam_folder_iam_member_add_command,
            'gcp-iam-folder-iam-member-remove': gcp_iam_folder_iam_member_remove_command,
            'gcp-iam-folder-iam-policy-set': gcp_iam_folder_iam_policy_set_command,
            'gcp-iam-folder-iam-policy-create': gcp_iam_folder_iam_policy_add_command,
            'gcp-iam-organizations-get': gcp_iam_organization_get_command,
            'gcp-iam-organization-iam-policy-get': gcp_iam_organization_iam_policy_get_command,
            'gcp-iam-organization-iam-permission-test': gcp_iam_organization_iam_test_permission_command,
            'gcp-iam-organization-iam-member-add': gcp_iam_organization_iam_member_add_command,
            'gcp-iam-organization-iam-member-remove': gcp_iam_organization_iam_member_remove_command,
            'gcp-iam-organization-iam-policy-set': gcp_iam_organization_iam_policy_set_command,
            'gcp-iam-organization-iam-policy-create': gcp_iam_organization_iam_policy_add_command,
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
        }

        if command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

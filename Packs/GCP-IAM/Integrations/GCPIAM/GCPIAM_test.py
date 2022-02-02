import importlib
import json
from unittest.mock import patch, Mock

import pytest

GCP_IAM = importlib.import_module("GCPIAM")


def get_error_message(resource_name: str, error: str = 'Not Found') -> str:
    """
    Get error message.
    Args:
        resource_name (str): The name of the resource which trying to retrieve.
        error (str): Exception message

    Returns:
        str: Error message.

    """
    return f'An error occurred while retrieving {resource_name}.\n {error}'


def load_mock_response(file_path: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_path (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_path}', mode='r', encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture
def client():
    with patch.object(GCP_IAM.Client, "__init__", lambda x: None):
        mocked_client = GCP_IAM.Client()
        mocked_client.cloud_identity_service = Mock()
        mocked_client.cloud_resource_manager_service = Mock()
        mocked_client.execute_request = Mock()
    return mocked_client


def test_gcp_iam_project_list_command(client):
    """
    Scenario: list projects.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('project/project_list.json')
    client.gcp_iam_project_list_request = Mock(return_value=mock_response)
    parent = "organizations/xsoar-organization"
    result = GCP_IAM.gcp_iam_projects_get_command(client, {"parent": parent})

    assert len(result[0].outputs) == 2
    assert result[0].outputs_prefix == 'GCPIAM.Project'
    assert result[0].outputs[0].get('name') == 'projects/project-name-1'


def test_gcp_iam_project_get_command(client):
    """
    Scenario: get project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('project/project_get.json')
    client.gcp_iam_project_get_request = Mock(return_value=mock_response)
    project_name = "projects/project-name-1"
    result = GCP_IAM.gcp_iam_projects_get_command(client, {"project_name": project_name})

    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'GCPIAM.Project'
    assert result[0].outputs[0].get('name') == project_name

    client.gcp_iam_project_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_projects_get_command(client, {"project_name": project_name})
    assert result[0].readable_output == get_error_message(project_name)


def test_gcp_iam_project_iam_policy_get_command(client):
    """
    Scenario: Retrieve the IAM access control policy for the specified project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-iam-policy-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('project/project_iam_policy_get.json')
    client.gcp_iam_project_iam_policy_get_request = Mock(return_value=mock_response)
    project_name = "projects/project-name-1"
    result = GCP_IAM.gcp_iam_project_iam_policy_get_command(client, {"project_name": project_name})

    assert len(result.outputs.get('bindings')) == 2
    assert result.outputs_prefix == 'GCPIAM.Policy'
    assert result.outputs.get('name') == project_name
    assert result.outputs.get('bindings')[0].get('role') == 'roles/anthosidentityservice.serviceAgent'


def test_gcp_iam_project_iam_test_permission_command(client):
    """
    Scenario: Retrieve permissions that a caller has on the specified project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-iam-permission-test called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('project/project_iam_test_permission.json')
    client.gcp_iam_project_iam_test_permission_request = Mock(return_value=mock_response)
    project_name = "projects/project-name-1"
    permissions = "compute.instances.create,aiplatform.dataItems.create"
    result = GCP_IAM.gcp_iam_project_iam_test_permission_command(client, {"project_name": project_name,
                                                                          "permissions": permissions})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'GCPIAM.Permission'
    assert result.outputs[1].get('name') == "compute.instances.create"
    assert result.outputs[0].get('name') == "aiplatform.dataItems.create"


def test_gcp_iam_project_iam_member_add_command(client):
    """
    Scenario: Add members to project policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-iam-member-add called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('project/project_iam_policy_set.json')
    client.gcp_iam_project_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('project/project_iam_policy_get.json')
    client.gcp_iam_project_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    project_name = "projects/project-name-1"
    member = "user:user-1@xsoar.com"
    role = "roles/browser"
    command_args = {"project_name": project_name,
                    "role": role,
                    "members": member}

    result = GCP_IAM.gcp_iam_project_iam_member_add_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_project_iam_member_remove_command(client):
    """
    Scenario: Remove members from project policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-iam-member-remove called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('project/project_iam_policy_set.json')
    client.gcp_iam_project_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('project/project_iam_policy_get.json')
    client.gcp_iam_project_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    project_name = "projects/project-name-1"
    member = "group:poctest@xsoar.com"
    role = "roles/browser"
    command_args = {"project_name": project_name,
                    "role": role,
                    "members": member}

    result = GCP_IAM.gcp_iam_project_iam_member_remove_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_project_iam_policy_set_command(client):
    """
    Scenario: Sets the IAM access control policy for the specified project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-iam-policy-set called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('project/project_iam_policy_set.json')
    client.gcp_iam_project_iam_policy_set_request = Mock(return_value=mock_response)

    policy = [
        {
            "role": "roles/owner",
            "members": [
                "group:poctest@xsoar.com",
                "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com",
                "user:user-1@xsoar.com"
            ]
        },
        {
            "role": "roles/browser",
            "members": [
                "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com",
                "user:user-1@xsoar.com"
            ]
        }
    ]

    project_name = "projects/project-name-1"

    command_args = {"project_name": project_name,
                    "policy": json.dumps(policy)}

    result = GCP_IAM.gcp_iam_project_iam_policy_set_command(client, command_args)

    assert len(result.outputs.get('bindings')) == 2
    assert result.outputs_prefix == 'GCPIAM.Policy'
    assert result.outputs.get('name') == project_name
    assert result.outputs.get('bindings') == policy


def test_gcp_iam_project_iam_policy_add_command(client):
    """
    Scenario: Add new project IAM policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-iam-policy-create called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('project/project_iam_policy_set.json')
    client.gcp_iam_project_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('project/project_iam_policy_get.json')
    client.gcp_iam_project_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    project_name = "projects/project-name-1"
    role = "roles/browser"
    members = [
        "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com",
        "user:user-1@xsoar.com"
    ]
    command_args = {
        "project_name": project_name,
        "role": role,
        "members": members
    }

    result = GCP_IAM.gcp_iam_project_iam_policy_add_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_project_iam_policy_remove_command(client):
    """
    Scenario: Remove policy from project IAM policies.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-policy-remove called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('project/project_iam_policy_set.json')
    client.gcp_iam_project_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('project/project_iam_policy_get.json')
    client.gcp_iam_project_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    project_name = "projects/project-name-1"
    role = "roles/browser"
    command_args = {
        "project_name": project_name,
        "role": role
    }

    result = GCP_IAM.gcp_iam_project_iam_policy_remove_command(client, command_args)

    assert result.readable_output == f'Project {project_name} IAM policies updated successfully.'


def test_gcp_iam_group_create_command(client):
    """
    Scenario: Create a new group.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('group/group_create.json')
    client.gcp_iam_group_create_request = Mock(return_value=mock_response)

    parent = "customers/xsoar-customer-id"
    display_name = "xsoar-api-test-2"
    description = "api-test-2"
    group_email_address = "poctest12@xsoar.com"

    command_args = {"parent": parent,
                    "display_name": display_name,
                    "description": description,
                    "group_email_address": group_email_address}

    result = GCP_IAM.gcp_iam_group_create_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 9
    assert result.outputs_prefix == 'GCPIAM.Group'
    assert result.outputs[0].get('parent') == parent
    assert result.outputs[0].get('displayName') == display_name
    assert result.outputs[0].get('description') == description
    assert result.outputs[0].get('groupKey').get('id') == group_email_address


def test_gcp_iam_group_list_command(client):
    """
    Scenario: List groups under the specified parent.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('group/group_list.json')
    client.gcp_iam_group_list_request = Mock(return_value=mock_response)

    parent = "customers/xsoar-customer-id"

    command_args = {"parent": parent}

    result = GCP_IAM.gcp_iam_group_list_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 3
    assert result.outputs_prefix == 'GCPIAM.Group'
    assert result.outputs[0].get('name') == 'groups/group-3-name'
    assert result.outputs[0].get('displayName') == "xsoar-api-test-2"
    assert result.outputs[0].get('groupKey').get('id') == "poctest1@xsoar.com"


def test_gcp_iam_group_get_command(client):
    """
    Scenario: Retrieve group information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('group/group_get.json')
    client.gcp_iam_group_get_request = Mock(return_value=mock_response)

    group_name = 'groups/group-1-name'

    command_args = {"group_name": group_name}

    result = GCP_IAM.gcp_iam_group_get_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 8
    assert result.outputs_prefix == 'GCPIAM.Group'
    assert result.outputs[0].get('name') == 'groups/group-1-name'
    assert result.outputs[0].get('displayName') == "xsoar-api-test-2"
    assert result.outputs[0].get('groupKey').get('id') == "poctest12@xsoar.com"


def test_gcp_iam_group_delete_command(client):
    """
    Scenario: Delete group.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-delete called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('group/group_delete.json')
    client.gcp_iam_group_delete_request = Mock(return_value=mock_response)

    group_name = 'groups/group-1-name'

    command_args = {"group_name": group_name}

    result = GCP_IAM.gcp_iam_group_delete_command(client, command_args)

    assert result.readable_output == f'Group {group_name} was successfully deleted.'


def test_gcp_iam_group_membership_create_command(client):
    """
    Scenario: Create a group membership.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-membership-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('group/group_membership_create.json')
    client.gcp_iam_group_membership_create_request = Mock(return_value=mock_response)

    group_name = 'groups/group-3-name'
    member_email = "user-2@xsoar.com"
    role = "MEMBER"

    command_args = {"groups_name": group_name, member_email: member_email, role: role}

    result = GCP_IAM.gcp_iam_group_membership_create_command(client, command_args)

    assert len(result) == 1
    assert len(result[0].outputs) == 1
    assert len(result[0].outputs[0]) == 4
    assert result[0].outputs_prefix == 'GCPIAM.Membership'
    assert result[0].outputs[0].get('name') == "groups/group-3-name/memberships/membership-1"
    assert result[0].outputs[0].get('roles')[0].get('name') == role
    assert result[0].outputs[0].get('preferredMemberKey').get('id') == member_email

    client.gcp_iam_group_membership_create_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_group_membership_create_command(client, command_args)
    assert result[
               0].readable_output == f'An error occurred while creating membership in group {group_name}.\n Not Found'


def test_gcp_iam_group_membership_list_command(client):
    """
    Scenario: List group memberships.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-membership-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('group/group_membership_list.json')
    client.gcp_iam_group_membership_list_request = Mock(return_value=mock_response)

    group_name = 'groups/group-3-name'

    command_args = {"group_name": group_name}

    result = GCP_IAM.gcp_iam_group_membership_list_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 3
    assert result.outputs_prefix == 'GCPIAM.Membership'
    assert result.outputs[0].get('name') == "groups/group-3-name/memberships/membership-1"
    assert result.outputs[0].get('roles')[0].get('name') == 'MEMBER'
    assert result.outputs[0].get('preferredMemberKey').get('id') == "user-2@xsoar.com"


def test_gcp_iam_group_membership_get_command(client):
    """
    Scenario: Retrieve group membership information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-membership-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('group/group_membership_get.json')
    client.gcp_iam_group_membership_get_request = Mock(return_value=mock_response)

    membership_name = "groups/group-2-name/memberships/membership-2"

    command_args = {"membership_name": membership_name}

    result = GCP_IAM.gcp_iam_group_membership_get_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 6
    assert result.outputs_prefix == 'GCPIAM.Membership'
    assert result.outputs[0].get('name') == membership_name
    assert result.outputs[0].get('roles')[1].get('name') == 'MEMBER'
    assert result.outputs[0].get('preferredMemberKey').get(
        'id') == 'service-account-1@project-id-1.iam.gserviceaccount.com'


def test_gcp_iam_group_membership_role_add_command(client):
    """
    Scenario: Add group membership role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-membership-role-add called.
    Then:
     - Ensure results readable output..
    """
    mock_response = load_mock_response('group/group_membership_add_role.json')
    client.gcp_iam_group_membership_role_add_request = Mock(return_value=mock_response)

    membership_name = "groups/group-2-name/memberships/membership-2"

    command_args = {"membership_name": membership_name, "role": "OWNER"}

    result = GCP_IAM.gcp_iam_group_membership_role_add_command(client, command_args)

    assert result.readable_output == f'Membership {membership_name} updated successfully.'


def test_gcp_iam_group_membership_role_remove_command(client):
    """
    Scenario: Remove group membership role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-membership-role-remove called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('group/group_membership_remove_role.json')
    client.gcp_iam_group_membership_role_remove_request = Mock(return_value=mock_response)

    membership_name = "groups/group-2-name/memberships/membership-2"

    command_args = {"membership_name": membership_name, "role": "OWNER"}

    result = GCP_IAM.gcp_iam_group_membership_role_remove_command(client, command_args)

    assert result.readable_output == f'Membership {membership_name} updated successfully.'


def test_gcp_iam_group_membership_delete_request(client):
    """
    Scenario: Delete group membership.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-group-membership-delete called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('group/group_membership_delete.json')
    client.gcp_iam_group_membership_delete_request = Mock(return_value=mock_response)

    membership_name = "groups/group-2-name/memberships/membership-2"

    command_args = {"membership_names": membership_name}

    result = GCP_IAM.gcp_iam_group_membership_delete_command(client, command_args)

    assert len(result) == 1
    assert result[0].readable_output == f'Membership {membership_name} deleted successfully.'

    client.gcp_iam_group_membership_delete_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_group_membership_delete_command(client, command_args)
    assert result[
               0].readable_output == f'An error occurred while deleting the membership {membership_name}.\n Not Found'


def test_gcp_iam_testable_permission_list_command(client):
    """
    Lists permissions that can be tested on a resource.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-testable-permission-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('permission/query_resource_permissions.json')
    client.gcp_iam_testable_permission_list_request = Mock(return_value=mock_response)

    resource_name = "groups/group-2-name"

    command_args = {"resource_name": resource_name}

    result = GCP_IAM.gcp_iam_testable_permission_list_command(client, command_args)

    assert len(result.outputs) == 3
    assert len(result.outputs[0]) == 2
    assert result.outputs_prefix == 'GCPIAM.Permission'
    assert result.outputs[0].get('name') == "accessapproval.requests.approve"
    assert result.outputs[0].get('stage') == "BETA"


def test_gcp_iam_grantable_role_list_command(client):
    """
    Lists roles that can be granted on a Google Cloud resource.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-grantable-role-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/grantable_role_list.json')
    client.gcp_iam_grantable_role_list_request = Mock(return_value=mock_response)

    resource_name = "organizations/organization-name"

    command_args = {"resource_name": resource_name}

    result = GCP_IAM.gcp_iam_grantable_role_list_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 3
    assert result.outputs_prefix == 'GCPIAM.Roles'
    assert result.outputs[0].get('name') == "roles/accessapproval.approver"
    assert result.outputs[0].get('title') == "Access Approval Approver"


def test_gcp_iam_service_account_create_command(client):
    """
    Create a service account in project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('service_account/service_account_create.json')
    client.gcp_iam_service_account_create_request = Mock(return_value=mock_response)

    project_name = "projects/project-id-1"
    service_account_id = "poc-test12"
    display_name = "user-1-display-name"
    description = "my poc service"

    command_args = dict(project_name=project_name, service_account_id=service_account_id,
                        display_name=display_name, description=description)

    result = GCP_IAM.gcp_iam_service_account_create_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 9
    assert result.outputs_prefix == 'GCPIAM.ServiceAccount'
    assert result.outputs[0].get('description') == description


def test_gcp_iam_service_account_update_command(client):
    """
    Update service account.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-update called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_update_request = Mock(return_value={})

    service_account_name = "projects/project-id-1/serviceAccounts/poc-test12@project-name-1.iam.gserviceaccount.com"
    service_account_id = "poc-test12"
    display_name = "user-1-display-name"
    description = "my poc service"

    command_args = dict(service_account_name=service_account_name, service_account_id=service_account_id,
                        display_name=display_name, description=description)

    result = GCP_IAM.gcp_iam_service_account_update_command(client, command_args)

    assert result.readable_output == f'Service account {service_account_name} updated successfully.'


def test_gcp_iam_service_account_list_command(client):
    """
    List service accounts in project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('service_account/service_account_list.json')
    client.gcp_iam_service_account_list_request = Mock(return_value=mock_response)

    project_name = "projects/project-id-1"

    command_args = dict(project_name=project_name)

    result = GCP_IAM.gcp_iam_service_accounts_get_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 8
    assert result.outputs_prefix == 'GCPIAM.ServiceAccount'
    assert result.outputs[0].get('projectId') == "project-id-1"


def test_gcp_iam_service_account_get_command(client):
    """
    Retrieve project service account information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('service_account/service_account_get.json')
    client.gcp_iam_service_account_get_request = Mock(return_value=mock_response)

    service_account_name = "projects/project-id-1/serviceAccounts/poc-test12@project-name-1.iam.gserviceaccount.com"

    command_args = dict(service_account_name=service_account_name)

    result = GCP_IAM.gcp_iam_service_accounts_get_command(client, command_args)

    assert len(result) == 1
    assert len(result[0].outputs) == 1
    assert len(result[0].outputs[0]) == 9
    assert result[0].outputs_prefix == 'GCPIAM.ServiceAccount'
    assert result[0].outputs[0].get('projectId') == 'project-id-1'

    client.gcp_iam_service_account_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_accounts_get_command(client, command_args)
    assert result[0].readable_output == get_error_message(service_account_name)


def test_gcp_iam_service_account_enable_command(client):
    """
    Enable project service account.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-enable called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_enable_request = Mock(return_value={})

    service_account_name = "projects/project-id-1/serviceAccounts/poc-test12@project-name-1.iam.gserviceaccount.com"

    command_args = dict(service_account_name=service_account_name)

    result = GCP_IAM.gcp_iam_service_account_enable_command(client, command_args)

    assert result[0].readable_output == f'Service account {service_account_name} updated successfully.'

    client.gcp_iam_service_account_enable_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_account_enable_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to enable {service_account_name}.\n Not Found'


def test_gcp_iam_service_account_disable_command(client):
    """
    Disable project service account.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-disable called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_disable_request = Mock(return_value={})

    service_account_name = "projects/project-id-1/serviceAccounts/poc-test12@project-name-1.iam.gserviceaccount.com"

    command_args = dict(service_account_name=service_account_name)

    result = GCP_IAM.gcp_iam_service_account_disable_command(client, command_args)

    assert result[0].readable_output == f'Service account {service_account_name} updated successfully.'

    client.gcp_iam_service_account_disable_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_account_disable_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to disable {service_account_name}.\n Not Found'


def test_gcp_iam_service_account_delete_command(client):
    """
    Delete project service account.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-delete called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_delete_request = Mock(return_value={})

    service_account_name = "projects/project-id-1/serviceAccounts/poc-test12@project-name-1.iam.gserviceaccount.com"

    command_args = dict(service_account_name=service_account_name)

    result = GCP_IAM.gcp_iam_service_account_delete_command(client, command_args)

    assert result[0].readable_output == f'Service account {service_account_name} deleted successfully.'

    client.gcp_iam_service_account_delete_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_account_delete_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to delete {service_account_name}.\n Not Found'


def test_gcp_iam_service_account_key_create_command(client):
    """
    Create a service account key.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-key-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('service_account_key/service_account_key_create.json')
    client.gcp_iam_service_account_key_create_request = Mock(return_value=mock_response)

    service_account_name = "projects/project-id-1/serviceAccounts/test-2@project-id-1.iam.gserviceaccount.com"

    command_args = dict(service_account_name=service_account_name)

    result = GCP_IAM.gcp_iam_service_account_key_create_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 9
    assert result.outputs_prefix == 'GCPIAM.ServiceAccountKey'
    assert result.outputs[0].get('privateKeyData') == "my-private-key-data"
    assert not result.outputs[0].get('disabled')


def test_gcp_iam_service_account_key_list_command(client):
    """
    List service accounts keys.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-key-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('service_account_key/service_account_key_list.json')
    client.gcp_iam_service_account_key_list_request = Mock(return_value=mock_response)

    service_account_name = "projects/project-id-1/serviceAccounts/test-2@project-id-1.iam.gserviceaccount.com"

    command_args = dict(service_account_name=service_account_name)

    result = GCP_IAM.gcp_iam_service_account_keys_get_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCPIAM.ServiceAccountKey'
    assert not result.outputs[1].get('disabled')
    assert result.outputs[1].get(
        'name') == "projects/project-id-1/serviceAccounts/" \
                   "integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"


def test_gcp_iam_service_account_key_get_command(client):
    """
    Retrieve service account key information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-key-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('service_account_key/service_account_key_get.json')
    client.gcp_iam_service_account_key_get_request = Mock(return_value=mock_response)

    key_name = "projects/project-id-1/serviceAccounts/" \
               "integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_keys_get_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCPIAM.ServiceAccountKey'
    assert not result.outputs[0].get('disabled')
    assert result.outputs[0].get(
        'name') == "projects/project-id-1/serviceAccounts/" \
                   "integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"


def test_gcp_iam_service_account_key_enable_command(client):
    """
    Enable service account key.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-enable called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_key_enable_request = Mock(return_value={})

    key_name = "projects/project-id-1/serviceAccounts/" \
               "integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_key_enable_command(client, command_args)

    assert result[0].readable_output == f'Service account key {key_name} updated successfully.'

    client.gcp_iam_service_account_key_enable_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_account_key_enable_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to enable {key_name}.\n Not Found'


def test_gcp_iam_service_account_key_disable_command(client):
    """
    Disable service account key.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-disable called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_key_disable_request = Mock(return_value={})

    key_name = "projects/project-id-1/serviceAccounts/" \
               "integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_key_disable_command(client, command_args)

    assert result[0].readable_output == f'Service account key {key_name} updated successfully.'

    client.gcp_iam_service_account_key_disable_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_account_key_disable_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to disable {key_name}.\n Not Found'


def test_gcp_iam_service_account_key_delete_command(client):
    """
    Delete service account key.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-service-account-delete called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_service_account_key_delete_request = Mock(return_value={})

    key_name = "projects/project-id-1/serviceAccounts/" \
               "integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_key_delete_command(client, command_args)

    assert result[0].readable_output == f'Service account key {key_name} deleted successfully.'

    client.gcp_iam_service_account_key_delete_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_service_account_key_delete_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to delete {key_name}.\n Not Found'


def test_gcp_iam_organization_role_create_command(client):
    """
    Create a custom organization role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/organization_role_create.json')
    client.gcp_iam_organization_role_create_request = Mock(return_value=mock_response)

    organization_name = "organizations/xsoar-organization"
    role_id = "xsoar_demo_97"

    command_args = dict(organization_name=organization_name, role_id=role_id)

    result = GCP_IAM.gcp_iam_organization_role_create_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCPIAM.Role'
    assert result.outputs[0].get('stage') == 'ALPHA'
    assert result.outputs[0].get('name') == f'{organization_name}/roles/{role_id}'


def test_gcp_iam_project_role_create_command(client):
    """
    Create a custom project role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/project_role_create.json')
    client.gcp_iam_project_role_create_request = Mock(return_value=mock_response)

    project_id = "xsoar-project-5"
    role_id = "test_xsoar_role"

    command_args = dict(project_id=project_id, role_id=role_id)

    result = GCP_IAM.gcp_iam_project_role_create_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCPIAM.Role'
    assert result.outputs[0].get('stage') == 'ALPHA'
    assert result.outputs[0].get('name') == f'projects/{project_id}/roles/{role_id}'


def test_gcp_iam_organization_role_get_command(client):
    """
    Retrieve organization role information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/organization_role_get.json')
    client.gcp_iam_organization_role_get_request = Mock(return_value=mock_response)

    role_name = "organizations/xsoar-organization/roles/xsoar_demo_97"

    command_args = dict(role_name=role_name)

    result = GCP_IAM.gcp_iam_organization_role_get_command(client, command_args)

    assert len(result[0].outputs) == 1
    assert len(result[0].outputs[0]) == 7
    assert result[0].outputs_prefix == 'GCPIAM.Role'
    assert result[0].outputs[0].get('stage') == 'ALPHA'
    assert result[0].outputs[0].get('name') == role_name

    client.gcp_iam_organization_role_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_organization_role_get_command(client, command_args)
    assert result[0].readable_output == get_error_message(role_name)


def test_gcp_iam_project_role_get_command(client):
    """
    Retrieve project role information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/project_role_get.json')
    client.gcp_iam_project_role_get_request = Mock(return_value=mock_response)

    role_name = "projects/xsoar-project-5/roles/test_xsoar_role"

    command_args = dict(role_name=role_name)

    result = GCP_IAM.gcp_iam_project_role_get_command(client, command_args)

    assert len(result[0].outputs) == 1
    assert len(result[0].outputs[0]) == 7
    assert result[0].outputs_prefix == 'GCPIAM.Role'
    assert result[0].outputs[0].get('stage') == 'ALPHA'
    assert result[0].outputs[0].get('name') == role_name

    client.gcp_iam_project_role_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_project_role_get_command(client, command_args)
    assert result[0].readable_output == get_error_message(role_name)


def test_gcp_iam_organization_role_list_command(client):
    """
    List organization custom roles.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/organization_role_list.json')
    client.gcp_iam_organization_role_list_request = Mock(return_value=mock_response)

    organization_name = "organizations/xsoar-organization"
    include_permissions = "True"

    command_args = dict(organization_name=organization_name, include_permissions=include_permissions)

    result = GCP_IAM.gcp_iam_organization_role_list_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCPIAM.Role'
    assert result.outputs[0].get('stage') == 'ALPHA'
    assert result.outputs[1].get('name') == "organizations/xsoar-organization/roles/xsoar_demo_97"


def test_gcp_iam_project_role_list_command(client):
    """
    List project custom roles.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/project_role_list.json')
    client.gcp_iam_project_role_list_request = Mock(return_value=mock_response)

    project_id = "xsoar-project-5"
    include_permissions = "True"

    command_args = dict(project_id=project_id, include_permissions=include_permissions)

    result = GCP_IAM.gcp_iam_project_role_list_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 7
    assert len(result.outputs[1]) == 7
    assert result.outputs_prefix == 'GCPIAM.Role'
    assert result.outputs[0].get('stage') == 'ALPHA'
    assert result.outputs[1].get('name') == "projects/xsoar-project-5/roles/test_xsoar_role"


def test_gcp_iam_predefined_role_list_command(client):
    """
    Lists every predefined Role that IAM supports.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-role-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/predefined_role_list.json')
    client.gcp_iam_predefined_role_list_request = Mock(return_value=mock_response)

    include_permissions = "True"

    command_args = dict(include_permissions=include_permissions)

    result = GCP_IAM.gcp_iam_predefined_role_list_command(client, command_args)

    assert len(result.outputs) == 2
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCPIAM.Role'
    assert result.outputs[0].get('stage') == 'BETA'
    assert result.outputs[1].get('name') == "roles/accessapproval.configEditor"


def test_gcp_iam_predefined_role_get_command(client):
    """
    Retrieve predefined role information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-role-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('role/predefined_role_get.json')
    client.gcp_iam_predefined_role_get_request = Mock(return_value=mock_response)

    role_name = "roles/accessapproval.approver"

    command_args = dict(role_name=role_name)

    result = GCP_IAM.gcp_iam_predefined_role_get_command(client, command_args)

    assert len(result[0].outputs) == 1
    assert len(result[0].outputs[0]) == 7
    assert result[0].outputs_prefix == 'GCPIAM.Role'
    assert result[0].outputs[0].get('stage') == 'BETA'
    assert result[0].outputs[0].get('name') == role_name

    client.gcp_iam_predefined_role_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_predefined_role_get_command(client, command_args)
    assert result[0].readable_output == get_error_message(role_name)


def test_gcp_iam_organization_role_update_command(client):
    """
    Update an organization custom role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-update called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_organization_role_update_request = Mock(return_value={})

    role_name = "organizations/xsoar-organization/roles/xsoar_demo_97"
    title = "new title"
    fields_to_update = "title"
    command_args = dict(role_name=role_name, title=title, fields_to_update=fields_to_update)

    result = GCP_IAM.gcp_iam_organization_role_update_command(client, command_args)

    assert result.readable_output == f'Role {role_name} updated successfully.'


def test_gcp_iam_project_role_update_command(client):
    """
    Update an project custom role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-update called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_project_role_update_request = Mock(return_value={})

    role_name = "projects/xsoar-project-5/roles/test_xsoar_role"
    title = "new title"
    fields_to_update = "title"
    command_args = dict(role_name=role_name, title=title, fields_to_update=fields_to_update)

    result = GCP_IAM.gcp_iam_project_role_update_command(client, command_args)

    assert result.readable_output == f'Role {role_name} updated successfully.'


def test_gcp_iam_organization_role_permission_add_command(client):
    """
    Add permissions to custom organization role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-permission-add called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_organization_role_update_request = Mock(return_value={})
    mock_response = load_mock_response('role/organization_role_get.json')
    client.gcp_iam_organization_role_get_request = Mock(return_value=mock_response)

    role_name = "organizations/xsoar-organization/roles/xsoar_demo_97"
    permissions = "aiplatform.artifacts.get,aiplatform.artifacts.list"
    command_args = dict(role_name=role_name, permissions=permissions)

    result = GCP_IAM.gcp_iam_organization_role_permission_add_command(client, command_args)

    assert result.readable_output == f'Role {role_name} updated successfully.'


def test_gcp_iam_project_role_permission_add_command(client):
    """
    Add permissions to custom project role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-permission-add called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_project_role_update_request = Mock(return_value={})
    mock_response = load_mock_response('role/project_role_get.json')
    client.gcp_iam_project_role_get_request = Mock(return_value=mock_response)

    role_name = "projects/xsoar-project-5/roles/test_xsoar_role"
    permissions = "aiplatform.artifacts.get,aiplatform.artifacts.list"
    command_args = dict(role_name=role_name, permissions=permissions)

    result = GCP_IAM.gcp_iam_project_role_permission_add_command(client, command_args)

    assert result.readable_output == f'Role {role_name} updated successfully.'


def test_gcp_iam_organization_role_permission_remove_command(client):
    """
    Remove permissions from custom organization role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-permission-remove called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_organization_role_update_request = Mock(return_value={})
    mock_response = load_mock_response('role/organization_role_get.json')
    client.gcp_iam_organization_role_get_request = Mock(return_value=mock_response)

    role_name = "organizations/xsoar-organization/roles/xsoar_demo_97"
    permissions = "aiplatform.artifacts.get"

    command_args = dict(role_name=role_name, permissions=permissions)

    result = GCP_IAM.gcp_iam_organization_role_permission_remove_command(client, command_args)

    assert result.readable_output == f'Role {role_name} updated successfully.'


def test_gcp_iam_project_role_permission_remove_command(client):
    """
    Remove permissions from custom project role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-permission-remove called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_project_role_update_request = Mock(return_value={})
    mock_response = load_mock_response('role/project_role_get.json')
    client.gcp_iam_project_role_get_request = Mock(return_value=mock_response)

    role_name = "projects/xsoar-project-5/roles/test_xsoar_role"
    permissions = "aiplatform.artifacts.get"

    command_args = dict(role_name=role_name, permissions=permissions)

    result = GCP_IAM.gcp_iam_project_role_permission_add_command(client, command_args)

    assert result.readable_output == f'Role {role_name} updated successfully.'


def test_gcp_iam_organization_role_permission_remove_command_exception(client):
    """
    Remove permissions from custom organization role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-permission-remove called.
     - User has provided invalid command arguments.
    Then:
     - Ensure command raise exception.
    """
    client.gcp_iam_organization_role_update_request = Mock(return_value={})
    mock_response = load_mock_response('role/organization_role_get.json')
    client.gcp_iam_organization_role_get_request = Mock(return_value=mock_response)

    role_name = "organizations/xsoar-organization/roles/xsoar_demo_97"
    permissions = "aiplatform.artifacts.get,aiplatform.artifacts.list"
    command_args = dict(role_name=role_name, permissions=permissions)

    with pytest.raises(Exception):
        GCP_IAM.gcp_iam_organization_role_permission_remove_command(client, command_args)


def test_gcp_iam_project_role_permission_remove_command_exception(client):
    """
    Remove permissions from custom project role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-permission-remove called.
     - User has provided invalid command arguments.
    Then:
     - Ensure command raise exception.
    """
    client.gcp_iam_project_role_get_request = Mock(return_value={})
    mock_response = load_mock_response('role/project_role_get.json')
    client.gcp_iam_project_role_update_request = Mock(return_value=mock_response)

    role_name = "projects/xsoar-project-5/roles/test_xsoar_role"
    permissions = "aiplatform.artifacts.get,aiplatform.artifacts.list"
    command_args = dict(role_name=role_name, permissions=permissions)

    with pytest.raises(Exception):
        GCP_IAM.gcp_iam_project_role_permission_remove_command(client, command_args)


def test_gcp_iam_organization_role_delete_command(client):
    """
    Delete a custom organization role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-role-delete called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_organization_role_delete_request = Mock(return_value={})

    role_name = "organizations/xsoar-organization/roles/xsoar_demo_97"

    command_args = dict(role_name=role_name)

    result = GCP_IAM.gcp_iam_organization_role_delete_command(client, command_args)

    assert result[0].readable_output == f'Role {role_name} deleted successfully.'

    client.gcp_iam_organization_role_delete_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_organization_role_delete_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to delete {role_name}.\n Not Found'


def test_gcp_iam_project_role_delete_command(client):
    """
    Delete a custom project role.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-project-role-delete called.
    Then:
     - Ensure results readable output.
    """
    client.gcp_iam_project_role_delete_request = Mock(return_value={})

    role_name = "projects/xsoar-project-5/roles/test_xsoar_role"

    command_args = dict(role_name=role_name)

    result = GCP_IAM.gcp_iam_project_role_delete_command(client, command_args)

    assert result[0].readable_output == f'Role {role_name} deleted successfully.'

    client.gcp_iam_project_role_delete_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_project_role_delete_command(client, command_args)
    assert result[0].readable_output == f'An error occurred while trying to delete {role_name}.\n Not Found'


def test_gcp_iam_folder_list_command(client):
    """
    Scenario: list folders.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folders-get called and the user provided the 'parent' argument.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('folder/folder_list.json')
    client.gcp_iam_folder_list_request = Mock(return_value=mock_response)
    parent = "organizations/xsoar-organization"
    result = GCP_IAM.gcp_iam_folders_get_command(client, {"parent": parent})

    assert len(result[0].outputs) == 2
    assert result[0].outputs_prefix == 'GCPIAM.Folder'
    assert result[0].outputs[0].get('name') == 'folders/folder-name-1'


def test_gcp_iam_folder_get_command(client):
    """
    Scenario: Retrieve folder information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folders-get called and the user not provided the 'parent' argument.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('folder/folder_get.json')
    client.gcp_iam_folder_get_request = Mock(return_value=mock_response)
    folder_name = "folders/folder-name-1"
    result = GCP_IAM.gcp_iam_folders_get_command(client, {"folder_name": folder_name})

    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'GCPIAM.Folder'
    assert result[0].outputs[0].get('name') == folder_name

    client.gcp_iam_folder_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_folders_get_command(client, {"folder_name": folder_name})
    assert result[0].readable_output == get_error_message(folder_name)


def test_gcp_iam_folder_iam_policy_get_command(client):
    """
    Scenario: Retrieve the IAM access control policy for the specified folder.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-policy-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('folder/folder_iam_policy_get.json')
    client.gcp_iam_folder_iam_policy_get_request = Mock(return_value=mock_response)
    folder_name = "folders/folder-name-1"
    result = GCP_IAM.gcp_iam_folder_iam_policy_get_command(client, {"folder_name": folder_name})

    assert len(result.outputs.get('bindings')) == 2
    assert result.outputs_prefix == 'GCPIAM.Policy'
    assert result.outputs.get('name') == folder_name
    assert result.outputs.get('bindings')[0].get('role') == "roles/resourcemanager.folderAdmin"


def test_gcp_iam_folder_iam_test_permission_command(client):
    """
    Scenario: Retrieve permissions that a caller has on the specified folder.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-permission-test called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('folder/folder_iam_test_permission.json')
    client.gcp_iam_folder_iam_test_permission_request = Mock(return_value=mock_response)
    folder_name = "folders/folder-name-1"
    permissions = "compute.instances.create,aiplatform.dataItems.create"
    result = GCP_IAM.gcp_iam_folder_iam_test_permission_command(client,
                                                                {"folder_name": folder_name,
                                                                 "permissions": permissions})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'GCPIAM.Permission'
    assert result.outputs[1].get('name') == "compute.instances.create"
    assert result.outputs[0].get('name') == "aiplatform.dataItems.create"


def test_gcp_iam_folder_iam_member_add_command(client):
    """
    Scenario: Add members to folder policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-member-add called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('folder/folder_iam_policy_set.json')
    client.gcp_iam_folder_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('folder/folder_iam_policy_get.json')
    client.gcp_iam_folder_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    folder_name = "folders/folder-name-1"
    members = "user:user-2@xsoar.com"
    role = "roles/resourcemanager.folderEditor"
    command_args = dict(folder_name=folder_name, role=role, members=members)

    result = GCP_IAM.gcp_iam_folder_iam_member_add_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_folder_iam_member_remove_command(client):
    """
    Scenario: Remove members from folder policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-member-remove called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('folder/folder_iam_policy_set.json')
    client.gcp_iam_folder_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('folder/folder_iam_policy_get.json')
    client.gcp_iam_folder_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    folder_name = "folders/folder-name-1"
    members = "user:user-1@xsoar.com"
    role = "roles/resourcemanager.folderEditor"
    command_args = dict(folder_name=folder_name, role=role, members=members)

    result = GCP_IAM.gcp_iam_folder_iam_member_remove_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_folder_iam_policy_set_command(client):
    """
    Scenario: Sets the IAM access control folder for the specified project.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-policy-set called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('folder/folder_iam_policy_set.json')
    client.gcp_iam_folder_iam_policy_set_request = Mock(return_value=mock_response)

    policy = [
        {
            "role": "roles/resourcemanager.folderAdmin",
            "members": [
                "user:user-1@xsoar.com"
            ]
        },
        {
            "role": "roles/resourcemanager.folderEditor",
            "members": [
                "user:user-1@xsoar.com",
                "user:user-2@xsoar.com"
            ]
        }
    ]

    folder_name = "folders/folder-name-1"

    command_args = dict(folder_name=folder_name, policy=json.dumps(policy))

    result = GCP_IAM.gcp_iam_folder_iam_policy_set_command(client, command_args)

    assert len(result.outputs.get('bindings')) == 2
    assert result.outputs_prefix == 'GCPIAM.Policy'
    assert result.outputs.get('name') == folder_name
    assert result.outputs.get('bindings') == policy


def test_gcp_iam_folder_iam_policy_add_command(client):
    """
    Scenario: Add new folder IAM policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-policy-create called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('folder/folder_iam_policy_set.json')
    client.gcp_iam_folder_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('folder/folder_iam_policy_get.json')
    client.gcp_iam_folder_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    folder_name = "folders/folder-name-1"
    role = "roles/resourcemanager.folderEditor"
    members = [
        "user:user-1@xsoar.com",
        "user:user-2@xsoar.com"
    ]

    command_args = dict(folder_name=folder_name, role=role, members=members)

    result = GCP_IAM.gcp_iam_folder_iam_policy_add_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_folder_iam_policy_remove_command(client):
    """
    Scenario: Remove policy from folder IAM policies.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folder-iam-policy-create called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('folder/folder_iam_policy_set.json')
    client.gcp_iam_folder_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('folder/folder_iam_policy_get.json')
    client.gcp_iam_folder_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    folder_name = "folders/folder-name-1"
    role = "roles/resourcemanager.folderEditor"

    command_args = dict(folder_name=folder_name, role=role)

    result = GCP_IAM.gcp_iam_folder_iam_policy_remove_command(client, command_args)

    assert result.readable_output == f'Folder {folder_name} IAM policies updated successfully.'


def test_gcp_iam_organization_list_command(client):
    """
    Scenario: list organizations.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organizations-get called and the user not provided the 'organization_name' argument.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('organization/organization_list.json')
    client.gcp_iam_organization_list_request = Mock(return_value=mock_response)

    result = GCP_IAM.gcp_iam_organizations_get_command(client, {})

    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'GCPIAM.Organization'
    assert result[0].outputs[0].get('name') == "organizations/xsoar-organization"


def test_gcp_iam_organization_get_command(client):
    """
    Scenario: Retrieve folder information.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-folders-get called and the user not provided the 'parent' argument.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('organization/organization_get.json')
    client.gcp_iam_organization_get_request = Mock(return_value=mock_response)
    organization_name = "organizations/xsoar-organization"
    result = GCP_IAM.gcp_iam_organizations_get_command(client, {"organization_name": organization_name})

    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'GCPIAM.Organization'
    assert result[0].outputs[0].get('name') == organization_name

    client.gcp_iam_organization_get_request.side_effect = Exception('Not Found')
    result = GCP_IAM.gcp_iam_organizations_get_command(client, {"organization_name": organization_name})
    assert result[0].readable_output == get_error_message(organization_name)


def test_gcp_iam_organization_iam_policy_get_command(client):
    """
    Scenario: Retrieve the IAM access control policy for the specified organization.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-policy-get called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('organization/organization_iam_policy_get.json')
    client.gcp_iam_organization_iam_policy_get_request = Mock(return_value=mock_response)
    organization_name = "organizations/xsoar-organization"
    result = GCP_IAM.gcp_iam_organization_iam_policy_get_command(client, {"organization_name": organization_name})

    assert len(result.outputs.get('bindings')) == 2
    assert result.outputs_prefix == 'GCPIAM.Policy'
    assert result.outputs.get('name') == organization_name
    assert result.outputs.get('bindings')[0].get('role') == "roles/bigquery.admin"


def test_gcp_iam_organization_iam_test_permission_command(client):
    """
    Scenario: Retrieve permissions that a caller has on the specified organization.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-permission-test called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('organization/organization_iam_test_permission.json')
    client.gcp_iam_organization_iam_test_permission_request = Mock(return_value=mock_response)
    organization_name = "organizations/xsoar-organization"
    permissions = "compute.instances.create,aiplatform.dataItems.create"
    result = GCP_IAM.gcp_iam_organization_iam_test_permission_command(client,
                                                                      {"organization_name": organization_name,
                                                                       "permissions": permissions})

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'GCPIAM.Permission'
    assert result.outputs[1].get('name') == "compute.instances.create"
    assert result.outputs[0].get('name') == "aiplatform.dataItems.create"


def test_gcp_iam_organization_iam_member_add_command(client):
    """
    Scenario: Add members to organization policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-member-add called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('organization/organization_iam_policy_set.json')
    client.gcp_iam_organization_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('organization/organization_iam_policy_get.json')
    client.gcp_iam_organization_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    organization_name = "organizations/xsoar-organization"
    members = "user:user-2@xsoar.com"
    role = "roles/bigquery.user"
    command_args = dict(organization_name=organization_name, role=role, members=members)

    result = GCP_IAM.gcp_iam_organization_iam_member_add_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_organization_iam_member_remove_command(client):
    """
    Scenario: Remove members from organization policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-member-remove called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('organization/organization_iam_policy_set.json')
    client.gcp_iam_organization_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('organization/organization_iam_policy_get.json')
    client.gcp_iam_organization_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    organization_name = "organizations/xsoar-organization"
    members = "user:user-1@xsoar.com"
    role = "roles/bigquery.user"
    command_args = dict(organization_name=organization_name, role=role, members=members)

    result = GCP_IAM.gcp_iam_organization_iam_member_remove_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_organization_iam_policy_set_command(client):
    """
    Scenario: Sets the IAM access control folder for the specified organization.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-policy-set called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    mock_response = load_mock_response('organization/organization_iam_policy_set.json')
    client.gcp_iam_organization_iam_policy_set_request = Mock(return_value=mock_response)

    policy = [
        {
            "role": "roles/bigquery.admin",
            "members": [
                "user:user-1@xsoar.com"
            ]
        },
        {
            "role": "roles/bigquery.user",
            "members": [
                "user:user-1@xsoar.com",
                "user:user-2@xsoar.com"
            ]
        }
    ]

    organization_name = "organizations/xsoar-organization"

    command_args = dict(organization_name=organization_name, policy=json.dumps(policy))

    result = GCP_IAM.gcp_iam_organization_iam_policy_set_command(client, command_args)

    assert len(result.outputs.get('bindings')) == 2
    assert result.outputs_prefix == 'GCPIAM.Policy'
    assert result.outputs.get('name') == organization_name
    assert result.outputs.get('bindings') == policy


def test_gcp_iam_organization_iam_policy_add_command(client):
    """
    Scenario: Add new organization IAM policy.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-policy-create called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('organization/organization_iam_policy_set.json')
    client.gcp_iam_organization_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('organization/organization_iam_policy_get.json')
    client.gcp_iam_organization_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    organization_name = "organizations/xsoar-organization"
    role = "roles/bigquery.user"
    members = [
        "user:user-1@xsoar.com",
        "user:user-2@xsoar.com"
    ]

    command_args = dict(organization_name=organization_name, role=role, members=members)

    result = GCP_IAM.gcp_iam_organization_iam_policy_add_command(client, command_args)

    assert result.readable_output == f'Role {role} updated successfully.'


def test_gcp_iam_organization_iam_policy_remove_command(client):
    """
    Scenario: Remove policy from organization IAM policies.
    Given:
     - User has provided valid credentials.
    When:
     - gcp-iam-organization-iam-policy-remove called.
    Then:
     - Ensure results readable output.
    """
    mock_response = load_mock_response('organization/organization_iam_policy_set.json')
    client.gcp_iam_organization_iam_policy_set_request = Mock(return_value=mock_response)

    iam_get_mock_response = load_mock_response('organization/organization_iam_policy_get.json')
    client.gcp_iam_organization_iam_policy_get_request = Mock(return_value=iam_get_mock_response)

    organization_name = "organizations/xsoar-organization"
    role = "roles/bigquery.user"

    command_args = dict(organization_name=organization_name, role=role)

    result = GCP_IAM.gcp_iam_organization_iam_policy_remove_command(client, command_args)

    assert result.readable_output == f'Organization {organization_name} IAM policies updated successfully.'

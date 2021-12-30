import importlib
import json
from unittest.mock import patch, Mock

import pytest

GCP_IAM = importlib.import_module("GCP-IAM")


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

    assert len(result.outputs) == 2
    assert result.outputs_prefix == 'GCP.IAM.Project'
    assert result.outputs[0].get('name') == 'projects/project-name-1'


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

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'GCP.IAM.Project'
    assert result.outputs[0].get('name') == project_name


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
    assert result.outputs_prefix == 'GCP.IAM.Policy'
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
    assert result.outputs_prefix == 'GCP.IAM.Permission'
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
    assert result.outputs_prefix == 'GCP.IAM.Policy'
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
    assert result.outputs_prefix == 'GCP.IAM.Roles'
    assert result.outputs[0].get('name') == "roles/accessapproval.approver"
    assert result.outputs[0].get('title') == "Access Approval Approver"

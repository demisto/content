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
    assert result.outputs_prefix == 'GCP.IAM.ServiceAccount'
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
    assert result.outputs_prefix == 'GCP.IAM.ServiceAccount'
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
    assert result[0].outputs_prefix == 'GCP.IAM.ServiceAccount'
    assert result[0].outputs[0].get('projectId') == 'rich-agency-334609'


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
    assert result.outputs_prefix == 'GCP.IAM.ServiceAccountKey'
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
    assert result.outputs_prefix == 'GCP.IAM.ServiceAccountKey'
    assert not result.outputs[1].get('disabled')
    assert result.outputs[1].get(
        'name') == "projects/rich-agency-334609/serviceAccounts/integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"


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

    key_name = "projects/rich-agency-334609/serviceAccounts/integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_keys_get_command(client, command_args)

    assert len(result.outputs) == 1
    assert len(result.outputs[0]) == 7
    assert result.outputs_prefix == 'GCP.IAM.ServiceAccountKey'
    assert not result.outputs[0].get('disabled')
    assert result.outputs[0].get(
        'name') == "projects/rich-agency-334609/serviceAccounts/integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"


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

    key_name = "projects/rich-agency-334609/serviceAccounts/integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_key_enable_command(client, command_args)

    assert result[0].readable_output == f'Service account key {key_name} updated successfully.'


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

    key_name = "projects/rich-agency-334609/serviceAccounts/integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_key_disable_command(client, command_args)

    assert result[0].readable_output == f'Service account key {key_name} updated successfully.'


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

    key_name = "projects/rich-agency-334609/serviceAccounts/integration-test-5@395661807466.iam.gserviceaccount.com/keys/service-account-key-1"

    command_args = dict(key_name=key_name)

    result = GCP_IAM.gcp_iam_service_account_key_delete_command(client, command_args)

    assert result[0].readable_output == f'Service account key {key_name} deleted successfully.'

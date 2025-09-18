import json
import pytest
from google.oauth2.credentials import Credentials
from unittest.mock import MagicMock


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_parse_firewall_rule_valid_input():
    """
    Given: A valid firewall rule string with multiple rules
    When: parse_firewall_rule is called
    Then: The function returns a correctly parsed list of dictionaries
    """
    from GCP import parse_firewall_rule

    input_str = "ipprotocol=tcp,ports=80,443;ipprotocol=udp,ports=53"
    expected = [{"IPProtocol": "tcp", "ports": ["80", "443"]}, {"IPProtocol": "udp", "ports": ["53"]}]

    result = parse_firewall_rule(input_str)
    assert result == expected


def test_parse_firewall_rule_invalid_input():
    """
    Given: An invalid firewall rule string
    When: parse_firewall_rule is called
    Then: The function raises a ValueError with appropriate message
    """
    from GCP import parse_firewall_rule

    input_str = "invalid=format"
    with pytest.raises(ValueError) as e:
        parse_firewall_rule(input_str)

    assert "Could not parse field" in str(e.value)
    assert "Please make sure you provided like so" in str(e.value)


def test_parse_metadata_items_valid_input():
    """
    Given: A valid metadata items string with multiple items
    When: parse_metadata_items is called
    Then: The function returns a correctly parsed list of dictionaries
    """
    from GCP import parse_metadata_items

    input_str = "key=enable-oslogin,value=true;key=serial-port-enable,value=false"
    expected = [{"key": "enable-oslogin", "value": "true"}, {"key": "serial-port-enable", "value": "false"}]

    result = parse_metadata_items(input_str)
    assert result == expected


def test_parse_metadata_items_invalid_input():
    """
    Given: An invalid metadata items string
    When: parse_metadata_items is called
    Then: The function raises a ValueError with appropriate message
    """
    from GCP import parse_metadata_items

    input_str = "wrong=format"
    with pytest.raises(ValueError) as e:
        parse_metadata_items(input_str)

    assert "Could not parse field" in str(e.value)
    assert "Please make sure you provided like so: key=abc,value=123" in str(e.value)


def test_compute_firewall_patch_edge_cases(mocker):
    """
    Given: Valid credentials with empty and complex arguments for a firewall rule update
    When: compute_firewall_patch is called with boolean and list conversions
    Then: The function handles data transformations correctly and builds proper requests
    """
    from GCP import compute_firewall_patch

    # Mock credentials
    mock_creds = mocker.MagicMock()

    # Set up mocks
    mock_compute = mocker.MagicMock()
    mock_firewalls = mocker.MagicMock()
    mock_patch = mocker.MagicMock()

    mock_compute.firewalls.return_value = mock_firewalls
    mock_firewalls.patch.return_value = mock_patch
    mock_patch.execute.return_value = {"id": "operation-123", "status": "RUNNING"}

    # Mock the build function
    mocker.patch("GCP.build", return_value=mock_compute)
    mocker.patch("GCP.tableToMarkdown", return_value="mocked markdown")

    # Test case 1: Empty configuration
    empty_args = {"project_id": "test-project", "resource_name": "fw-rule"}

    compute_firewall_patch(mock_creds, empty_args)

    # Should call with empty config
    mock_firewalls.patch.assert_called_with(project="test-project", firewall="fw-rule", body={})

    # Reset mock for next test
    mock_firewalls.patch.reset_mock()

    # Test case 2: Boolean conversions and special fields
    bool_args = {
        "project_id": "test-project",
        "resource_name": "fw-rule",
        "disabled": "true",  # String boolean that should be converted
        "logConfigEnable": "false",  # Another string boolean
        "sourceTags": "single-tag",  # Single item that should become a list
        "allowed": "ipprotocol=all,ports=*",  # Special format for allowed
    }

    result = compute_firewall_patch(mock_creds, bool_args)

    # Get the body passed to patch
    called_with = mock_firewalls.patch.call_args[1]["body"]

    # Verify boolean conversions
    assert called_with["disabled"] is True
    assert called_with["logConfig"]["enable"] is False

    # Verify list conversions
    assert called_with["sourceTags"] == ["single-tag"]

    # Verify allowed rules parsing
    assert called_with["allowed"] == [{"IPProtocol": "all", "ports": ["*"]}]

    mock_firewalls.patch.assert_called_once()
    assert result.outputs_prefix == "GCP.Compute.Operations"


def test_storage_bucket_policy_delete_multiple_entities(mocker):
    """
    Given: A bucket with IAM policy containing multiple entities to be removed
    When: storage_bucket_policy_delete is called with entity='allUsers,user:test@mail.com'
    Then: The policy is updated with both entities removed from all roles
    """
    from GCP import storage_bucket_policy_delete

    # Mock data
    args = {"resource_name": "test-bucket", "entity": "allUsers,user:test@mail.com"}

    policy = {
        "bindings": [
            {"role": "roles/storage.objectViewer", "members": ["allUsers", "user:test@mail.com", "user:other@example.com"]},
            {"role": "roles/storage.admin", "members": ["user:admin@example.com", "user:test@mail.com"]},
        ]
    }

    # Mock the GCP API calls
    mock_storage = mocker.Mock()
    mock_buckets = mocker.Mock()

    mock_storage.buckets.return_value = mock_buckets
    mock_buckets.getIamPolicy.return_value.execute.return_value = policy
    mock_buckets.setIamPolicy.return_value.execute.return_value = {}

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_storage)

    # Run the function
    result = storage_bucket_policy_delete(mock_creds, args)

    # Verify the results
    assert "`allUsers`" in result.readable_output
    assert "`user:test@mail.com`" in result.readable_output
    mock_buckets.getIamPolicy.assert_called_once_with(bucket="test-bucket")
    mock_buckets.setIamPolicy.assert_called_once()
    # Verify that the removed entities are no longer in the policy
    call_args = mock_buckets.setIamPolicy.call_args[1]
    updated_policy = call_args["body"]
    for binding in updated_policy["bindings"]:
        assert "allUsers" not in binding.get("members", [])
        assert "user:test@mail.com" not in binding.get("members", [])


def test_compute_subnet_update_flow_logs(mocker):
    """
    Given: A GCP subnet that needs flow logs enabled
    When: compute_subnet_update is called with enable_flow_logs=true
    Then: The subnet's flow logs are enabled with proper fingerprint validation
    """
    from GCP import compute_subnet_update

    # Mock data
    args = {"project_id": "test-project", "region": "us-east1", "resource_name": "test-subnet", "enable_flow_logs": "true"}

    # Subnet response with fingerprint
    subnet_response = {"name": "test-subnet", "fingerprint": "test-fingerprint-123", "enableFlowLogs": False}

    # Expected patch operation response
    patch_response = {
        "id": "operation-123",
        "name": "operation-123",
        "kind": "compute#operation",
        "operationType": "patch",
        "progress": "100",
        "zone": "us-east1",
        "status": "RUNNING",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_subnetworks = mocker.Mock()

    mock_compute.subnetworks.return_value = mock_subnetworks
    mock_subnetworks.get.return_value.execute.return_value = subnet_response
    mock_subnetworks.patch.return_value.execute.return_value = patch_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_compute)

    # Run the function
    result = compute_subnet_update(mock_creds, args)

    # Verify the results
    assert "Flow Logs configuration for subnet test-subnet" in result.readable_output
    assert result.outputs[0] == patch_response

    # Check that the correct API calls were made
    mock_subnetworks.get.assert_called_once_with(project="test-project", region="us-east1", subnetwork="test-subnet")

    mock_subnetworks.patch.assert_called_once_with(
        project="test-project",
        region="us-east1",
        subnetwork="test-subnet",
        body={"enableFlowLogs": True, "fingerprint": "test-fingerprint-123"},
    )


def test_compute_subnet_update_private_access(mocker):
    """
    Given: A GCP subnet that needs private IP Google access enabled
    When: compute_subnet_update is called with enable_private_ip_google_access=true
    Then: The subnet's private IP Google access is enabled
    """
    from GCP import compute_subnet_update

    # Mock data
    args = {
        "project_id": "test-project",
        "region": "us-east1",
        "resource_name": "test-subnet",
        "enable_private_ip_google_access": "true",
    }

    # Expected operation response
    set_response = {
        "id": "operation-456",
        "name": "operation-456",
        "kind": "compute#operation",
        "operationType": "setPrivateIpGoogleAccess",
        "progress": "100",
        "zone": "us-east1",
        "status": "RUNNING",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_subnetworks = mocker.Mock()

    mock_compute.subnetworks.return_value = mock_subnetworks
    mock_subnetworks.setPrivateIpGoogleAccess.return_value.execute.return_value = set_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_compute)

    # Run the function
    result = compute_subnet_update(mock_creds, args)

    # Verify the results
    assert "Private IP Google Access configuration for subnet test-subnet" in result.readable_output
    assert result.outputs[1] == set_response

    # Check that the correct API calls were made
    mock_subnetworks.setPrivateIpGoogleAccess.assert_called_once_with(
        project="test-project", region="us-east1", subnetwork="test-subnet", body={"privateIpGoogleAccess": True}
    )


#
# def test_compute_instance_metadata_add_new_item(mocker):
#     """
#     Given: Project metadata needs to be updated with a new key-value pair
#     When: compute_instance_metadata_add is called with new metadata
#     Then: The function should add the new item to existing metadata and call setMetadata with the updated list
#     """
#     from GCP import compute_instance_metadata_add
#
#     # Mock arguments
#     args = {
#         "project_id": "test-project",
#         "zone": "us-central1-c",
#         "resource_name": "gke-test-instance",
#         "metadata": "key=enable-oslogin,value=true",
#     }
#
#     # Mock credentials
#     mock_creds = mocker.Mock(spec=Credentials)
#
#     # Setup mock instance and response
#     mock_instance = {
#         "metadata": {"fingerprint": "test-fingerprint", "items": [{"key": "existing-key", "value": "existing-value"}]}
#     }
#
#     mock_response = {"id": "operation-123", "name": "operation-name", "status": "RUNNING"}
#
#     # Use MagicMock for compute
#     mock_compute = MagicMock()
#     mock_compute.instances().get().execute.return_value = mock_instance
#     mock_compute.instances().setMetadata().execute.return_value = mock_response
#
#     mocker.patch("GCP.build", return_value=mock_compute)
#
#     # Execute the function
#     result = compute_instance_metadata_add(mock_creds, args)
#
#     # Check call to setMetadata with correct body
#     called_args, called_kwargs = mock_compute.instances().setMetadata.call_args
#
#     assert called_kwargs["project"] == "test-project"
#     assert called_kwargs["zone"] == "us-central1-c"
#     assert called_kwargs["instance"] == "gke-test-instance"
#
#     # Check body has expected items
#     body = called_kwargs["body"]
#     assert body["fingerprint"] == "test-fingerprint"
#
#     # Convert items to dict for easier comparison
#     items_dict = {item["key"]: item["value"] for item in body["items"]}
#     assert items_dict["existing-key"] == "existing-value"
#     assert items_dict["enable-oslogin"] == "true"
#
#     # Check outputs
#     assert result.outputs_prefix == "GCP.Compute.Operations"
#     assert result.outputs == mock_response
#
#
# def test_compute_instance_metadata_add_update_existing(mocker):
#     """
#     Given: Project metadata needs to be updated where a key already exists
#     When: compute_instance_metadata_add is called with metadata containing an existing key
#     Then: The function should update the value of the existing key and preserve other metadata
#     """
#     from GCP import compute_instance_metadata_add
#
#     # Mock arguments
#     args = {
#         "project_id": "test-project",
#         "zone": "us-central1-c",
#         "resource_name": "gke-test-instance",
#         "metadata": "key=enable-oslogin,value=false;key=new-key,value=new-value",
#     }
#
#     # Mock credentials
#     mock_creds = mocker.Mock(spec=Credentials)
#
#     # Setup mock instance and response
#     mock_instance = {
#         "metadata": {
#             "fingerprint": "test-fingerprint",
#             "items": [{"key": "enable-oslogin", "value": "true"}, {"key": "existing-key", "value": "existing-value"}],
#         }
#     }
#
#     mock_response = {"id": "operation-123", "name": "operation-name", "status": "RUNNING"}
#
#     # Use MagicMock for compute
#     mock_compute = MagicMock()
#     mock_compute.instances().get().execute.return_value = mock_instance
#     mock_compute.instances().setMetadata().execute.return_value = mock_response
#
#     mocker.patch("GCP.build", return_value=mock_compute)
#
#     # Execute the function
#     result = compute_instance_metadata_add(mock_creds, args)
#
#     # Check body has expected items
#     called_args, called_kwargs = mock_compute.instances().setMetadata.call_args
#     body = called_kwargs["body"]
#
#     # Convert items to dict for easier comparison
#     items_dict = {item["key"]: item["value"] for item in body["items"]}
#     assert items_dict["enable-oslogin"] == "false"  # Should be updated
#     assert items_dict["existing-key"] == "existing-value"  # Should remain unchanged
#     assert items_dict["new-key"] == "new-value"  # Should be added
#
#     assert result.outputs == mock_response


def test_container_cluster_security_update_master_auth_networks(mocker):
    """
    Given: A GKE cluster needs to update its master authorized networks
    When: container_cluster_security_update is called with enable_master_authorized_networks and CIDRs
    Then: The function should make an API call with the correct CIDR blocks configuration
    """
    from GCP import container_cluster_security_update

    # Mock arguments
    args = {
        "project_id": "test-project",
        "region": "us-central1-c",
        "resource_name": "test-cluster-1",
        "enable_master_authorized_networks": "true",
        "cidrs": "192.168.0.0/24,10.0.0.0/32",
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Mock response
    mock_response = {"name": "operation-123", "status": "RUNNING"}

    # Use MagicMock for container
    mock_container = MagicMock()
    mock_container.projects().locations().clusters().update().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_container)

    # Execute the function
    result = container_cluster_security_update(mock_creds, args)

    # Verify correct parameters were used
    called_args, called_kwargs = mock_container.projects().locations().clusters().update.call_args

    assert called_kwargs["name"] == "projects/test-project/locations/us-central1-c/clusters/test-cluster-1"

    # Check body contents
    body = called_kwargs["body"]
    auth_networks_config = body["update"]["desiredControlPlaneEndpointsConfig"]["ipEndpointsConfig"]["authorizedNetworksConfig"]
    assert auth_networks_config["enabled"] is True

    # Check CIDR blocks
    cidr_blocks = auth_networks_config["cidrBlocks"]
    assert len(cidr_blocks) == 2
    assert {"cidrBlock": "192.168.0.0/24"} in cidr_blocks
    assert {"cidrBlock": "10.0.0.0/32"} in cidr_blocks

    assert result.outputs == mock_response


def test_storage_bucket_metadata_update_enable_both_settings(mocker):
    """
    Given: A GCS bucket needs both versioning and uniform access settings updated
    When: storage_bucket_metadata_update is called with both settings
    Then: The function should call bucket.Patch with both settings configured correctly
    """
    from GCP import storage_bucket_metadata_update

    # Mock arguments
    args = {
        "project_id": "test-project",
        "resource_name": "test-bucket",
        "enable_versioning": "true",
        "enable_uniform_access": "false",
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Mock response
    mock_response = {
        "name": "test-bucket",
        "id": "bucket-123",
        "kind": "storage#bucket",
        "selfLink": "https://storage.googleapis.com/storage/v1/b/test-bucket",
        "projectNumber": "123456",
        "updated": "2023-01-01T00:00:00Z",
        "location": "us-central1",
        "versioning": {"enabled": True},
        "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
    }

    # Use MagicMock for storage
    mock_storage = MagicMock()
    mock_storage.buckets().patch().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_storage)

    # Execute the function
    result = storage_bucket_metadata_update(mock_creds, args)

    # Verify correct parameters were used
    called_args, called_kwargs = mock_storage.buckets().patch.call_args

    assert called_kwargs["bucket"] == "test-bucket"

    # Check body contents
    body = called_kwargs["body"]
    assert body["versioning"]["enabled"] is True
    assert body["iamConfiguration"]["uniformBucketLevelAccess"]["enabled"] is False

    # Check outputs
    assert result.outputs_prefix == "GCP.StorageBucket.Metadata"
    assert result.outputs == mock_response
    assert result.outputs_key_field == "name"


def test_compute_instance_service_account_set(mocker):
    """
    Given: A VM instance that needs a service account assigned
    When: compute_instance_service_account_set is called with service_account_email and scopes
    Then: The function should call setServiceAccount with the proper email and scopes
    """
    from GCP import compute_instance_service_account_set

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "test-instance",
        "service_account_email": "service-account@test-project.iam.gserviceaccount.com",
        "scopes": "https://www.googleapis.com/auth/compute,https://www.googleapis.com/auth/devstorage.read_only",
    }

    # Mock response
    mock_response = {
        "id": "operation-123",
        "name": "operation-123",
        "operationType": "setServiceAccount",
        "progress": "100",
        "zone": "us-central1-c",
        "status": "RUNNING",
    }

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().setServiceAccount().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_compute)
    mocker.patch("GCP.tableToMarkdown", return_value="mocked markdown")

    # Execute the function
    result = compute_instance_service_account_set(mock_creds, args)

    # Verify correct parameters were used
    called_args, called_kwargs = mock_compute.instances().setServiceAccount.call_args

    assert called_kwargs["project"] == "test-project"
    assert called_kwargs["zone"] == "us-central1-c"
    assert called_kwargs["instance"] == "test-instance"

    # Check that email and scopes are set correctly
    body = called_kwargs["body"]
    assert body["email"] == "service-account@test-project.iam.gserviceaccount.com"
    assert body["scopes"] == ["https://www.googleapis.com/auth/compute", "https://www.googleapis.com/auth/devstorage.read_only"]

    # Check outputs
    assert result.outputs_prefix == "GCP.Compute.Operations"
    assert result.outputs == mock_response


def test_compute_instance_service_account_set_empty_scopes(mocker):
    """
    Given: A VM instance that needs a service account assigned with empty scopes
    When: compute_instance_service_account_set is called with only a service_account_email
    Then: The function should call setServiceAccount with the email and empty scopes list
    """
    from GCP import compute_instance_service_account_set

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "test-instance",
        "service_account_email": "service-account@test-project.iam.gserviceaccount.com",
    }

    # Mock response
    mock_response = {
        "id": "operation-123",
        "name": "operation-123",
        "operationType": "setServiceAccount",
        "progress": "100",
        "zone": "us-central1-c",
        "status": "RUNNING",
    }

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().setServiceAccount().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_compute)
    mocker.patch("GCP.tableToMarkdown", return_value="mocked markdown")

    # Execute the function
    result = compute_instance_service_account_set(mock_creds, args)

    # Verify correct parameters were used
    called_args, called_kwargs = mock_compute.instances().setServiceAccount.call_args

    # Check that email is set correctly and scopes is an empty list
    body = called_kwargs["body"]
    assert body["email"] == "service-account@test-project.iam.gserviceaccount.com"
    assert body["scopes"] == []

    # Check outputs
    assert result.outputs_prefix == "GCP.Compute.Operations"
    assert result.outputs == mock_response


def test_compute_instance_service_account_remove(mocker):
    """
    Given: A VM instance that has a service account attached
    When: compute_instance_service_account_remove is called
    Then: The function should call setServiceAccount with an empty email and scopes
    """
    from GCP import compute_instance_service_account_remove

    # Mock arguments
    args = {"project_id": "test-project", "zone": "us-central1-c", "resource_name": "test-instance"}

    # Mock response
    mock_response = {
        "id": "operation-123",
        "name": "operation-123",
        "operationType": "setServiceAccount",
        "progress": "100",
        "zone": "us-central1-c",
        "status": "RUNNING",
    }

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().setServiceAccount().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_compute)
    mocker.patch("GCP.tableToMarkdown", return_value="mocked markdown")

    # Execute the function
    result = compute_instance_service_account_remove(mock_creds, args)

    # Verify correct parameters were used
    called_args, called_kwargs = mock_compute.instances().setServiceAccount.call_args

    assert called_kwargs["project"] == "test-project"
    assert called_kwargs["zone"] == "us-central1-c"
    assert called_kwargs["instance"] == "test-instance"

    # Check that email and scopes are empty
    body = called_kwargs["body"]
    assert body["email"] == ""
    assert body["scopes"] == []

    # Check outputs
    assert result.outputs_prefix == "GCP.Compute.Operations"
    assert result.outputs == mock_response


def test_iam_project_policy_binding_remove(mocker):
    """
    Given: A GCP project with an IAM policy that has members assigned to roles
    When: iam_project_policy_binding_remove is called to remove a member from a specific role
    Then: The function should call setIamPolicy with the updated policy
    """
    from GCP import iam_project_policy_binding_remove

    # Mock arguments
    args = {"project_id": "test-project", "member": "user:test@example.com,serviceAccount:sa@example.com", "role": "roles/editor"}

    # Mock policy response with multiple roles and members
    mock_policy = {
        "bindings": [
            {
                "role": "roles/editor",
                "members": ["user:test@example.com", "serviceAccount:sa@example.com", "user:keep@example.com"],
            },
            {"role": "roles/viewer", "members": ["user:test@example.com", "user:other@example.com"]},
        ],
        "etag": "BwWKmjvelug=",
    }

    # Use MagicMock for resource manager
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().getIamPolicy().execute.return_value = mock_policy
    mock_resource_manager.projects().setIamPolicy().execute.return_value = {}

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function
    result = iam_project_policy_binding_remove(mock_creds, args)

    # Verify getIamPolicy was called correctly
    get_policy_args = mock_resource_manager.projects().getIamPolicy.call_args[1]
    assert get_policy_args["resource"] == "projects/test-project"

    # Verify setIamPolicy was called with modified policy
    set_policy_args, set_policy_kwargs = mock_resource_manager.projects().setIamPolicy.call_args
    updated_policy = set_policy_kwargs["body"]["policy"]

    # Check that the members were removed from the editor role but kept in viewer role
    editor_role = next(binding for binding in updated_policy["bindings"] if binding["role"] == "roles/editor")
    viewer_role = next(binding for binding in updated_policy["bindings"] if binding["role"] == "roles/viewer")

    assert "user:test@example.com" not in editor_role["members"]
    assert "serviceAccount:sa@example.com" not in editor_role["members"]
    assert "user:keep@example.com" in editor_role["members"]
    assert "user:test@example.com" in viewer_role["members"]  # Should still be in other roles

    # Check readable output
    assert "`user:test@example.com`" in result.readable_output
    assert "`serviceAccount:sa@example.com`" in result.readable_output
    assert "successfully removed" in result.readable_output


# The following commands are currently unsupported:
# def test_iam_project_deny_policy_create(mocker):
#     """
#     Given: A GCP project that needs a deny policy created
#     When: iam_project_deny_policy_create is called with policy details
#     Then: The function should call createPolicy with the correct configuration
#     """
#     from GCP import iam_project_deny_policy_create
#
#     # Mock arguments
#     args = {
#         "project_id": "test-project",
#         "policy_id": "test-deny-policy",
#         "display_name": "Test Deny Policy",
#         "denied_principals": "user:test@example.com,serviceAccount:sa@example.com",
#         "denied_permissions": "compute.instances.create,compute.instances.delete",
#     }
#
#     # Mock response
#     mock_response = {
#         "name": "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Ftest-project/denypolicies/test-deny-policy",
#         "displayName": "Test Deny Policy",
#         "createTime": "2023-08-15T12:00:00Z",
#         "updateTime": "2023-08-15T12:00:00Z",
#         "rules": [
#             {
#                 "denyRule": {
#                     "deniedPrincipals": ["user:test@example.com", "serviceAccount:sa@example.com"],
#                     "deniedPermissions": ["compute.instances.create", "compute.instances.delete"],
#                 }
#             }
#         ],
#     }
#
#     # Use MagicMock for IAM
#     mock_iam = MagicMock()
#     mock_iam.policies().createPolicy().execute.return_value = mock_response
#
#     # Mock the build function
#     mock_creds = mocker.Mock(spec=Credentials)
#     mocker.patch("GCP.build", return_value=mock_iam)
#
#     # Execute the function
#     result = iam_project_deny_policy_create(mock_creds, args)
#
#     # Verify createPolicy was called with correct parameters
#     call_args, call_kwargs = mock_iam.policies().createPolicy.call_args
#
#     assert call_kwargs["parent"] == "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Ftest-project/denypolicies"
#     assert call_kwargs["policyId"] == "test-deny-policy"
#
#     body = call_kwargs["body"]
#     assert body["displayName"] == "Test Deny Policy"
#     assert body["rules"][0]["denyRule"]["deniedPrincipals"] == ["user:test@example.com", "serviceAccount:sa@example.com"]
#     assert body["rules"][0]["denyRule"]["deniedPermissions"] == ["compute.instances.create", "compute.instances.delete"]
#
#     # Check outputs
#     assert result.outputs_prefix == "GCP.IAM.DenyPolicy"
#     assert result.outputs == mock_response
#     assert "test-deny-policy" in result.readable_output
#     assert "successfully created" in result.readable_output
#
#
# def test_iam_service_account_delete(mocker):
#     """
#     Given: A GCP service account that needs to be deleted
#     When: iam_service_account_delete is called with project_id and service_account_email
#     Then: The function should call serviceAccounts().delete with the correct resource name
#     """
#     from GCP import iam_service_account_delete
#
#     # Mock arguments
#     args = {"project_id": "test-project", "service_account_email": "test-sa@test-project.iam.gserviceaccount.com"}
#
#     # Use MagicMock for IAM
#     mock_iam = MagicMock()
#     mock_iam.projects().serviceAccounts().delete().execute.return_value = {}
#
#     # Mock the build function
#     mock_creds = mocker.Mock(spec=Credentials)
#     mocker.patch("GCP.build", return_value=mock_iam)
#
#     # Execute the function
#     result = iam_service_account_delete(mock_creds, args)
#
#     # Verify delete was called with correct name
#     call_args, call_kwargs = mock_iam.projects().serviceAccounts().delete.call_args
#
#     assert call_kwargs["name"] == "projects/test-project/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com"
#
#     # Check readable output
#     assert "test-sa@test-project.iam.gserviceaccount.com" in result.readable_output
#     assert "successfully deleted" in result.readable_output
#
#
# def test_iam_group_membership_delete(mocker):
#     """
#     Given: A Google Cloud Identity group with a member that needs to be removed
#     When: iam_group_membership_delete is called with group_id and membership_id
#     Then: The function should call memberships().delete with the correct membership name
#     """
#     from GCP import iam_group_membership_delete
#
#     # Mock arguments
#     args = {"group_id": "01abc123def456", "membership_id": "member789ghi"}
#
#     # Use MagicMock for Cloud Identity
#     mock_cloud_identity = MagicMock()
#     mock_cloud_identity.groups().memberships().delete().execute.return_value = {}
#
#     # Mock the build function
#     mock_creds = mocker.Mock(spec=Credentials)
#     mocker.patch("GCP.build", return_value=mock_cloud_identity)
#
#     # Execute the function
#     result = iam_group_membership_delete(mock_creds, args)
#
#     # Verify delete was called with correct name
#     call_args, call_kwargs = mock_cloud_identity.groups().memberships().delete.call_args
#
#     assert call_kwargs["name"] == "groups/01abc123def456/memberships/member789ghi"
#
#     # Check readable output
#     assert "Membership member789ghi was deleted from group 01abc123def456" in result.readable_output


def test_check_required_permissions_all_granted(mocker):
    """
    Given: GCP credentials with all required permissions
    When: check_required_permissions is called without specifying a command
    Then: The function should return None, indicating all permissions are granted
    """
    from GCP import check_required_permissions, COMMAND_REQUIREMENTS

    # Get all permissions that need to be tested
    all_permissions = list({p for _, perms in COMMAND_REQUIREMENTS.values() for p in perms})
    testable_permissions = [p for p in all_permissions if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - all permissions granted
    mock_response = {"permissions": testable_permissions}

    # Mock validate_apis_enabled to return empty list (no disabled APIs)
    mocker.patch("GCP.validate_apis_enabled", return_value=[])

    # Use MagicMock for resource manager
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().testIamPermissions().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function
    result = check_required_permissions(mock_creds, "test-project")

    # Verify testIamPermissions was called with all permissions
    test_perms_args, test_perms_kwargs = mock_resource_manager.projects().testIamPermissions.call_args

    assert test_perms_kwargs["resource"] == "projects/test-project"
    assert set(test_perms_kwargs["body"]["permissions"]) == set(testable_permissions)

    # Function should return None when all permissions are granted
    assert result is None


def test_check_required_permissions_for_specific_command(mocker):
    """
    Given: GCP credentials when checking permissions for a specific command
    When: check_required_permissions is called with a specific command
    Then: The function should only check permissions required for that command
    """
    from GCP import check_required_permissions, COMMAND_REQUIREMENTS

    # Check permissions for a specific command
    command = "gcp-compute-firewall-patch"
    _, required_perms = COMMAND_REQUIREMENTS[command]
    testable_permissions = [p for p in required_perms if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - all permissions granted
    mock_response = {"permissions": testable_permissions}

    # Mock validate_apis_enabled to return empty list (no disabled APIs)
    mocker.patch("GCP.validate_apis_enabled", return_value=[])

    # Use MagicMock for resource manager
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().testIamPermissions().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function
    result = check_required_permissions(mock_creds, "test-project", command=command)

    # Verify testIamPermissions was called with only the required permissions for this command
    test_perms_args, test_perms_kwargs = mock_resource_manager.projects().testIamPermissions.call_args

    assert test_perms_kwargs["resource"] == "projects/test-project"
    assert set(test_perms_kwargs["body"]["permissions"]) == set(testable_permissions)

    # Function should return None when all permissions are granted
    assert result is None


def test_check_required_permissions_missing_permissions(mocker):
    """
    Given: GCP credentials missing some required permissions
    When: check_required_permissions is called
    Then: The function should raise DemistoException with missing permissions
    """
    from GCP import check_required_permissions, COMMAND_REQUIREMENTS, DemistoException

    # Get all permissions that need to be tested
    all_permissions = list({p for _, perms in COMMAND_REQUIREMENTS.values() for p in perms})
    testable_permissions = [p for p in all_permissions if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - some permissions are missing
    granted_permissions = testable_permissions[:-2]  # All except the last two
    missing_permissions = testable_permissions[-2:]  # Just the last two permissions

    mock_response = {"permissions": granted_permissions}

    # Mock validate_apis_enabled to return empty list (no disabled APIs)
    mocker.patch("GCP.validate_apis_enabled", return_value=[])

    # Use MagicMock for resource manager
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().testIamPermissions().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function and expect an exception
    with pytest.raises(DemistoException) as e:
        check_required_permissions(mock_creds, "test-project")

    # Verify that the error message contains the missing permissions
    for missing_perm in missing_permissions:
        assert missing_perm in str(e.value)
    assert "Missing required permissions" in str(e.value)


def test_validate_apis_enabled_all_enabled(mocker):
    """
    Given: A GCP project with all required APIs enabled
    When: validate_apis_enabled is called with a list of API endpoints
    Then: The function should return an empty list indicating all APIs are enabled
    """
    from GCP import validate_apis_enabled

    # Mock credentials and project
    mock_creds = mocker.Mock(spec=Credentials)
    project_id = "test-project"
    apis = ["compute.googleapis.com", "storage.googleapis.com"]

    # Mock API responses showing enabled state
    mock_service_usage = mocker.MagicMock()
    mock_service_usage.services().get().execute.return_value = {"state": "ENABLED"}

    mocker.patch("GCP.GCPServices.SERVICE_USAGE.build", return_value=mock_service_usage)

    # Execute the function
    result = validate_apis_enabled(mock_creds, project_id, apis)

    # Verify all APIs were checked
    assert mock_service_usage.services().get.call_count == 3

    # Verify correct API names were used
    call_args_list = mock_service_usage.services().get.call_args_list
    assert call_args_list[1][1]["name"] == "projects/test-project/services/compute.googleapis.com"
    assert call_args_list[2][1]["name"] == "projects/test-project/services/storage.googleapis.com"

    # Should return empty list when all APIs are enabled
    assert result == []


def test_validate_apis_enabled_some_disabled(mocker):
    """
    Given: A GCP project with some APIs disabled and some enabled
    When: validate_apis_enabled is called with a list of API endpoints
    Then: The function should return a list of disabled API endpoints
    """
    from GCP import validate_apis_enabled

    # Mock credentials and project
    mock_creds = mocker.Mock(spec=Credentials)
    project_id = "test-project"
    apis = ["compute.googleapis.com", "storage.googleapis.com", "container.googleapis.com"]

    # Mock API responses with mixed states
    def mock_api_response(name, **kwargs):
        if "compute" in name:
            return mocker.MagicMock(**{"execute.return_value": {"state": "ENABLED"}})
        elif "storage" in name:
            return mocker.MagicMock(**{"execute.return_value": {"state": "DISABLED"}})
        else:  # container
            return mocker.MagicMock(**{"execute.return_value": {"state": "SUSPENDED"}})

    mock_service_usage = mocker.MagicMock()
    mock_service_usage.services().get.side_effect = mock_api_response

    mocker.patch("GCP.GCPServices.SERVICE_USAGE.build", return_value=mock_service_usage)

    # Execute the function
    result = validate_apis_enabled(mock_creds, project_id, apis)

    expected_disabled_apis = {"storage.googleapis.com", "container.googleapis.com"}
    assert set(result) == expected_disabled_apis
    assert len(result) == 2
    assert "compute.googleapis.com" not in set(result)


def test_validate_apis_enabled_api_check_fails(mocker):
    """
    Given: A GCP project where API status checks fail with exceptions
    When: validate_apis_enabled is called and some API checks raise exceptions
    Then: The function should treat failed checks as disabled APIs and include them in the result
    """
    from GCP import validate_apis_enabled

    # Mock credentials and project
    mock_creds = mocker.Mock(spec=Credentials)
    project_id = "test-project"
    apis = ["compute.googleapis.com", "storage.googleapis.com"]

    # Mock API responses with one success and one failure
    def mock_api_response(name, **kwargs):
        if "compute" in name:
            return mocker.MagicMock(**{"execute.return_value": {"state": "ENABLED"}})
        else:  # storage - will raise exception
            mock_response = mocker.MagicMock()
            mock_response.execute.side_effect = Exception("API access denied")
            return mock_response

    mock_service_usage = mocker.MagicMock()
    mock_service_usage.services().get.side_effect = mock_api_response

    mocker.patch("GCP.GCPServices.SERVICE_USAGE.build", return_value=mock_service_usage)

    # Execute the function
    result = validate_apis_enabled(mock_creds, project_id, apis)

    assert set(result) == {"storage.googleapis.com"}
    assert "compute.googleapis.com" not in set(result)


def test_validate_apis_enabled_service_usage_unavailable(mocker):
    """
    Given: A GCP project where the Service Usage API itself is unavailable
    When: validate_apis_enabled is called and building the service fails
    Then: The function should return an empty list to skip validation
    """
    from GCP import validate_apis_enabled

    # Mock credentials and project
    mock_creds = mocker.Mock(spec=Credentials)
    project_id = "test-project"
    apis = ["compute.googleapis.com", "storage.googleapis.com"]

    # Mock Service Usage API build failure
    mocker.patch("GCP.GCPServices.SERVICE_USAGE.build", side_effect=Exception("Service Usage API not available"))

    # Execute the function
    result = validate_apis_enabled(mock_creds, project_id, apis)

    # Should return empty list when Service Usage API is unavailable
    assert result == []


def test_health_check_successful(mocker):
    """
    Given: Valid GCP credentials and a project with accessible services
    When: health_check is called with proper shared credentials
    Then: The function should return None indicating successful connectivity
    """
    from GCP import health_check

    # Mock shared credentials
    shared_creds = {"access_token": "valid-token-123"}
    project_id = "test-project"
    connector_id = "connector-123"

    # Mock successful service tests
    mock_service_results = [
        ("compute", True, ""),
        ("storage", True, ""),
        ("container", True, ""),
    ]

    mocker.patch("GCP.GCPServices.test_all_services", return_value=mock_service_results)

    # Execute the function
    result = health_check(shared_creds, project_id, connector_id)

    # Should return None for successful health check
    assert result is None


def test_health_check_missing_token(mocker):
    """
    Given: Shared credentials that are missing the access token
    When: health_check is called with invalid credentials
    Then: The function should return a HealthCheckError with connectivity error type
    """
    from GCP import health_check

    # Mock shared credentials without token
    shared_creds = {"some_other_field": "value"}
    project_id = "test-project"
    connector_id = "connector-123"

    # Execute the function
    result = health_check(shared_creds, project_id, connector_id)

    # Should return HealthCheckError for missing token
    assert result is not None
    assert result.account_id == project_id
    assert result.connector_id == connector_id
    assert "token is missing from credentials" in result.message
    assert result.error_type == "Connectivity Error"


def test_health_check_service_connectivity_failure(mocker):
    """
    Given: Valid credentials but GCP services are not accessible
    When: health_check is called and service tests fail with non-permission errors
    Then: The function should return a HealthCheckError indicating connectivity issues
    """
    from GCP import health_check

    # Mock shared credentials
    shared_creds = {"access_token": "valid-token-123"}
    project_id = "test-project"
    connector_id = "connector-123"

    # Mock service test failure (non-permission related)
    mock_service_results = [
        ("compute", True, ""),
        ("storage", False, "Network timeout occurred"),
        ("container", True, ""),
    ]

    mocker.patch("GCP.GCPServices.test_all_services", return_value=mock_service_results)

    # Execute the function
    result = health_check(shared_creds, project_id, connector_id)

    # Should return HealthCheckError for service connectivity failure
    assert result is not None
    assert result.account_id == project_id
    assert result.connector_id == connector_id
    assert "Sample check failed" in result.message
    assert "Network timeout occurred" in result.message
    assert result.error_type == "Connectivity Error"


def test_health_check_service_permission_failure_ignored(mocker):
    """
    Given: Valid credentials but services fail with permission-related errors
    When: health_check is called and service tests fail with permission errors
    Then: The function should return None as permission errors are expected and ignored
    """
    from GCP import health_check

    # Mock shared credentials
    shared_creds = {"access_token": "valid-token-123"}
    project_id = "test-project"
    connector_id = "connector-123"

    # Mock service test failure (permission related - should be ignored)
    mock_service_results = [
        ("compute", True, ""),
        ("storage", False, "Permission denied for storage.buckets.list"),
        ("container", False, "Insufficient Permission to access container API"),
    ]

    mocker.patch("GCP.GCPServices.test_all_services", return_value=mock_service_results)

    # Execute the function
    result = health_check(shared_creds, project_id, connector_id)

    # Should return None as permission errors are ignored in health checks
    assert result is None


def test_health_check_credentials_creation_failure(mocker):
    """
    Given: Shared credentials that cause an exception during Credentials object creation
    When: health_check is called and credential creation fails
    Then: The function should return a HealthCheckError with the exception details
    """
    from GCP import health_check

    # Mock shared credentials
    shared_creds = {"access_token": "invalid-token"}
    project_id = "test-project"
    connector_id = "connector-123"

    # Mock Credentials creation failure
    mocker.patch("GCP.Credentials", side_effect=ValueError("Invalid token format"))

    # Execute the function
    result = health_check(shared_creds, project_id, connector_id)

    # Should return HealthCheckError for credential creation failure
    assert result is not None
    assert result.account_id == project_id
    assert result.connector_id == connector_id
    assert "Invalid token format" in result.message
    assert result.error_type == "Connectivity Error"


def test_parse_labels_valid_2_inputs():
    """
    Given: A valid labels string with multiple labels
    When: parse_labels is called
    Then: The function returns a correctly parsed dictionary
    """
    from GCP import parse_labels

    input_str = "key=label1,value=true;key=label2,value=false"
    expected = {"label1": "true", "label2": "false"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_valid_1_input():
    """
    Given: A valid labels string with a single label
    When: parse_labels is called
    Then: The function returns a correctly parsed dictionary
    """
    from GCP import parse_labels

    input_str_option1 = "key=label1,value=true;"
    input_str_option2 = "key=label1,value=true"
    expected_option1 = {
        "label1": "true",
    }
    expected_option2 = {
        "label1": "true",
    }

    result_option1 = parse_labels(input_str_option1)
    result_option2 = parse_labels(input_str_option2)
    assert result_option1 == expected_option1
    assert result_option2 == expected_option2


def test_handle_permission_error_valid_json_with_matching_permission(mocker):
    """
    Given: An HttpError with JSON content containing a permission error that matches command requirements
    When: handle_permission_error is called with the error
    Then: The function should extract permission info and call return_multiple_permissions_error
    """
    from GCP import handle_permission_error
    from googleapiclient.errors import HttpError
    import json

    command_name = "gcp-compute-instance-labels-set"

    # Create mock HTTP response
    mock_resp = mocker.MagicMock()
    mock_resp.status = 403
    mock_resp.get.return_value = "application/json"

    error_content = {
        "error": {
            "errors": [{"reason": "forbidden"}],
            "message": "Required 'compute.instances.setLabels' permission for "
            "'projects/project/zones/zone/instances/instance_number'",
        }
    }

    # Create HttpError with mocked content
    http_error = HttpError(mock_resp, json.dumps(error_content).encode())

    # Mock demisto functions
    mocker.patch("GCP.demisto.debug")
    mock_return_error = mocker.patch("GCP.return_multiple_permissions_error")

    # Execute the function
    handle_permission_error(http_error, "test-project", command_name)

    # Verify return_multiple_permissions_error was called with correct parameters
    mock_return_error.assert_called_once()
    error_entries = mock_return_error.call_args[0][0]

    assert len(error_entries) == 1
    assert error_entries[0]["account_id"] == "test-project"
    assert error_entries[0]["name"] == "compute.instances.setLabels"
    assert "compute.instances.setLabels" in error_entries[0]["message"]


def test_handle_permission_error_valid_json_no_matching_permission(mocker):
    """
    Given: An HttpError with JSON content that doesn't match any command requirements
    When: handle_permission_error is called with the error
    Then: The function should use "N/A" as the permission name
    """
    from GCP import handle_permission_error
    from googleapiclient.errors import HttpError
    import json

    # Mock command requirements
    command_name = "gcp-compute-firewall-patch"

    # Create mock HTTP response
    mock_resp = mocker.MagicMock()
    mock_resp.status = 403
    mock_resp.get.return_value = "application/json"

    error_content = {"error": {"errors": [{"reason": "forbidden"}], "message": "Access denied for unknown resource"}}

    # Create HttpError with mocked content
    http_error = HttpError(mock_resp, json.dumps(error_content).encode())

    # Mock demisto functions
    mocker.patch("GCP.demisto.debug")
    mock_return_error = mocker.patch("GCP.return_multiple_permissions_error")

    # Execute the function
    handle_permission_error(http_error, "test-project", command_name)

    # Verify return_multiple_permissions_error was called with N/A permission
    error_entries = mock_return_error.call_args[0][0]

    assert len(error_entries) == 1
    assert error_entries[0]["account_id"] == "test-project"
    assert error_entries[0]["name"] == "N/A"
    assert "Access denied for unknown resource" in error_entries[0]["message"]


def test_handle_permission_error_multiple_matching_permissions(mocker):
    """
    Given: An HttpError with JSON content containing multiple permissions that match command requirements
    When: handle_permission_error is called with the error
    Then: The function should extract all matching permissions and create multiple error entries
    """
    from GCP import handle_permission_error
    from googleapiclient.errors import HttpError
    import json

    # Mock command requirements with multiple permissions
    command_name = "gcp-compute-firewall-patch"

    # Create mock HTTP response
    mock_resp = mocker.MagicMock()
    mock_resp.status = 403
    mock_resp.get.return_value = "application/json"

    error_content = {
        "error": {
            "errors": [{"reason": "forbidden"}],
            "message": "Required 'compute.firewalls.update' and compute.firewalls.get' permissions for project.",
        }
    }

    # Create HttpError with mocked content
    http_error = HttpError(mock_resp, json.dumps(error_content).encode())

    # Mock demisto functions
    mocker.patch("GCP.demisto.debug")
    mock_return_error = mocker.patch("GCP.return_multiple_permissions_error")

    # Execute the function
    handle_permission_error(http_error, "test-project", command_name)

    # Verify return_multiple_permissions_error was called with multiple permissions
    error_entries = mock_return_error.call_args[0][0]

    assert len(error_entries) == 2
    permission_names = [entry["name"] for entry in error_entries]
    assert "compute.firewalls.get" in permission_names
    assert "compute.firewalls.update" in permission_names

    for entry in error_entries:
        assert entry["account_id"] == "test-project"
        assert entry["message"] == "Required 'compute.firewalls.update' and compute.firewalls.get' permissions for project."


def test_handle_permission_error_non_json_content_type(mocker):
    """
    Given: An HttpError with non-JSON content type
    When: handle_permission_error is called with the error
    Then: The function should re-raise the original HttpError
    """
    from GCP import handle_permission_error
    from googleapiclient.errors import HttpError

    # Create mock HTTP response with non-JSON content
    mock_resp = mocker.MagicMock()
    mock_resp.status = 403
    mock_resp.get.return_value = "text/html"

    # Create HttpError
    http_error = HttpError(mock_resp, b"<html>Error page</html>")

    # Mock demisto functions
    mocker.patch("GCP.demisto.debug")

    # Execute the function and expect the same error to be raised
    with pytest.raises(SystemExit) as exc_info:
        handle_permission_error(http_error, "test-project", "some-command")

    # Verify there was a graceful exist
    assert exc_info.typename == "SystemExit"
    assert exc_info.value.code == 0


def test_handle_permission_error_missing_error_structure(mocker):
    """
    Given: An HttpError with valid JSON but missing expected error structure
    When: handle_permission_error is called with the error
    Then: The function should handle missing keys gracefully
    """
    from GCP import handle_permission_error
    from googleapiclient.errors import HttpError
    import json

    # Mock command requirements
    command_name = "gcp-compute-firewall-patch"

    # Create mock HTTP response with incomplete error structure
    mock_resp = mocker.MagicMock()
    mock_resp.status = 403
    mock_resp.get.return_value = "application/json"

    error_content = {
        "error": {
            "errors": [{}],  # Missing 'reason' key
            # Missing 'message' key
        }
    }

    # Create HttpError with mocked content
    http_error = HttpError(mock_resp, json.dumps(error_content).encode())

    # Mock demisto functions
    mocker.patch("GCP.demisto.debug")
    mock_return_error = mocker.patch("GCP.return_multiple_permissions_error")

    # Execute the function and expect a KeyError or similar handling
    # with pytest.raises(SystemExit):
    handle_permission_error(http_error, "test-project", command_name)
    error_entries = mock_return_error.call_args[0][0]

    assert len(error_entries) == 1
    assert error_entries[0]["account_id"] == "test-project"
    assert error_entries[0]["name"] == "N/A"


def test_handle_permission_error_case_insensitive_matching(mocker):
    """
    Given: An HttpError with JSON content containing permissions in different cases
    When: handle_permission_error is called with the error
    Then: The function should match permissions case-insensitively
    """
    from GCP import handle_permission_error
    from googleapiclient.errors import HttpError
    import json

    # Mock command requirements
    command_name = "gcp-compute-firewall-patch"

    # Create mock HTTP response
    mock_resp = mocker.MagicMock()
    mock_resp.status = 403
    mock_resp.get.return_value = "application/json"

    error_content = {
        "error": {"errors": [{"reason": "forbidden"}], "message": "Required 'COMPUTE.FIREWALLS.UPDATE' for the resource"}
    }

    # Create HttpError with mocked content
    http_error = HttpError(mock_resp, json.dumps(error_content).encode())

    # Mock demisto functions
    mocker.patch("GCP.demisto.debug")
    mock_return_error = mocker.patch("GCP.return_multiple_permissions_error")

    # Execute the function
    handle_permission_error(http_error, "test-project", command_name)

    # Verify return_multiple_permissions_error was called with matched permission
    error_entries = mock_return_error.call_args[0][0]

    assert len(error_entries) == 1
    assert error_entries[0]["account_id"] == "test-project"
    assert error_entries[0]["name"] == "compute.firewalls.update"


def test_gcp_compute_instances_list_command_basic_success(mocker):
    """
    Given: Valid credentials and basic arguments
    When: gcp_compute_instances_list_command is called
    Then: The function should return instances list with correct outputs
    """
    from GCP import gcp_compute_instances_list_command

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-a",
    }

    # Mock API response
    mock_response = util_load_json("test_data/list_instances_response.json")

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.list.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instances_list_command(mock_creds, args)

    # Verify API call parameters
    mock_instances.list.assert_called_once_with(
        project="test-project", zone="us-central1-a", filter=None, maxResults=500, orderBy=None, pageToken=None
    )

    # Verify outputs structure
    assert "GCP.Compute.Instances(val.id && val.id == obj.id)" in result.outputs
    assert "GCP.Compute(true)" in result.outputs
    assert len(result.outputs["GCP.Compute.Instances(val.id && val.id == obj.id)"]) == 2


def test_gcp_compute_instances_list_command_with_pagination(mocker):
    """
    Given: Valid arguments with pagination
    When: gcp_compute_instances_list_command is called with page_token
    Then: The function should handle pagination correctly and return next page token
    """
    from GCP import gcp_compute_instances_list_command

    # Mock arguments
    args = {"project_id": "test-project", "zone": "us-central1-a", "limit": 1, "page_token": "current-page-token"}

    # Mock API response with next page token
    mock_response = {
        "kind": "compute#instanceList",
        "items": [
            {
                "id": "123456789",
                "name": "test-instance-1",
                "kind": "compute#instance",
                "creationTimestamp": "2023-01-01T10:00:00.000-07:00",
                "status": "RUNNING",
                "machineType": "projects/test-project/zones/us-central1-a/machineTypes/n1-standard-1",
                "zone": "projects/test-project/zones/us-central1-a",
            }
        ],
        "nextPageToken": "next-page-token-123",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.list.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instances_list_command(mock_creds, args)

    # Verify API call parameters include pagination
    mock_instances.list.assert_called_once_with(
        project="test-project", zone="us-central1-a", filter=None, maxResults=1, orderBy=None, pageToken="current-page-token"
    )

    # Verify pagination handling in outputs
    assert result.outputs["GCP.Compute(true)"]["InstancesNextPageToken"] == "next-page-token-123"
    assert "InstancesNextPageToken" in result.raw_response
    assert "nextPageToken" not in result.raw_response
    assert (
        "Run the following command to retrieve the next batch of instances:\n!gcp-compute-instances-list "
        "project_id=test-project zone=us-central1-a page_token=next-page-token-123 limit=1\n" in result.readable_output
    )


def test_gcp_compute_instances_list_command_with_filters_and_ordering(mocker):
    """
    Given: Valid arguments with filters and ordering
    When: gcp_compute_instances_list_command is called with filters and order_by
    Then: The function should pass filters and ordering to the API call
    """
    from GCP import gcp_compute_instances_list_command

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-a",
        "filters": "status=RUNNING",
        "order_by": "creationTimestamp desc",
        "limit": 100,
    }

    # Mock API response
    mock_response = {
        "kind": "compute#instanceList",
        "items": [
            {
                "id": "123456789",
                "name": "test-instance-1",
                "kind": "compute#instance",
                "creationTimestamp": "2023-01-01T10:00:00.000-07:00",
                "status": "RUNNING",
                "machineType": "projects/test-project/zones/us-central1-a/machineTypes/n1-standard-1",
                "zone": "projects/test-project/zones/us-central1-a",
            }
        ],
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.list.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instances_list_command(mock_creds, args)

    # Verify API call parameters include filters and ordering
    mock_instances.list.assert_called_once_with(
        project="test-project",
        zone="us-central1-a",
        filter="status=RUNNING",
        maxResults=100,
        orderBy="creationTimestamp desc",
        pageToken=None,
    )

    # Verify successful execution
    assert len(result.outputs["GCP.Compute.Instances(val.id && val.id == obj.id)"]) == 1


def test_gcp_compute_instances_list_command_limit_validation_too_high(mocker):
    """
    Given: Arguments with limit greater than 500
    When: gcp_compute_instances_list_command is called
    Then: The function should raise DemistoException
    """
    from GCP import gcp_compute_instances_list_command, DemistoException

    # Mock arguments with invalid limit
    args = {"project_id": "test-project", "zone": "us-central1-a", "limit": "501"}

    mock_creds = mocker.Mock(spec=Credentials)

    # Execute the function and expect exception
    with pytest.raises(DemistoException) as exc_info:
        gcp_compute_instances_list_command(mock_creds, args)

    assert "The acceptable values of the argument limit are 1 to 500" in str(exc_info.value)
    assert "501" in str(exc_info.value)


def test_gcp_compute_instances_list_command_limit_validation_too_low(mocker):
    """
    Given: Arguments with limit less than 1
    When: gcp_compute_instances_list_command is called
    Then: The function should raise DemistoException
    """
    from GCP import gcp_compute_instances_list_command, DemistoException

    # Mock arguments with invalid limit
    args = {"project_id": "test-project", "zone": "us-central1-a", "limit": "0"}

    mock_creds = mocker.Mock(spec=Credentials)

    # Execute the function and expect exception
    with pytest.raises(DemistoException) as exc_info:
        gcp_compute_instances_list_command(mock_creds, args)

    assert "The acceptable values of the argument limit are 1 to 500" in str(exc_info.value)
    assert "0" in str(exc_info.value)


def test_gcp_compute_instances_list_command_empty_response(mocker):
    """
    Given: Valid arguments but no instances found
    When: gcp_compute_instances_list_command is called
    Then: The function should handle empty response gracefully
    """
    from GCP import gcp_compute_instances_list_command

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-a",
    }

    # Mock API response with no instances
    mock_response = {
        "kind": "compute#instanceList",
        "id": "projects/test-project/zones/us-central1-a/instances",
        "items": [],
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/zones/us-central1-a/instances",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.list.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instances_list_command(mock_creds, args)

    # Verify empty results are handled properly
    assert len(result.outputs["GCP.Compute.Instances(val.id && val.id == obj.id)"]) == 0


def test_gcp_compute_instance_get_command_basic_success(mocker):
    """
    Given: Valid credentials and basic arguments for getting an instance
    When: gcp_compute_instance_get_command is called
    Then: The function should return instance details with correct outputs
    """
    from GCP import gcp_compute_instance_get_command

    # Mock arguments
    args = {"project_id": "test-project", "zone": "us-central1-a", "instance": "test-instance-1"}

    # Mock API response
    mock_response = {
        "id": "123456789",
        "name": "test-instance-1",
        "kind": "compute#instance",
        "creationTimestamp": "2023-01-01T10:00:00.000-07:00",
        "description": "Test instance for unit testing",
        "status": "RUNNING",
        "machineType": "projects/test-project/zones/us-central1-a/machineTypes/n1-standard-1",
        "zone": "projects/test-project/zones/us-central1-a",
        "networkInterfaces": [
            {
                "network": "projects/test-project/global/networks/default",
                "subnetwork": "projects/test-project/regions/us-central1/subnetworks/default",
            }
        ],
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.get.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_get_command(mock_creds, args)

    # Verify API call parameters
    mock_instances.get.assert_called_once_with(project="test-project", zone="us-central1-a", instance="test-instance-1")

    # Verify outputs structure
    assert result.outputs_prefix == "GCP.Compute.Instances"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response


def test_gcp_compute_instance_get_command_minimal_response(mocker):
    """
    Given: API response with minimal fields (some optional fields missing)
    When: gcp_compute_instance_get_command is called
    Then: The function should handle missing optional fields gracefully
    """
    from GCP import gcp_compute_instance_get_command

    # Mock arguments
    args = {"project_id": "test-project", "zone": "asia-east1-a", "instance": "minimal-instance"}

    # Mock API response with minimal fields
    mock_response = {
        "id": "555666777",
        "name": "minimal-instance",
        "kind": "compute#instance",
        "status": "PROVISIONING",
        "machineType": "projects/test-project/zones/asia-east1-a/machineTypes/f1-micro",
        # Missing: creationTimestamp, description
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.get.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_get_command(mock_creds, args)

    # Verify API call
    mock_instances.get.assert_called_once_with(project="test-project", zone="asia-east1-a", instance="minimal-instance")

    # Verify outputs handle missing fields
    assert result.outputs == mock_response
    assert result.outputs["id"] == "555666777"
    assert result.outputs["name"] == "minimal-instance"
    assert "creationTimestamp" not in result.outputs
    assert "description" not in result.outputs


def test_gcp_compute_instance_get_command_complete_response(mocker):
    """
    Given: API response with all possible fields populated
    When: gcp_compute_instance_get_command is called
    Then: The function should handle complete response correctly
    """
    from GCP import gcp_compute_instance_get_command

    # Mock arguments
    args = {"project_id": "test-project", "zone": "us-west2-c", "instance": "full-instance"}

    # Mock API response with all fields
    mock_response = {
        "id": "111222333",
        "name": "full-instance",
        "kind": "compute#instance",
        "creationTimestamp": "2023-03-15T08:45:00.000-07:00",
        "description": "Comprehensive test instance with all fields",
        "status": "RUNNING",
        "machineType": "projects/test-project/zones/us-west2-c/machineTypes/n2-standard-4",
        "zone": "projects/test-project/zones/us-west2-c",
        "tags": {"items": ["web-server", "database"]},
        "labels": {"environment": "production", "team": "backend"},
        "metadata": {"items": [{"key": "startup-script", "value": "#!/bin/bash\necho 'Hello World'"}]},
        "disks": [
            {"type": "PERSISTENT", "mode": "READ_WRITE", "source": "projects/test-project/zones/us-west2-c/disks/full-instance"}
        ],
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.get.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_get_command(mock_creds, args)

    # Verify complete response is returned
    assert result.outputs == mock_response
    assert result.outputs["tags"]["items"] == ["web-server", "database"]
    assert result.outputs["labels"]["environment"] == "production"
    assert result.outputs["metadata"]["items"][0]["key"] == "startup-script"


def test_gcp_compute_instance_get_command_table_generation(mocker):
    """
    Given: Valid instance data
    When: gcp_compute_instance_get_command is called
    Then: The function should generate readable output table with correct headers and data
    """
    from GCP import gcp_compute_instance_get_command

    # Mock arguments
    args = {"project_id": "test-project", "zone": "us-east1-b", "instance": "table-test-instance"}

    # Mock API response
    mock_response = {
        "id": "444555666",
        "name": "table-test-instance",
        "kind": "compute#instance",
        "creationTimestamp": "2023-04-10T12:00:00.000-07:00",
        "description": "Instance for table testing",
        "status": "TERMINATED",
        "machineType": "projects/test-project/zones/us-east1-b/machineTypes/g1-small",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.get.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)
    mock_table = mocker.patch("GCP.tableToMarkdown", return_value="Generated table output")
    mock_pascal_to_space = mocker.patch("GCP.pascalToSpace")

    # Execute the function
    result = gcp_compute_instance_get_command(mock_creds, args)

    # Verify tableToMarkdown was called with correct parameters
    mock_table.assert_called_once()
    table_call_args = mock_table.call_args

    # Check table title
    assert table_call_args[0][0] == "GCP Instance table-test-instance from zone us-east1-b"

    # Check table data
    table_data = table_call_args[0][1]
    assert table_data["id"] == "444555666"
    assert table_data["name"] == "table-test-instance"
    assert table_data["status"] == "TERMINATED"

    # Check headers
    expected_headers = ["id", "name", "kind", "creationTimestamp", "description", "status", "machineType"]
    assert table_call_args[1]["headers"] == expected_headers

    # Check other parameters
    assert table_call_args[1]["removeNull"] is True
    assert table_call_args[1]["headerTransform"] == mock_pascal_to_space

    # Verify readable output uses table result
    assert result.readable_output == "Generated table output"


def test_gcp_compute_instance_label_set_command_basic_success(mocker):
    """
    Given: Valid credentials and basic arguments for setting instance labels
    When: gcp_compute_instance_label_set_command is called
    Then: The function should set labels and return operation details with correct outputs
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-a",
        "instance": "test-instance",
        "label_fingerprint": "abc123fingerprint",
        "labels": "key=environment,value=production;key=team,value=backend",
    }

    # Mock API response
    mock_response = {
        "id": "operation-12345",
        "name": "operation-set-labels",
        "kind": "compute#operation",
        "status": "RUNNING",
        "progress": "0",
        "operationType": "setLabels",
        "zone": "projects/test-project/zones/us-central1-a",
        "targetId": "567890",
        "targetLink": "projects/test-project/zones/us-central1-a/instances/test-instance",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.setLabels.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_label_set_command(mock_creds, args)

    # Verify API call parameters
    expected_body = {"labels": {"environment": "production", "team": "backend"}, "labelFingerprint": "abc123fingerprint"}
    mock_instances.setLabels.assert_called_once_with(
        project="test-project", zone="us-central1-a", instance="test-instance", body=expected_body
    )

    # Verify outputs structure
    assert result.outputs_prefix == "GCP.Compute.Operations"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response
    assert result.raw_response == mock_response


def test_gcp_compute_instance_label_set_command_no_labels(mocker):
    """
    Given: Valid arguments with empty labels string
    When: gcp_compute_instance_label_set_command is called
    Then: An exception should be raised for empty labels.
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments with empty labels
    args = {
        "project_id": "test-project",
        "zone": "asia-southeast1-a",
        "instance": "test-instance-3",
        "label_fingerprint": "xyz789fingerprint",
        "labels": "''",
    }

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)

    # Execute the function
    with pytest.raises(ValueError) as e:
        gcp_compute_instance_label_set_command(mock_creds, args)

    assert "Could not parse field" in str(e.value)


def test_gcp_compute_instance_label_set_command_multiple_labels(mocker):
    """
    Given: Valid arguments with multiple complex labels
    When: gcp_compute_instance_label_set_command is called
    Then: The function should parse and set all labels correctly
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments with multiple labels
    args = {
        "project_id": "test-project",
        "zone": "us-east1-c",
        "instance": "multi-label-instance",
        "label_fingerprint": "multi123fingerprint",
        "labels": "key=env,value=staging;key=app,value=frontend;key=version,value=v2.1.0;key=owner,value=team-alpha",
    }

    # Mock API response
    mock_response = {
        "id": "operation-22222",
        "name": "operation-multi-labels",
        "kind": "compute#operation",
        "status": "RUNNING",
        "progress": "25",
        "operationType": "setLabels",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.setLabels.return_value.execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_label_set_command(mock_creds, args)

    # Verify API call with all labels
    expected_body = {
        "labels": {"env": "staging", "app": "frontend", "version": "v2.1.0", "owner": "team-alpha"},
        "labelFingerprint": "multi123fingerprint",
    }
    mock_instances.setLabels.assert_called_once_with(
        project="test-project", zone="us-east1-c", instance="multi-label-instance", body=expected_body
    )

    assert result.outputs == mock_response


def test_gcp_compute_instance_label_set_command_minimal_response(mocker):
    """
    Given: API response with minimal fields
    When: gcp_compute_instance_label_set_command is called
    Then: The function should handle missing optional fields gracefully in data_res
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-b",
        "instance": "minimal-response-instance",
        "label_fingerprint": "minimal123",
        "labels": "key=test,value=minimal",
    }

    # Mock API response with minimal fields
    mock_response = {
        "id": "operation-33333",
        "kind": "compute#operation",
        "status": "DONE",
        # Missing: name, progress, operationType
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.setLabels.return_value.execute.return_value = mock_response

    # Mock the build function and table generation
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)
    mock_table = mocker.patch("GCP.tableToMarkdown", return_value="Generated table")

    # Execute the function
    result = gcp_compute_instance_label_set_command(mock_creds, args)

    # Verify table generation handles missing fields
    mock_table.assert_called_once()
    table_data = mock_table.call_args[0][1]

    assert table_data["id"] == "operation-33333"
    assert table_data["status"] == "DONE"
    assert table_data["kind"] == "compute#operation"
    assert table_data["name"] is None
    assert table_data["progress"] is None
    assert table_data["operationType"] is None

    assert result.readable_output == "Generated table"
    assert result.outputs == mock_response


def test_parse_labels_empty_string():
    """
    Given: An empty labels string
    When: parse_labels is called
    Then: The function returns an empty dictionary
    """
    from GCP import parse_labels

    input_str = ""
    expected = {}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_whitespace_only():
    """
    Given: A labels string with only whitespace
    When: parse_labels is called
    Then: The function returns an empty dictionary
    """
    from GCP import parse_labels

    input_str = "   "
    expected = {}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_single_label_with_trailing_semicolon():
    """
    Given: A valid labels string with a single label and trailing semicolon
    When: parse_labels is called
    Then: The function returns a correctly parsed dictionary
    """
    from GCP import parse_labels

    input_str = "key=environment,value=PRODUCTION;"
    expected = {"environment": "production"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_case_conversion():
    """
    Given: A labels string with mixed case keys and values
    When: parse_labels is called
    Then: The function converts both keys and values to lowercase
    """
    from GCP import parse_labels

    input_str = "key=Environment,value=PRODUCTION;key=TEAM,value=Backend"
    expected = {"environment": "production", "team": "backend"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_special_characters_in_values():
    """
    Given: A labels string with special characters in values
    When: parse_labels is called
    Then: The function handles special characters correctly
    """
    from GCP import parse_labels

    input_str = "key=version,value=v2.1.0;key=branch,value=feature-branch_123"
    expected = {"version": "v2.1.0", "branch": "feature-branch_123"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_empty_segments():
    """
    Given: A labels string with empty segments between semicolons
    When: parse_labels is called
    Then: The function skips empty segments and processes valid ones
    """
    from GCP import parse_labels

    input_str = "key=app,value=web;;key=env,value=test;"
    expected = {"app": "web", "env": "test"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_malformed_missing_key():
    """
    Given: A labels string missing the key part
    When: parse_labels is called
    Then: The function raises a ValueError with appropriate message
    """
    from GCP import parse_labels

    input_str = "value=production"
    with pytest.raises(ValueError) as e:
        parse_labels(input_str)

    assert "Could not parse field" in str(e.value)
    assert "value=production" in str(e.value)
    assert "Please make sure you provided like so: key=abc,value=123" in str(e.value)


def test_parse_labels_malformed_missing_value():
    """
    Given: A labels string missing the value part
    When: parse_labels is called
    Then: The function raises a ValueError with appropriate message
    """
    from GCP import parse_labels

    input_str = "key=environment"
    with pytest.raises(ValueError) as e:
        parse_labels(input_str)

    assert "Could not parse field" in str(e.value)
    assert "key=environment" in str(e.value)
    assert "Please make sure you provided like so: key=abc,value=123" in str(e.value)


def test_parse_labels_malformed_wrong_separator():
    """
    Given: A labels string using wrong separator between key and value
    When: parse_labels is called
    Then: The function raises a ValueError with appropriate message
    """
    from GCP import parse_labels

    input_str = "key:environment,value:production"
    with pytest.raises(ValueError) as e:
        parse_labels(input_str)

    assert "Could not parse field" in str(e.value)
    assert "key:environment,value:production" in str(e.value)
    assert "Please make sure you provided like so: key=abc,value=123" in str(e.value)


def test_parse_labels_malformed_extra_equals():
    """
    Given: A labels string with extra equals signs
    When: parse_labels is called
    Then: The function raises a ValueError with appropriate message
    """
    from GCP import parse_labels

    input_str = "key=env=prod,value=test"
    with pytest.raises(ValueError) as e:
        parse_labels(input_str)

    assert "Could not parse field" in str(e.value)
    assert "key=env=prod,value=test" in str(e.value)
    assert "Please make sure you provided like so: key=abc,value=123" in str(e.value)


def test_parse_labels_numeric_values():
    """
    Given: A labels string with numeric values
    When: parse_labels is called
    Then: The function converts numeric values to lowercase strings
    """
    from GCP import parse_labels

    input_str = "key=port,value=8080;key=instances,value=3"
    expected = {"port": "8080", "instances": "3"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_duplicate_keys():
    """
    Given: A labels string with duplicate keys
    When: parse_labels is called
    Then: The function updates with the last value for duplicate keys
    """
    from GCP import parse_labels

    input_str = "key=env,value=dev;key=app,value=web;key=env,value=prod"
    expected = {"env": "prod", "app": "web"}

    result = parse_labels(input_str)
    assert result == expected


def test_parse_labels_mixed_valid_invalid():
    """
    Given: A labels string with mix of valid and invalid segments
    When: parse_labels is called
    Then: The function raises a ValueError on the first invalid segment
    """
    from GCP import parse_labels

    input_str = "key=env,value=prod;invalid_format;key=app,value=web"
    with pytest.raises(ValueError) as e:
        parse_labels(input_str)

    assert "Could not parse field" in str(e.value)
    assert "invalid_format" in str(e.value)
    assert "Please make sure you provided like so: key=abc,value=123" in str(e.value)


def test_parse_labels_empty_key_value():
    """
    Given: A labels string with empty key or value
    When: parse_labels is called
    Then: An exception is raised.
    """
    from GCP import parse_labels

    input_str = "key=,value=empty_key;key=empty_value,value="

    with pytest.raises(ValueError) as e:
        parse_labels(input_str)
    assert "Could not parse field" in str(e.value)


def test_parse_labels_complex_valid_format():
    """
    Given: A complex labels string with multiple valid labels including special characters
    When: parse_labels is called
    Then: The function returns correctly parsed dictionary with all labels
    """
    from GCP import parse_labels

    input_str = (
        "key=app-name,value=my-web-app;key=version_tag,value=v1.2.3-beta;key=environment,value=STAGING;key=owner.team,"
        "value=Platform_Team"
    )
    expected = {"app-name": "my-web-app", "version_tag": "v1.2.3-beta", "environment": "staging", "owner.team": "platform_team"}

    result = parse_labels(input_str)
    assert result == expected


def test_gcp_compute_instance_label_set_command_add_labels_true(mocker):
    """
    Given: Valid arguments with add_labels=true and existing instance labels
    When: gcp_compute_instance_label_set_command is called
    Then: The function should merge new labels with existing ones
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments with add_labels=true
    args = {
        "project_id": "test-project",
        "zone": "us-central1-a",
        "instance": "test-instance",
        "label_fingerprint": "abc123fingerprint",
        "labels": "key=newlabel,value=newvalue;key=app,value=updated",
        "add_labels": "true",
    }

    # Mock relevant instance data with current labels
    mock_instance_response = {
        "id": "567890",
        "name": "test-instance",
        "labels": {"environment": "production", "app": "oldvalue", "team": "backend"},
    }

    # Mock setLabels operation response
    mock_operation_response = {
        "id": "operation-12345",
        "name": "operation-set-labels",
        "kind": "compute#operation",
        "status": "RUNNING",
        "progress": "0",
        "operationType": "setLabels",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.get.return_value.execute.return_value = mock_instance_response
    mock_instances.setLabels.return_value.execute.return_value = mock_operation_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_label_set_command(mock_creds, args)

    # Verify get was called to fetch existing labels
    mock_instances.get.assert_called_once_with(project="test-project", zone="us-central1-a", instance="test-instance")

    # Verify setLabels was called with merged labels
    expected_body = {
        "labels": {
            "environment": "production",
            "team": "backend",
            "newlabel": "newvalue",
            "app": "updated",  # Should override existing value
        },
        "labelFingerprint": "abc123fingerprint",
    }
    mock_instances.setLabels.assert_called_once_with(
        project="test-project", zone="us-central1-a", instance="test-instance", body=expected_body
    )

    assert result.outputs == mock_operation_response


def test_gcp_compute_instance_label_set_command_add_labels_no_existing(mocker):
    """
    Given: Valid arguments with add_labels=true but instance has no existing labels
    When: gcp_compute_instance_label_set_command is called
    Then: The function should handle missing labels field gracefully
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments with add_labels=true
    args = {
        "project_id": "test-project",
        "zone": "us-west1-b",
        "instance": "new-instance",
        "label_fingerprint": "xyz789fingerprint",
        "labels": "key=firstlabel,value=firstvalue",
        "add_labels": "true",
    }

    # Mock instance response without labels field
    mock_instance_response = {
        "id": "111222333",
        "name": "new-instance",
        # No labels field
    }

    # Mock setLabels operation response
    mock_operation_response = {"id": "operation-99999", "kind": "compute#operation", "status": "DONE"}

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.get.return_value.execute.return_value = mock_instance_response
    mock_instances.setLabels.return_value.execute.return_value = mock_operation_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_label_set_command(mock_creds, args)

    # Verify setLabels was called with only new labels (no existing to merge)
    expected_body = {"labels": {"firstlabel": "firstvalue"}, "labelFingerprint": "xyz789fingerprint"}
    mock_instances.setLabels.assert_called_once_with(
        project="test-project", zone="us-west1-b", instance="new-instance", body=expected_body
    )

    assert result.outputs == mock_operation_response


def test_gcp_compute_instance_label_set_command_add_labels_false(mocker):
    """
    Given: Valid arguments with add_labels=false (default behavior)
    When: gcp_compute_instance_label_set_command is called
    Then: The function should not fetch existing labels and only set new ones
    """
    from GCP import gcp_compute_instance_label_set_command

    # Mock arguments with add_labels=false (explicit)
    args = {
        "project_id": "test-project",
        "zone": "europe-west1-c",
        "instance": "replace-labels-instance",
        "label_fingerprint": "replace123fingerprint",
        "labels": "key=onlylabel,value=onlyvalue",
        "add_labels": "false",
    }

    # Mock setLabels operation response
    mock_operation_response = {
        "id": "operation-replace",
        "name": "operation-replace-labels",
        "kind": "compute#operation",
        "status": "RUNNING",
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_instances = mocker.Mock()
    mock_compute.instances.return_value = mock_instances
    mock_instances.setLabels.return_value.execute.return_value = mock_operation_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.GCPServices.COMPUTE.build", return_value=mock_compute)

    # Execute the function
    result = gcp_compute_instance_label_set_command(mock_creds, args)

    # Verify get was NOT called (no existing labels fetched)
    mock_instances.get.assert_not_called()

    # Verify setLabels was called with only new labels
    expected_body = {"labels": {"onlylabel": "onlyvalue"}, "labelFingerprint": "replace123fingerprint"}
    mock_instances.setLabels.assert_called_once_with(
        project="test-project", zone="europe-west1-c", instance="replace-labels-instance", body=expected_body
    )

    assert result.outputs == mock_operation_response

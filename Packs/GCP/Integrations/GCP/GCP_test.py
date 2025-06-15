import pytest
from google.oauth2.credentials import Credentials
from unittest.mock import MagicMock


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


def test_compute_instance_metadata_add_new_item(mocker):
    """
    Given: Project metadata needs to be updated with a new key-value pair
    When: compute_instance_metadata_add is called with new metadata
    Then: The function should add the new item to existing metadata and call setMetadata with the updated list
    """
    from GCP import compute_instance_metadata_add

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "gke-test-instance",
        "metadata": "key=enable-oslogin,value=true",
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Setup mock instance and response
    mock_instance = {
        "metadata": {"fingerprint": "test-fingerprint", "items": [{"key": "existing-key", "value": "existing-value"}]}
    }

    mock_response = {"id": "operation-123", "name": "operation-name", "status": "RUNNING"}

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().get().execute.return_value = mock_instance
    mock_compute.instances().setMetadata().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_compute)

    # Execute the function
    result = compute_instance_metadata_add(mock_creds, args)

    # Check call to setMetadata with correct body
    called_args, called_kwargs = mock_compute.instances().setMetadata.call_args

    assert called_kwargs["project"] == "test-project"
    assert called_kwargs["zone"] == "us-central1-c"
    assert called_kwargs["instance"] == "gke-test-instance"

    # Check body has expected items
    body = called_kwargs["body"]
    assert body["fingerprint"] == "test-fingerprint"

    # Convert items to dict for easier comparison
    items_dict = {item["key"]: item["value"] for item in body["items"]}
    assert items_dict["existing-key"] == "existing-value"
    assert items_dict["enable-oslogin"] == "true"

    # Check outputs
    assert result.outputs_prefix == "GCP.Compute.Operations"
    assert result.outputs == mock_response


def test_compute_instance_metadata_add_update_existing(mocker):
    """
    Given: Project metadata needs to be updated where a key already exists
    When: compute_instance_metadata_add is called with metadata containing an existing key
    Then: The function should update the value of the existing key and preserve other metadata
    """
    from GCP import compute_instance_metadata_add

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "gke-test-instance",
        "metadata": "key=enable-oslogin,value=false;key=new-key,value=new-value",
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Setup mock instance and response
    mock_instance = {
        "metadata": {
            "fingerprint": "test-fingerprint",
            "items": [{"key": "enable-oslogin", "value": "true"}, {"key": "existing-key", "value": "existing-value"}],
        }
    }

    mock_response = {"id": "operation-123", "name": "operation-name", "status": "RUNNING"}

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().get().execute.return_value = mock_instance
    mock_compute.instances().setMetadata().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_compute)

    # Execute the function
    result = compute_instance_metadata_add(mock_creds, args)

    # Check body has expected items
    called_args, called_kwargs = mock_compute.instances().setMetadata.call_args
    body = called_kwargs["body"]

    # Convert items to dict for easier comparison
    items_dict = {item["key"]: item["value"] for item in body["items"]}
    assert items_dict["enable-oslogin"] == "false"  # Should be updated
    assert items_dict["existing-key"] == "existing-value"  # Should remain unchanged
    assert items_dict["new-key"] == "new-value"  # Should be added

    assert result.outputs == mock_response


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
        "scopes": "https://www.googleapis.com/auth/compute,https://www.googleapis.com/auth/devstorage.read_only"
    }

    # Mock response
    mock_response = {
        "id": "operation-123",
        "name": "operation-123",
        "operationType": "setServiceAccount",
        "progress": "100",
        "zone": "us-central1-c",
        "status": "RUNNING"
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
    assert body["scopes"] == [
        "https://www.googleapis.com/auth/compute",
        "https://www.googleapis.com/auth/devstorage.read_only"
    ]

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
        "service_account_email": "service-account@test-project.iam.gserviceaccount.com"
    }

    # Mock response
    mock_response = {
        "id": "operation-123",
        "name": "operation-123",
        "operationType": "setServiceAccount",
        "progress": "100",
        "zone": "us-central1-c",
        "status": "RUNNING"
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
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "test-instance"
    }

    # Mock response
    mock_response = {
        "id": "operation-123",
        "name": "operation-123",
        "operationType": "setServiceAccount",
        "progress": "100",
        "zone": "us-central1-c",
        "status": "RUNNING"
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
    args = {
        "project_id": "test-project",
        "member": "user:test@example.com,serviceAccount:sa@example.com",
        "role": "roles/editor"
    }

    # Mock policy response with multiple roles and members
    mock_policy = {
        "bindings": [
            {
                "role": "roles/editor",
                "members": ["user:test@example.com", "serviceAccount:sa@example.com", "user:keep@example.com"]
            },
            {
                "role": "roles/viewer",
                "members": ["user:test@example.com", "user:other@example.com"]
            }
        ],
        "etag": "BwWKmjvelug="
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


def test_iam_project_deny_policy_create(mocker):
    """
    Given: A GCP project that needs a deny policy created
    When: iam_project_deny_policy_create is called with policy details
    Then: The function should call createPolicy with the correct configuration
    """
    from GCP import iam_project_deny_policy_create

    # Mock arguments
    args = {
        "project_id": "test-project",
        "policy_id": "test-deny-policy",
        "display_name": "Test Deny Policy",
        "denied_principals": "user:test@example.com,serviceAccount:sa@example.com",
        "denied_permissions": "compute.instances.create,compute.instances.delete"
    }

    # Mock response
    mock_response = {
        "name": "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Ftest-project/denypolicies/test-deny-policy",
        "displayName": "Test Deny Policy",
        "createTime": "2023-08-15T12:00:00Z",
        "updateTime": "2023-08-15T12:00:00Z",
        "rules": [
            {
                "denyRule": {
                    "deniedPrincipals": ["user:test@example.com", "serviceAccount:sa@example.com"],
                    "deniedPermissions": ["compute.instances.create", "compute.instances.delete"]
                }
            }
        ]
    }

    # Use MagicMock for IAM
    mock_iam = MagicMock()
    mock_iam.policies().createPolicy().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_iam)

    # Execute the function
    result = iam_project_deny_policy_create(mock_creds, args)

    # Verify createPolicy was called with correct parameters
    call_args, call_kwargs = mock_iam.policies().createPolicy.call_args

    assert call_kwargs["parent"] == "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Ftest-project/denypolicies"
    assert call_kwargs["policyId"] == "test-deny-policy"

    body = call_kwargs["body"]
    assert body["displayName"] == "Test Deny Policy"
    assert body["rules"][0]["denyRule"]["deniedPrincipals"] == ["user:test@example.com", "serviceAccount:sa@example.com"]
    assert body["rules"][0]["denyRule"]["deniedPermissions"] == ["compute.instances.create", "compute.instances.delete"]

    # Check outputs
    assert result.outputs_prefix == "GCP.IAM.DenyPolicy"
    assert result.outputs == mock_response
    assert "test-deny-policy" in result.readable_output
    assert "successfully created" in result.readable_output


def test_iam_service_account_delete(mocker):
    """
    Given: A GCP service account that needs to be deleted
    When: iam_service_account_delete is called with project_id and service_account_email
    Then: The function should call serviceAccounts().delete with the correct resource name
    """
    from GCP import iam_service_account_delete

    # Mock arguments
    args = {
        "project_id": "test-project",
        "service_account_email": "test-sa@test-project.iam.gserviceaccount.com"
    }

    # Use MagicMock for IAM
    mock_iam = MagicMock()
    mock_iam.projects().serviceAccounts().delete().execute.return_value = {}

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_iam)

    # Execute the function
    result = iam_service_account_delete(mock_creds, args)

    # Verify delete was called with correct name
    call_args, call_kwargs = mock_iam.projects().serviceAccounts().delete.call_args

    assert call_kwargs["name"] == "projects/test-project/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com"

    # Check readable output
    assert "test-sa@test-project.iam.gserviceaccount.com" in result.readable_output
    assert "successfully deleted" in result.readable_output


def test_iam_group_membership_delete(mocker):
    """
    Given: A Google Cloud Identity group with a member that needs to be removed
    When: iam_group_membership_delete is called with group_id and membership_id
    Then: The function should call memberships().delete with the correct membership name
    """
    from GCP import iam_group_membership_delete

    # Mock arguments
    args = {
        "group_id": "01abc123def456",
        "membership_id": "member789ghi"
    }

    # Use MagicMock for Cloud Identity
    mock_cloud_identity = MagicMock()
    mock_cloud_identity.groups().memberships().delete().execute.return_value = {}

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_cloud_identity)

    # Execute the function
    result = iam_group_membership_delete(mock_creds, args)

    # Verify delete was called with correct name
    call_args, call_kwargs = mock_cloud_identity.groups().memberships().delete.call_args

    assert call_kwargs["name"] == "groups/01abc123def456/memberships/member789ghi"

    # Check readable output
    assert "Membership member789ghi was deleted from group 01abc123def456" in result.readable_output


def test_check_required_permissions_all_granted(mocker):
    """
    Given: GCP credentials with all required permissions
    When: check_required_permissions is called without specifying a command
    Then: The function should return None, indicating all permissions are granted
    """
    from GCP import check_required_permissions, REQUIRED_PERMISSIONS

    # Get all permissions that need to be tested
    all_permissions = list({p for perms in REQUIRED_PERMISSIONS.values() for p in perms})
    testable_permissions = [p for p in all_permissions if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - all permissions granted
    mock_response = {"permissions": testable_permissions}

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
    from GCP import check_required_permissions, REQUIRED_PERMISSIONS

    # Check permissions for a specific command
    command = "gcp-compute-firewall-patch"
    required_perms = REQUIRED_PERMISSIONS[command]
    testable_permissions = [p for p in required_perms if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - all permissions granted
    mock_response = {"permissions": testable_permissions}

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
    from GCP import check_required_permissions, REQUIRED_PERMISSIONS, DemistoException

    # Get all permissions that need to be tested
    all_permissions = list({p for perms in REQUIRED_PERMISSIONS.values() for p in perms})
    testable_permissions = [p for p in all_permissions if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - some permissions are missing
    granted_permissions = testable_permissions[:-2]  # All except the last two
    missing_permissions = testable_permissions[-2:]  # Just the last two permissions

    mock_response = {"permissions": granted_permissions}

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


def test_check_required_permissions_with_connector_id(mocker):
    """
    Given: GCP credentials with connector_id and missing permissions
    When: check_required_permissions is called with connector_id
    Then: The function should return a HealthCheckError instead of raising an exception
    """
    from GCP import check_required_permissions, REQUIRED_PERMISSIONS, HealthCheckError, ErrorType

    # Get all permissions that need to be tested
    all_permissions = list({p for perms in REQUIRED_PERMISSIONS.values() for p in perms})
    testable_permissions = [p for p in all_permissions if not p.startswith("cloudidentity.")]

    # Mock response from testIamPermissions - some permissions are missing
    granted_permissions = testable_permissions[:-2]  # All except the last two

    mock_response = {"permissions": granted_permissions}

    # Use MagicMock for resource manager
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().testIamPermissions().execute.return_value = mock_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function with connector_id
    result = check_required_permissions(mock_creds, "test-project", connector_id="test-connector-id")

    # Verify that the result is a HealthCheckError
    assert isinstance(result, HealthCheckError)
    assert result.account_id == "test-project"
    assert result.connector_id == "test-connector-id"
    assert result.error_type == ErrorType.PERMISSION_ERROR
    assert "Missing required permissions" in result.message


def test_check_required_permissions_api_error(mocker):
    """
    Given: GCP credentials that cause an API error when checking permissions
    When: check_required_permissions is called
    Then: The function should raise DemistoException with the error message
    """
    from GCP import check_required_permissions, DemistoException

    # Use MagicMock for resource manager that raises an exception
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().testIamPermissions().execute.side_effect = Exception("API Error")

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function and expect an exception
    with pytest.raises(DemistoException) as e:
        check_required_permissions(mock_creds, "test-project")

    # Verify that the error message contains the API error
    assert "Failed to test permissions" in str(e.value)
    assert "API Error" in str(e.value)


def test_check_required_permissions_api_error_with_connector_id(mocker):
    """
    Given: GCP credentials with connector_id that cause an API error
    When: check_required_permissions is called with connector_id
    Then: The function should return a HealthCheckError instead of raising an exception
    """
    from GCP import check_required_permissions, HealthCheckError, ErrorType

    # Use MagicMock for resource manager that raises an exception
    mock_resource_manager = MagicMock()
    mock_resource_manager.projects().testIamPermissions().execute.side_effect = Exception("API Error")

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch("GCP.build", return_value=mock_resource_manager)

    # Execute the function with connector_id
    result = check_required_permissions(mock_creds, "test-project", connector_id="test-connector-id")

    # Verify that the result is a HealthCheckError
    assert isinstance(result, HealthCheckError)
    assert result.account_id == "test-project"
    assert result.connector_id == "test-connector-id"
    assert result.error_type == ErrorType.PERMISSION_ERROR
    assert "Failed to test permissions" in result.message
    assert "API Error" in result.message

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
    expected = [
        {"IPProtocol": "tcp", "ports": ["80", "443"]},
        {"IPProtocol": "udp", "ports": ["53"]}
    ]

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
    expected = [
        {"key": "enable-oslogin", "value": "true"},
        {"key": "serial-port-enable", "value": "false"}
    ]

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
    empty_args = {
        "project_id": "test-project",
        "resource_name": "fw-rule"
    }

    compute_firewall_patch(mock_creds, empty_args)

    # Should call with empty config
    mock_firewalls.patch.assert_called_with(
        project="test-project",
        firewall="fw-rule",
        body={}
    )

    # Reset mock for next test
    mock_firewalls.patch.reset_mock()

    # Test case 2: Boolean conversions and special fields
    bool_args = {
        "project_id": "test-project",
        "resource_name": "fw-rule",
        "disabled": "true",  # String boolean that should be converted
        "logConfigEnable": "false",  # Another string boolean
        "sourceTags": "single-tag",  # Single item that should become a list
        "allowed": "ipprotocol=all,ports=*"  # Special format for allowed
    }

    result = compute_firewall_patch(mock_creds, bool_args)

    # Get the body passed to patch
    called_with = mock_firewalls.patch.call_args[1]['body']

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
    args = {
        "resource_name": "test-bucket",
        "entity": "allUsers,user:test@mail.com"
    }

    policy = {
        "bindings": [
            {
                "role": "roles/storage.objectViewer",
                "members": ["allUsers", "user:test@mail.com", "user:other@example.com"]
            },
            {
                "role": "roles/storage.admin",
                "members": ["user:admin@example.com", "user:test@mail.com"]
            }
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
    mocker.patch('GCP.build', return_value=mock_storage)

    # Run the function
    result = storage_bucket_policy_delete(mock_creds, args)

    # Verify the results
    assert "`allUsers`" in result.readable_output
    assert "`user:test@mail.com`" in result.readable_output
    mock_buckets.getIamPolicy.assert_called_once_with(bucket="test-bucket")
    mock_buckets.setIamPolicy.assert_called_once()
    # Verify that the removed entities are no longer in the policy
    call_args = mock_buckets.setIamPolicy.call_args[1]
    updated_policy = call_args['body']
    for binding in updated_policy['bindings']:
        assert "allUsers" not in binding.get('members', [])
        assert "user:test@mail.com" not in binding.get('members', [])


def test_compute_subnet_update_flow_logs(mocker):
    """
    Given: A GCP subnet that needs flow logs enabled
    When: compute_subnet_update is called with enable_flow_logs=true
    Then: The subnet's flow logs are enabled with proper fingerprint validation
    """
    from GCP import compute_subnet_update

    # Mock data
    args = {
        "project_id": "test-project",
        "region": "us-east1",
        "resource_name": "test-subnet",
        "enable_flow_logs": "true"
    }

    # Subnet response with fingerprint
    subnet_response = {
        "name": "test-subnet",
        "fingerprint": "test-fingerprint-123",
        "enableFlowLogs": False
    }

    # Expected patch operation response
    patch_response = {
        "id": "operation-123",
        "name": "operation-123",
        "kind": "compute#operation",
        "operationType": "patch",
        "progress": "100",
        "zone": "us-east1",
        "status": "RUNNING"
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_subnetworks = mocker.Mock()

    mock_compute.subnetworks.return_value = mock_subnetworks
    mock_subnetworks.get.return_value.execute.return_value = subnet_response
    mock_subnetworks.patch.return_value.execute.return_value = patch_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch('GCP.build', return_value=mock_compute)

    # Run the function
    result = compute_subnet_update(mock_creds, args)

    # Verify the results
    assert "Flow Logs configuration for subnet test-subnet" in result.readable_output
    assert result.outputs[0] == patch_response

    # Check that the correct API calls were made
    mock_subnetworks.get.assert_called_once_with(
        project="test-project",
        region="us-east1",
        subnetwork="test-subnet"
    )

    mock_subnetworks.patch.assert_called_once_with(
        project="test-project",
        region="us-east1",
        subnetwork="test-subnet",
        body={"enableFlowLogs": True, "fingerprint": "test-fingerprint-123"}
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
        "enable_private_ip_google_access": "true"
    }

    # Expected operation response
    set_response = {
        "id": "operation-456",
        "name": "operation-456",
        "kind": "compute#operation",
        "operationType": "setPrivateIpGoogleAccess",
        "progress": "100",
        "zone": "us-east1",
        "status": "RUNNING"
    }

    # Mock the GCP API calls
    mock_compute = mocker.Mock()
    mock_subnetworks = mocker.Mock()

    mock_compute.subnetworks.return_value = mock_subnetworks
    mock_subnetworks.setPrivateIpGoogleAccess.return_value.execute.return_value = set_response

    # Mock the build function
    mock_creds = mocker.Mock(spec=Credentials)
    mocker.patch('GCP.build', return_value=mock_compute)

    # Run the function
    result = compute_subnet_update(mock_creds, args)

    # Verify the results
    assert "Private IP Google Access configuration for subnet test-subnet" in result.readable_output
    assert result.outputs[1] == set_response

    # Check that the correct API calls were made
    mock_subnetworks.setPrivateIpGoogleAccess.assert_called_once_with(
        project="test-project",
        region="us-east1",
        subnetwork="test-subnet",
        body={"privateIpGoogleAccess": True}
    )


def test_compute_project_metadata_add_new_item(mocker):
    """
    Given: Project metadata needs to be updated with a new key-value pair
    When: compute_project_metadata_add is called with new metadata
    Then: The function should add the new item to existing metadata and call setMetadata with the updated list
    """
    from GCP import compute_project_metadata_add

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "gke-test-instance",
        "metadata": "key=enable-oslogin,value=true"
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Setup mock instance and response
    mock_instance = {
        "metadata": {
            "fingerprint": "test-fingerprint",
            "items": [
                {"key": "existing-key", "value": "existing-value"}
            ]
        }
    }

    mock_response = {
        "id": "operation-123",
        "name": "operation-name",
        "status": "RUNNING"
    }

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().get().execute.return_value = mock_instance
    mock_compute.instances().setMetadata().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_compute)

    # Execute the function
    result = compute_project_metadata_add(mock_creds, args)

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


def test_compute_project_metadata_add_update_existing(mocker):
    """
    Given: Project metadata needs to be updated where a key already exists
    When: compute_project_metadata_add is called with metadata containing an existing key
    Then: The function should update the value of the existing key and preserve other metadata
    """
    from GCP import compute_project_metadata_add

    # Mock arguments
    args = {
        "project_id": "test-project",
        "zone": "us-central1-c",
        "resource_name": "gke-test-instance",
        "metadata": "key=enable-oslogin,value=false;key=new-key,value=new-value"
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Setup mock instance and response
    mock_instance = {
        "metadata": {
            "fingerprint": "test-fingerprint",
            "items": [
                {"key": "enable-oslogin", "value": "true"},
                {"key": "existing-key", "value": "existing-value"}
            ]
        }
    }

    mock_response = {
        "id": "operation-123",
        "name": "operation-name",
        "status": "RUNNING"
    }

    # Use MagicMock for compute
    mock_compute = MagicMock()
    mock_compute.instances().get().execute.return_value = mock_instance
    mock_compute.instances().setMetadata().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_compute)

    # Execute the function
    result = compute_project_metadata_add(mock_creds, args)

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
        "cidrs": "192.168.0.0/24,10.0.0.0/32"
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Mock response
    mock_response = {
        "name": "operation-123",
        "status": "RUNNING"
    }

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
    Then: The function should call bucket.patch with both settings configured correctly
    """
    from GCP import storage_bucket_metadata_update

    # Mock arguments
    args = {
        "project_id": "test-project",
        "resource_name": "test-bucket",
        "enable_versioning": "true",
        "enable_uniform_access": "false"
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
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": False}
        }
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


def test_check_required_permissions_specific_command_missing_permission(mocker):
    """
    Given: Need to verify permissions for a specific command but some permissions are missing
    When: check_required_permissions is called for 'gcp-compute-firewall-patch' with missing permissions
    Then: The function should raise a DemistoException with the missing permissions
    """
    from GCP import check_required_permissions
    from CommonServerPython import DemistoException

    # Mock arguments
    args = {
        "project_id": "test-project"
    }

    # Mock credentials
    mock_creds = mocker.Mock(spec=Credentials)

    # Mock response with some permissions missing
    mock_response = {
        "permissions": [
            "compute.firewalls.update",
            "compute.firewalls.get",
            # Missing: "compute.firewalls.list",
            "compute.networks.updatePolicy",
            # Missing: "compute.networks.list"
        ]
    }

    # Use MagicMock for resourcemanager
    mock_resourcemanager = MagicMock()
    mock_resourcemanager.projects().testIamPermissions().execute.return_value = mock_response

    mocker.patch("GCP.build", return_value=mock_resourcemanager)

    # The function should raise an exception due to missing permissions
    with pytest.raises(DemistoException) as excinfo:
        check_required_permissions(mock_creds, args, command="gcp-compute-firewall-patch")

    # Verify the exception contains information about missing permissions
    exception_msg = str(excinfo.value)
    assert "Missing permissions" in exception_msg
    assert "compute.firewalls.list" in exception_msg
    assert "compute.networks.list" in exception_msg

    # Verify correct parameters were used in the API call
    called_args, called_kwargs = mock_resourcemanager.projects().testIamPermissions.call_args

    assert called_kwargs["name"] == "projects/test-project"

    # The body should contain only permissions for the firewall-patch command
    permissions = called_kwargs["body"]["permissions"]
    assert "compute.firewalls.update" in permissions
    assert "compute.firewalls.get" in permissions
    assert "compute.firewalls.list" in permissions
    assert "compute.networks.updatePolicy" in permissions
    assert "compute.networks.list" in permissions

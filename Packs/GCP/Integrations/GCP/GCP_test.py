import pytest


def test_parse_firewall_rule():
    """
    Given: A string representing firewall rules.
    When: Calling parse_firewall_rule function.
    Then: Returns a list of dictionaries with 'IPProtocol' and 'ports' fields.
    """
    from GCP import parse_firewall_rule

    rule_str = "ipprotocol=tcp,ports=80,443;ipprotocol=udp,ports=53"
    result = parse_firewall_rule(rule_str)

    assert len(result) == 2
    assert result[0]["IPProtocol"] == "tcp"
    assert result[0]["ports"] == ["80", "443"]
    assert result[1]["IPProtocol"] == "udp"
    assert result[1]["ports"] == ["53"]


def test_parse_firewall_rule_invalid_format():
    """
    Given: A string with invalid firewall rule format.
    When: Calling parse_firewall_rule function.
    Then: Raises a ValueError with appropriate error message.
    """
    from GCP import parse_firewall_rule

    rule_str = "invalid-format"

    with pytest.raises(ValueError) as e:
        parse_firewall_rule(rule_str)

    assert "Could not parse field" in str(e.value)


def test_parse_metadata_items():
    """
    Given: A string representing metadata items.
    When: Calling parse_metadata_items function.
    Then: Returns a list of dictionaries with 'key' and 'value' fields.
    """
    from GCP import parse_metadata_items

    tags_str = "key=enable-oslogin,value=TRUE;key=serial-port-enable,value=FALSE"
    result = parse_metadata_items(tags_str)

    assert len(result) == 2
    assert result[0]["key"] == "enable-oslogin"
    assert result[0]["value"] == "TRUE"
    assert result[1]["key"] == "serial-port-enable"
    assert result[1]["value"] == "FALSE"


def test_parse_metadata_items_invalid_format():
    """
    Given: A string with invalid metadata item format.
    When: Calling parse_metadata_items function.
    Then: Raises a ValueError with appropriate error message.
    """
    from GCP import parse_metadata_items

    tags_str = "invalid-format"

    with pytest.raises(ValueError) as e:
        parse_metadata_items(tags_str)

    assert "Could not parse field" in str(e.value)


def test_get_access_token_missing_project_id():
    """
    Given: Arguments dictionary without project_id.
    When: Calling get_access_token function.
    Then: Raises a DemistoException about missing project_id.
    """
    from GCP import get_access_token
    from CommonServerPython import DemistoException

    args = {}

    with pytest.raises(DemistoException) as e:
        get_access_token(args)

    assert "project_id is required" in str(e.value)


def test_get_access_token():
    """
    Given: Arguments dictionary with project_id.
    When: Calling get_access_token function.
    Then: Returns an access token string.
    """
    from GCP import get_access_token

    args = {"project_id": "test-project"}

    result = get_access_token(args)

    assert result == ""  # Currently hardcoded to return empty string


def test_compute_firewall_patch(mocker):
    """
    Given: Arguments for firewall patch and GCP credentials.
    When: Calling compute_firewall_patch function.
    Then: Returns a CommandResults object with the operation details and calls API with correct parameters.
    """
    from GCP import compute_firewall_patch
    from CommonServerPython import CommandResults
    import json

    # Mock the GCP API response
    mock_execute = mocker.MagicMock(return_value={
        "id": "operation-123",
        "name": "operation-name",
        "operationType": "patch",
        "status": "RUNNING",
        "progress": 0,
        "zone": "us-central1-a",
        "kind": "compute#operation"
    })
    mock_patch = mocker.MagicMock()
    mock_patch.return_value.execute = mock_execute

    mock_firewalls = mocker.MagicMock()
    mock_firewalls.patch.return_value = mock_patch

    mock_compute = mocker.MagicMock()
    mock_compute.firewalls.return_value = mock_firewalls

    mocker.patch("GCP.Credentials")
    mocker.patch("GCP.build", return_value=mock_compute)

    args = {
        "project_id": "test-project",
        "resource_name": "test-firewall",
        "description": "Updated firewall rule",
        "disabled": "true",
        "sourceRanges": "10.0.0.0/8,192.168.0.0/16",
        "allowed": "ipprotocol=tcp,ports=80,443"
    }

    creds = mocker.MagicMock()
    result = compute_firewall_patch(creds, args)

    # Check that the function returns expected results
    assert isinstance(result, CommandResults)
    assert "Firewall rule test-firewall was successfully patched" in result.readable_output
    assert result.outputs_prefix == "GCP.Compute.Operations"
    assert result.outputs["id"] == "operation-123"

    # Verify API was called with correct parameters
    mock_firewalls.patch.assert_called_once()
    call_args = mock_firewalls.patch.call_args[1]
    assert call_args["project"] == "test-project"
    assert call_args["firewall"] == "test-firewall"

    # Verify the body contains the expected config
    body = call_args["body"]
    assert body["description"] == "Updated firewall rule"
    assert body["disabled"] is True
    assert body["sourceRanges"] == ["10.0.0.0/8", "192.168.0.0/16"]
    assert body["allowed"][0]["IPProtocol"] == "tcp"
    assert body["allowed"][0]["ports"] == ["80", "443"]


def test_storage_bucket_policy_delete_with_removal(mocker):
    """
    Given: Arguments for bucket policy deletion and GCP credentials.
    When: Calling storage_bucket_policy_delete function with removable entities.
    Then: Returns a CommandResults object with success message and calls API with correct parameters.
    """
    from GCP import storage_bucket_policy_delete
    from CommonServerPython import CommandResults

    # Mock the GCP API responses
    initial_policy = {
        "bindings": [
            {
                "role": "roles/storage.objectViewer",
                "members": ["allUsers", "user:someone@example.com"]
            },
            {
                "role": "roles/storage.objectAdmin",
                "members": ["user:admin@example.com", "allUsers"]
            }
        ]
    }

    mock_get_policy = mocker.MagicMock(return_value=initial_policy)
    mock_set_policy = mocker.MagicMock()

    mock_buckets = mocker.MagicMock()
    mock_buckets.getIamPolicy.return_value.execute = mock_get_policy
    mock_buckets.setIamPolicy.return_value.execute = mock_set_policy

    mock_storage = mocker.MagicMock()
    mock_storage.buckets.return_value = mock_buckets

    mocker.patch("GCP.build", return_value=mock_storage)

    args = {
        "resource_name": "test-bucket",
        "entity": "allUsers"
    }

    creds = mocker.MagicMock()
    result = storage_bucket_policy_delete(creds, args)

    # Check that the function returns expected results
    assert isinstance(result, CommandResults)
    assert "Access permissions for `allUsers` were successfully revoked" in result.readable_output

    # Verify APIs were called with correct parameters
    mock_buckets.getIamPolicy.assert_called_once_with(bucket="test-bucket")
    mock_buckets.setIamPolicy.assert_called_once()

    # Verify the policy was correctly modified
    call_args = mock_buckets.setIamPolicy.call_args[1]
    assert call_args["bucket"] == "test-bucket"

    policy = call_args["body"]
    assert len(policy["bindings"]) == 2

    # Verify allUsers was removed from both roles
    for binding in policy["bindings"]:
        assert "allUsers" not in binding["members"]

    # Verify other members still exist
    assert "user:someone@example.com" in policy["bindings"][0]["members"]
    assert "user:admin@example.com" in policy["bindings"][1]["members"]


def test_storage_bucket_policy_delete_no_changes(mocker):
    """
    Given: Arguments for bucket policy deletion and GCP credentials.
    When: Calling storage_bucket_policy_delete function with no matching entities.
    Then: Returns a CommandResults object with no changes message and doesn't call setIamPolicy.
    """
    from GCP import storage_bucket_policy_delete
    from CommonServerPython import CommandResults

    # Mock the GCP API responses
    initial_policy = {
        "bindings": [
            {
                "role": "roles/storage.objectViewer",
                "members": ["user:someone@example.com"]
            }
        ]
    }

    mock_get_policy = mocker.MagicMock(return_value=initial_policy)

    mock_buckets = mocker.MagicMock()
    mock_buckets.getIamPolicy.return_value.execute = mock_get_policy

    mock_storage = mocker.MagicMock()
    mock_storage.buckets.return_value = mock_buckets

    mocker.patch("GCP.build", return_value=mock_storage)

    args = {
        "resource_name": "test-bucket",
        "entity": "allUsers"
    }

    creds = mocker.MagicMock()
    result = storage_bucket_policy_delete(creds, args)

    # Check that the function returns expected results
    assert isinstance(result, CommandResults)
    assert "No IAM changes made for bucket" in result.readable_output

    # Verify getIamPolicy was called but setIamPolicy was not
    mock_buckets.getIamPolicy.assert_called_once_with(bucket="test-bucket")
    mock_buckets.setIamPolicy.assert_not_called()


def test_compute_subnet_update_flow_logs(mocker):
    """
    Given: Arguments for subnet update with flow logs and GCP credentials.
    When: Calling compute_subnet_update function with enable_flow_logs.
    Then: Returns a CommandResults object and calls API with correct parameters.
    """
    from GCP import compute_subnet_update
    from CommonServerPython import CommandResults

    # Mock the GCP API responses
    mock_get_response = {
        "fingerprint": "test-fingerprint"
    }
    mock_operation_response = {
        "id": "operation-123",
        "name": "operation-name",
        "operationType": "patch",
        "status": "RUNNING",
        "progress": 0,
        "zone": "us-central1-a",
        "kind": "compute#operation"
    }

    mock_get = mocker.MagicMock(return_value=mock_get_response)
    mock_patch = mocker.MagicMock(return_value=mock_operation_response)

    mock_subnetworks = mocker.MagicMock()
    mock_subnetworks.get.return_value.execute = mock_get
    mock_subnetworks.patch.return_value.execute = mock_patch

    mock_compute = mocker.MagicMock()
    mock_compute.subnetworks.return_value = mock_subnetworks

    mocker.patch("GCP.build", return_value=mock_compute)

    args = {
        "project_id": "test-project",
        "region": "us-central1",
        "resource_name": "test-subnet",
        "enable_flow_logs": "true"
    }

    creds = mocker.MagicMock()
    result = compute_subnet_update(creds, args)

    # Check that the function returns expected results
    assert isinstance(result, CommandResults)
    assert "Flow Logs configuration for subnet test-subnet" in result.readable_output

    # Verify APIs were called with correct parameters
    mock_subnetworks.get.assert_called_once_with(
        project="test-project",
        region="us-central1",
        subnetwork="test-subnet"
    )

    mock_subnetworks.patch.assert_called_once()
    patch_args = mock_subnetworks.patch.call_args[1]
    assert patch_args["project"] == "test-project"
    assert patch_args["region"] == "us-central1"
    assert patch_args["subnetwork"] == "test-subnet"
    assert patch_args["body"]["enableFlowLogs"] is True
    assert patch_args["body"]["fingerprint"] == "test-fingerprint"


def test_compute_subnet_update_private_access(mocker):
    """
    Given: Arguments for subnet update with private access and GCP credentials.
    When: Calling compute_subnet_update function with enable_private_ip_google_access.
    Then: Returns a CommandResults object and calls API with correct parameters.
    """
    from GCP import compute_subnet_update
    from CommonServerPython import CommandResults

    # Mock the GCP API responses
    mock_operation_response = {
        "id": "operation-123",
        "name": "operation-name",
        "operationType": "setPrivateIpGoogleAccess",
        "status": "RUNNING",
        "progress": 0,
        "zone": "us-central1-a",
        "kind": "compute#operation"
    }

    mock_subnetworks = mocker.MagicMock()
    mock_subnetworks.setPrivateIpGoogleAccess.return_value.execute = mocker.MagicMock(
        return_value=mock_operation_response
    )

    mock_compute = mocker.MagicMock()
    mock_compute.subnetworks.return_value = mock_subnetworks

    mocker.patch("GCP.build", return_value=mock_compute)

    args = {
        "project_id": "test-project",
        "region": "us-central1",
        "resource_name": "test-subnet",
        "enable_private_ip_google_access": "true"
    }

    creds = mocker.MagicMock()
    result = compute_subnet_update(creds, args)

    # Check that the function returns expected results

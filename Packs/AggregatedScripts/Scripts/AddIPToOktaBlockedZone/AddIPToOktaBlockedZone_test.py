import pytest
from CommonServerPython import DemistoException
import json

# Import the module itself for testing
import BlockExternalIPWithCAPolicy  # Assuming this is the name of your Okta script file

# For clarity in testing, we can define the script name, though not strictly necessary
SCRIPT_NAME = "BlockExternalIPWithCAPolicy"


# --- Helper functions tests ---

def test_is_private_ip_private():
    """
    Given: A private IP address.
    When: Calling is_private_ip.
    Then: Should return True.
    """
    assert BlockExternalIPWithCAPolicy.is_private_ip("192.168.1.1") is True
    assert BlockExternalIPWithCAPolicy.is_private_ip("10.0.0.5") is True


def test_is_private_ip_public():
    """
    Given: A public IP address.
    When: Calling is_private_ip.
    Then: Should return False.
    """
    assert BlockExternalIPWithCAPolicy.is_private_ip("8.8.8.8") is False
    assert BlockExternalIPWithCAPolicy.is_private_ip("203.0.113.1") is False


def test_is_private_ip_invalid():
    """
    Given: An invalid IP address format.
    When: Calling is_private_ip.
    Then: Should return False and log a debug message.
    """
    # Mock demisto.debug to capture its calls
    mocker_debug = pytest.importorskip("demistomock").demisto.debug
    mocker_debug.reset_mock()  # Reset any previous calls

    assert BlockExternalIPWithCAPolicy.is_private_ip("invalid-ip") is False
    mocker_debug.assert_called_with("Invalid IP address format encountered: invalid-ip")


# --- ip_in_range tests ---

@pytest.mark.parametrize("ip, ip_range, expected", [
    ("192.168.1.5", "192.168.1.0/24", True),
    ("192.168.2.1", "192.168.1.0/24", False),
    ("10.0.0.5", "10.0.0.1-10.0.0.10", True),
    ("10.0.0.0", "10.0.0.1-10.0.0.10", False),
    ("10.0.0.11", "10.0.0.1-10.0.0.10", False),
    ("1.1.1.1", "1.1.1.1", True),
    ("1.1.1.2", "1.1.1.1", False),
    ("invalid-ip", "1.1.1.1", False),
    ("1.1.1.1", "invalid-range", False),
    ("1.1.1.1", "1.1.1.1/32", True) # Test exact match with CIDR
])
def test_ip_in_range(mocker, ip, ip_range, expected):
    """
    Tests various scenarios for ip_in_range function.
    """
    # Mock demisto.debug to prevent actual logging during test
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'debug')
    assert BlockExternalIPWithCAPolicy.ip_in_range(ip, ip_range) == expected


# --- _get_command_error_details tests ---

def test_get_command_error_details_api_call_json():
    """
    Given: A command result with "Error in API call" and embedded JSON.
    When: Calling _get_command_error_details.
    Then: Should parse and return the code and message.
    """
    res = {"Contents": "Error in API call [400] - {\"error\": {\"code\": \"E0000001\", \"message\": \"API error\"}}"}
    expected = "E0000001: API error"
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected


def test_get_command_error_details_raw_json_error():
    """
    Given: A command result where 'Contents' is a direct JSON error object string.
    When: Calling _get_command_error_details.
    Then: Should parse and return the code and message.
    """
    res = {"Contents": "{\"error\": {\"code\": \"AuthFailed\", \"message\": \"Authentication failed\"}}"}
    expected = "AuthFailed: Authentication failed"
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected


def test_get_command_error_details_dict_error():
    """
    Given: A command result where 'Contents' is already a dictionary with an 'error' key.
    When: Calling _get_command_error_details.
    Then: Should extract and return the code and message.
    """
    res = {"Contents": {"error": {"code": "NotFound", "message": "Resource not found"}}}
    expected = "NotFound: Resource not found"
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected


def test_get_command_error_details_simple_string():
    """
    Given: A command result with a simple string in 'Contents'.
    When: Calling _get_command_error_details.
    Then: Should return the raw string.
    """
    res = {"Contents": "Something went wrong."}
    expected = "Something went wrong."
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected


def test_get_command_error_details_readable_contents_fallback():
    """
    Given: A command result without 'Contents' but with 'ReadableContents'.
    When: Calling _get_command_error_details.
    Then: Should fall back to 'ReadableContents'.
    """
    res = {"ReadableContents": "Fallback error message."}
    expected = "Fallback error message."
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected


def test_get_command_error_details_empty_res():
    """
    Given: An empty command result.
    When: Calling _get_command_error_details.
    Then: Should return "Unknown error".
    """
    res = {}
    expected = "Unknown error"
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected


def test_get_command_error_details_malformed_api_call_json(mocker):
    """
    Given: A command result with "Error in API call" but malformed JSON.
    When: Calling _get_command_error_details.
    Then: Should return the unparsed API error message and log debug.
    """
    # Mock demisto.debug to check if it's called
    mocker_debug = mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'debug')
    res = {"Contents": "Error in API call [500] - This is not JSON."}
    expected = "Unparsed API error: Error in API call [500] - This is not JSON."
    assert BlockExternalIPWithCAPolicy._get_command_error_details(res) == expected
    mocker_debug.assert_called_once()


# --- _execute_demisto_command tests ---

def test_execute_demisto_command_success(mocker):
    """
    Given: A successful Demisto command execution.
    When: Calling _execute_demisto_command.
    Then: Should return the 'Contents' of the result.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'executeCommand',
                        return_value=[{"Contents": {"data": "test"}}])
    mocker.patch("BlockExternalIPWithCAPolicy.isError", return_value=False)
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'debug')

    result = BlockExternalIPWithCAPolicy._execute_demisto_command("test-command", {}, "Prefix")
    assert result == {"data": "test"}
    BlockExternalIPWithCAPolicy.demisto.executeCommand.assert_called_once_with("test-command", {})


def test_execute_demisto_command_empty_response(mocker):
    """
    Given: Demisto command returns an empty list or None.
    When: Calling _execute_demisto_command.
    Then: Should raise DemistoException.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'executeCommand', return_value=[])
    with pytest.raises(DemistoException, match="Prefix: Empty or invalid command result for test-command."):
        BlockExternalIPWithCAPolicy._execute_demisto_command("test-command", {}, "Prefix")

    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'executeCommand', return_value=None)
    with pytest.raises(DemistoException, match="Prefix: Empty or invalid command result for test-command."):
        BlockExternalIPWithCAPolicy._execute_demisto_command("test-command", {}, "Prefix")


def test_execute_demisto_command_error(mocker):
    """
    Given: Demisto command returns an error result.
    When: Calling _execute_demisto_command.
    Then: Should raise DemistoException with parsed error details.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'executeCommand',
                        return_value=[{"Contents": {"error": {"message": "Simulated error"}}, "Type": 8}])
    mocker.patch("BlockExternalIPWithCAPolicy.isError", return_value=True)
    mocker.patch("BlockExternalIPWithCAPolicy._get_command_error_details", return_value="Simulated error")

    with pytest.raises(DemistoException, match="Prefix: Simulated error"):
        BlockExternalIPWithCAPolicy._execute_demisto_command("test-command", {}, "Prefix")


# --- get_blocked_ip_zone_info tests ---

def test_get_blocked_ip_zone_info_found(mocker):
    """
    Given: Okta list zones command returns a BlockedIpZone.
    When: Calling get_blocked_ip_zone_info.
    Then: Should return its ID and gateways.
    """
    mock_zones_response = {
        "result": [
            {"name": "OtherZone", "id": "id1", "gateways": []},
            {"name": "BlockedIpZone", "id": "blocked_id", "gateways": [
                {"type": "CIDR", "value": "1.1.1.0/24"},
                {"type": "RANGE", "value": "2.2.2.1-2.2.2.5"},
                {"type": "OTHER", "value": "xyz"}  # Should be ignored
            ]},
        ]
    }
    mocker.patch("BlockExternalIPWithCAPolicy._execute_demisto_command", return_value=mock_zones_response)

    result = BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info()
    assert result == {"zone_id": "blocked_id", "zone_gateways": ["1.1.1.0/24", "2.2.2.1-2.2.2.5"]}


def test_get_blocked_ip_zone_info_not_found(mocker):
    """
    Given: Okta list zones command does not return a BlockedIpZone.
    When: Calling get_blocked_ip_zone_info.
    Then: Should raise DemistoException.
    """
    mock_zones_response = {"result": [{"name": "OtherZone", "id": "id1", "gateways": []}]}
    mocker.patch("BlockExternalIPWithCAPolicy._execute_demisto_command", return_value=mock_zones_response)

    with pytest.raises(DemistoException, match="BlockedIpZone not found in Okta zones."):
        BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info()


def test_get_blocked_ip_zone_info_unexpected_format(mocker):
    """
    Given: Okta list zones command returns an unexpected format.
    When: Calling get_blocked_ip_zone_info.
    Then: Should raise DemistoException.
    """
    mocker.patch("BlockExternalIPWithCAPolicy._execute_demisto_command", return_value="unexpected string")

    with pytest.raises(DemistoException, match="Unexpected format in okta-list-zones response."):
        BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info()


# --- update_blocked_ip_zone tests ---

def test_update_blocked_ip_zone_ip_not_in_range(mocker):
    """
    Given: An IP not already in the zone gateways.
    When: Calling update_blocked_ip_zone.
    Then: Should update the zone and return success.
    """
    mock_execute = mocker.patch("BlockExternalIPWithCAPolicy._execute_demisto_command")
    mock_return_results = mocker.patch("BlockExternalIPWithCAPolicy.return_results")
    mocker.patch("BlockExternalIPWithCAPolicy.ip_in_range", return_value=False)

    zone_id = "test_zone_id"
    existing_gateways = ["1.1.1.1/32"]
    ip_to_add = "8.8.8.8"

    BlockExternalIPWithCAPolicy.update_blocked_ip_zone(zone_id, existing_gateways, ip_to_add)

    expected_gateways = ["1.1.1.1/32", "8.8.8.8/32"]
    mock_execute.assert_called_once_with(
        "okta-update-zone",
        {
            "zoneID": zone_id,
            "gateways": ",".join(expected_gateways),
            "gatewayIPs": f"{ip_to_add}/32",
            "updateType": "APPEND",
            "type": "IP",
            "name": "BlockedIpZone",
            "status": "ACTIVE"
        },
        "Failed to update BlockedIpZone"
    )
    mock_return_results.assert_called_once_with(f"IP {ip_to_add} added to BlockedIpZone.")


def test_update_blocked_ip_zone_ip_already_in_range(mocker):
    """
    Given: An IP already covered by one of the zone gateways.
    When: Calling update_blocked_ip_zone.
    Then: Should return results early without updating the zone.
    """
    mock_execute = mocker.patch("BlockExternalIPWithCAPolicy._execute_demisto_command")
    mock_return_results = mocker.patch("BlockExternalIPWithCAPolicy.return_results")
    mocker.patch("BlockExternalIPWithCAPolicy.ip_in_range", side_effect=[False, True]) # First check fails, second passes

    zone_id = "test_zone_id"
    existing_gateways = ["1.1.1.1/32", "8.8.8.0/24"]
    ip_to_add = "8.8.8.8" # This IP will be in the second gateway's range

    BlockExternalIPWithCAPolicy.update_blocked_ip_zone(zone_id, existing_gateways, ip_to_add)

    mock_execute.assert_not_called()  # Ensure no update command was called
    mock_return_results.assert_called_once_with(f"IP {ip_to_add} is already covered by entry: 8.8.8.0/24")


# --- Main function tests ---

def test_main_success_add_ip(mocker):
    """
    Given: Valid IP and zone found, IP not already in zone.
    When: Calling main.
    Then: Should add IP to zone and return success message.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'args', return_value={"ip": "9.9.9.9"})
    mocker.patch("BlockExternalIPWithCAPolicy.is_private_ip", return_value=False)
    mocker.patch(
        "BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info",
        return_value={"zone_id": "zone123", "zone_gateways": ["1.1.1.1/32"]}
    )
    # Mock update_blocked_ip_zone to simulate successful update, it already handles return_results
    mocker.patch("BlockExternalIPWithCAPolicy.update_blocked_ip_zone")
    mocker.patch("BlockExternalIPWithCAPolicy.return_error") # Ensure return_error is not called

    BlockExternalIPWithCAPolicy.main()

    BlockExternalIPWithCAPolicy.is_private_ip.assert_called_once_with("9.9.9.9")
    BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info.assert_called_once()
    BlockExternalIPWithCAPolicy.update_blocked_ip_zone.assert_called_once_with("zone123", ["1.1.1.1/32"], "9.9.9.9")
    BlockExternalIPWithCAPolicy.return_error.assert_not_called() # Should not error


def test_main_missing_ip_arg(mocker):
    """
    Given: Missing 'ip' argument.
    When: Calling main.
    Then: Should call return_error.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'args', return_value={})
    mock_return_error = mocker.patch("BlockExternalIPWithCAPolicy.return_error")

    BlockExternalIPWithCAPolicy.main()
    mock_return_error.assert_called_once_with("Missing required argument: ip")


def test_main_private_ip_arg(mocker):
    """
    Given: A private IP address.
    When: Calling main.
    Then: Should call return_error.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'args', return_value={"ip": "192.168.1.100"})
    mocker.patch("BlockExternalIPWithCAPolicy.is_private_ip", return_value=True)
    mock_return_error = mocker.patch("BlockExternalIPWithCAPolicy.return_error")

    BlockExternalIPWithCAPolicy.main()
    mock_return_error.assert_called_once_with("The IP 192.168.1.100 is private/internal and should not be added.")


def test_main_get_blocked_ip_zone_info_failure(mocker):
    """
    Given: get_blocked_ip_zone_info raises an exception.
    When: Calling main.
    Then: Should call return_error.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'args', return_value={"ip": "9.9.9.9"})
    mocker.patch("BlockExternalIPWithCAPolicy.is_private_ip", return_value=False)
    mocker.patch("BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info",
                 side_effect=DemistoException("Zone lookup failed"))
    mock_return_error = mocker.patch("BlockExternalIPWithCAPolicy.return_error")

    BlockExternalIPWithCAPolicy.main()
    mock_return_error.assert_called_once_with("Error blocking IP in Okta zone: Zone lookup failed")


def test_main_update_blocked_ip_zone_failure(mocker):
    """
    Given: update_blocked_ip_zone raises an exception.
    When: Calling main.
    Then: Should call return_error.
    """
    mocker.patch.object(BlockExternalIPWithCAPolicy.demisto, 'args', return_value={"ip": "9.9.9.9"})
    mocker.patch("BlockExternalIPWithCAPolicy.is_private_ip", return_value=False)
    mocker.patch(
        "BlockExternalIPWithCAPolicy.get_blocked_ip_zone_info",
        return_value={"zone_id": "zone123", "zone_gateways": []}
    )
    mocker.patch("BlockExternalIPWithCAPolicy.update_blocked_ip_zone",
                 side_effect=DemistoException("Zone update failed"))
    mock_return_error = mocker.patch("BlockExternalIPWithCAPolicy.return_error")

    BlockExternalIPWithCAPolicy.main()
    mock_return_error.assert_called_once_with("Error blocking IP in Okta zone: Zone update failed")
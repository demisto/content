import pytest
from CommonServerPython import DemistoException
import ipaddress  # Added for direct ipaddress assertions in tests

# Import the module itself for testing, using the correct script name
import OktaAddIPToBlockedIpZone

# For clarity in testing, we can define the script name, though not strictly necessary
SCRIPT_NAME = "OktaAddIPToBlockedIpZone"


# --- Helper functions tests ---


def test_is_private_ip_private(mocker):
    """
    Given: A private IP address.
    When: Calling is_private_ip.
    Then: Should return True.
    """
    # Mock demisto.debug to prevent actual logging during test
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    assert OktaAddIPToBlockedIpZone.is_private_ip("192.168.1.1") is True
    assert OktaAddIPToBlockedIpZone.is_private_ip("10.0.0.5") is True


def test_is_private_ip_public(mocker):
    """
    Given: A public IP address.
    When: Calling is_private_ip.
    Then: Should return False.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    assert OktaAddIPToBlockedIpZone.is_private_ip("8.8.8.8") is False


def test_is_private_ip_invalid(mocker):
    """
    Given: An invalid IP address format.
    When: Calling is_private_ip.
    Then: Should return False and log a debug message.
    """
    mocker_debug = mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")

    assert OktaAddIPToBlockedIpZone.is_private_ip("invalid-ip") is False
    mocker_debug.assert_called_with("Invalid IP address format encountered: invalid-ip")


# --- ip_in_range tests ---


@pytest.mark.parametrize(
    "ip, ip_range, expected",
    [
        ("192.168.1.5", "192.168.1.0/24", True),
        ("192.168.2.1", "192.168.1.0/24", False),
        ("10.0.0.5", "10.0.0.1-10.0.0.10", True),
        ("10.0.0.0", "10.0.0.1-10.0.0.10", False),
        ("10.0.0.11", "10.0.0.1-10.0.0.10", False),
        ("1.1.1.1", "1.1.1.1", True),
        ("1.1.1.2", "1.1.1.1", False),
        ("invalid-ip", "1.1.1.1", False),
        ("1.1.1.1", "invalid-range", False),
        ("1.1.1.1", "1.1.1.1/32", True),
        # New tests for IP version mismatch
        ("2001:db8::1", "1.1.1.1", False),  # IPv6 vs IPv4 single
        ("1.1.1.1", "2001:db8::/32", False),  # IPv4 vs IPv6 network
    ],
)
def test_ip_in_range(mocker, ip, ip_range, expected):
    """
    Tests various scenarios for ip_in_range function.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    assert OktaAddIPToBlockedIpZone.ip_in_range(ip, ip_range) == expected


# --- _get_command_error_details tests ---


def test_get_command_error_details_api_call_json(mocker):
    """
    Given: A command result with "Error in API call" and embedded JSON.
    When: Calling _get_command_error_details.
    Then: Should parse and return the code and message.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {"Contents": 'Error in API call [400] - {"error": {"code": "E0000001", "message": "API error"}}'}
    expected = "E0000001: API error"
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected


def test_get_command_error_details_raw_json_error(mocker):
    """
    Given: A command result where 'Contents' is a direct JSON error object string.
    When: Calling _get_command_error_details.
    Then: Should parse and return the code and message.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {"Contents": '{"error": {"code": "AuthFailed", "message": "Authentication failed"}}'}
    expected = "AuthFailed: Authentication failed"
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected


def test_get_command_error_details_dict_error(mocker):
    """
    Given: A command result where 'Contents' is already a dictionary with an 'error' key.
    When: Calling _get_command_error_details.
    Then: Should extract and return the code and message.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {"Contents": {"error": {"code": "NotFound", "message": "Resource not found"}}}
    expected = "NotFound: Resource not found"
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected


def test_get_command_error_details_simple_string(mocker):
    """
    Given: A command result with a simple string in 'Contents'.
    When: Calling _get_command_error_details.
    Then: Should return the raw string.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {"Contents": "Something went wrong."}
    expected = "Something went wrong."
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected


def test_get_command_error_details_readable_contents_fallback(mocker):
    """
    Given: A command result without 'Contents' but with 'ReadableContents'.
    When: Calling _get_command_error_details.
    Then: Should fall back to 'ReadableContents'.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {"ReadableContents": "Fallback error message."}
    expected = "Fallback error message."
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected


def test_get_command_error_details_empty_res(mocker):
    """
    Given: An empty command result.
    When: Calling _get_command_error_details.
    Then: Should return "Unknown error".
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {}
    expected = "Unknown error"
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected


def test_get_command_error_details_malformed_api_call_json(mocker):
    """
    Given: A command result with "Error in API call" but malformed JSON.
    When: Calling _get_command_error_details.
    Then: Should return the unparsed API error message and log debug.
    """
    mocker_debug = mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")
    res = {"Contents": "Error in API call [500] - This is not JSON."}
    expected = "Unparsed API error: Error in API call [500] - This is not JSON."
    assert OktaAddIPToBlockedIpZone._get_command_error_details(res) == expected
    mocker_debug.assert_called_once()


# --- _execute_command tests (Renamed from _execute_demisto_command) ---


def test_execute_command_success(mocker):  # Renamed test function
    """
    Given: A successful command execution.
    When: Calling _execute_command.
    Then: Should return the 'Contents' of the result.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "executeCommand", return_value=[{"Contents": {"data": "test"}}])
    mocker.patch("OktaAddIPToBlockedIpZone.isError", return_value=False)
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "debug")

    # Call the renamed function
    result = OktaAddIPToBlockedIpZone._execute_command("test-command", {}, "Prefix")
    assert result == {"data": "test"}
    OktaAddIPToBlockedIpZone.demisto.executeCommand.assert_called_once_with("test-command", {})


def test_execute_command_empty_response(mocker):  # Renamed test function
    """
    Given: Command returns an empty list or None.
    When: Calling _execute_command.
    Then: Should raise DemistoException.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "executeCommand", return_value=[])
    with pytest.raises(DemistoException, match="Prefix: Empty or invalid command result for test-command."):
        OktaAddIPToBlockedIpZone._execute_command("test-command", {}, "Prefix")  # Call the renamed function

    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "executeCommand", return_value=None)
    with pytest.raises(DemistoException, match="Prefix: Empty or invalid command result for test-command."):
        OktaAddIPToBlockedIpZone._execute_command("test-command", {}, "Prefix")  # Call the renamed function


def test_execute_command_error(mocker):  # Renamed test function
    """
    Given: Command returns an error result.
    When: Calling _execute_command.
    Then: Should raise DemistoException with parsed error details.
    """
    mocker.patch.object(
        OktaAddIPToBlockedIpZone.demisto,
        "executeCommand",
        return_value=[{"Contents": {"error": {"message": "Simulated error"}}, "Type": 8}],
    )
    mocker.patch("OktaAddIPToBlockedIpZone.isError", return_value=True)
    mocker.patch("OktaAddIPToBlockedIpZone._get_command_error_details", return_value="Simulated error")

    with pytest.raises(DemistoException, match="Prefix: Simulated error"):
        OktaAddIPToBlockedIpZone._execute_command("test-command", {}, "Prefix")  # Call the renamed function


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
            {
                "name": "BlockedIpZone",
                "id": "blocked_id",
                "gateways": [
                    {"type": "CIDR", "value": "1.1.1.0/24"},
                    {"type": "RANGE", "value": "2.2.2.1-2.2.2.5"},
                    {"type": "OTHER", "value": "xyz"},  # Should be ignored
                ],
            },
        ]
    }
    # Mock the renamed _execute_command function
    mocker.patch("OktaAddIPToBlockedIpZone._execute_command", return_value=mock_zones_response)

    result = OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info()
    assert result == {"zone_id": "blocked_id", "zone_gateways": ["1.1.1.0/24", "2.2.2.1-2.2.2.5"]}


def test_get_blocked_ip_zone_info_not_found(mocker):
    """
    Given: Okta list zones command does not return a BlockedIpZone.
    When: Calling get_blocked_ip_zone_info.
    Then: Should raise DemistoException.
    """
    mock_zones_response = {"result": [{"name": "OtherZone", "id": "id1", "gateways": []}]}
    # Mock the renamed _execute_command function
    mocker.patch("OktaAddIPToBlockedIpZone._execute_command", return_value=mock_zones_response)

    with pytest.raises(DemistoException, match="BlockedIpZone not found in Okta zones."):
        OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info()


def test_get_blocked_ip_zone_info_unexpected_format(mocker):
    """
    Given: Okta list zones command returns an unexpected format.
    When: Calling get_blocked_ip_zone_info.
    Then: Should raise DemistoException.
    """
    # Mock the renamed _execute_command function
    mocker.patch("OktaAddIPToBlockedIpZone._execute_command", return_value="unexpected string")

    with pytest.raises(DemistoException, match="Unexpected format in okta-list-zones response."):
        OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info()


# --- update_blocked_ip_zone tests ---


def test_update_blocked_ip_zone_ip_not_in_range(mocker):
    """
    Given: An IP not already in the zone gateways.
    When: Calling update_blocked_ip_zone.
    Then: Should update the zone and return success.
    """
    # Mock the renamed _execute_command function
    mock_execute = mocker.patch("OktaAddIPToBlockedIpZone._execute_command")
    mock_return_results = mocker.patch("OktaAddIPToBlockedIpZone.return_results")
    # Mock ip_in_range to return False for all checks in this specific test
    mocker.patch("OktaAddIPToBlockedIpZone.ip_in_range", return_value=False)

    zone_id = "test_zone_id"
    existing_gateways = ["1.1.1.1/32"]
    ip_to_add = "8.8.8.8"

    OktaAddIPToBlockedIpZone.update_blocked_ip_zone(zone_id, existing_gateways, ip_to_add)

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
            "status": "ACTIVE",
        },
        "Failed to update BlockedIpZone",
    )
    mock_return_results.assert_called_once_with(f"IP {ip_to_add} added to BlockedIpZone.")


def test_update_blocked_ip_zone_ip_already_in_range(mocker):
    """
    Given: An IP already covered by one of the zone gateways.
    When: Calling update_blocked_ip_zone.
    Then: Should return results early without updating the zone.
    """
    # Mock the renamed _execute_command function
    mock_execute = mocker.patch("OktaAddIPToBlockedIpZone._execute_command")
    mock_return_results = mocker.patch("OktaAddIPToBlockedIpZone.return_results")
    # Simulate ip_in_range returning True for one of the checks
    mocker.patch("OktaAddIPToBlockedIpZone.ip_in_range", side_effect=[False, True])

    zone_id = "test_zone_id"
    existing_gateways = ["1.1.1.1/32", "8.8.8.0/24"]
    ip_to_add = "8.8.8.8"  # This IP will be in the second gateway's range

    OktaAddIPToBlockedIpZone.update_blocked_ip_zone(zone_id, existing_gateways, ip_to_add)

    mock_execute.assert_not_called()  # Ensure no update command was called
    mock_return_results.assert_called_once_with(f"IP {ip_to_add} is already covered by entry: 8.8.8.0/24")


# --- Main function tests ---


def test_main_success_add_ip(mocker):
    """
    Given: Valid IPv4 and zone found, IP not already in zone.
    When: Calling main.
    Then: Should add IP to zone and return success message.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "args", return_value={"ip": "9.9.9.9"})
    mocker.patch("OktaAddIPToBlockedIpZone.is_private_ip", return_value=False)
    mocker.patch(
        "OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info", return_value={"zone_id": "zone123", "zone_gateways": ["1.1.1.1/32"]}
    )
    mocker.patch("OktaAddIPToBlockedIpZone.update_blocked_ip_zone")
    mocker.patch("OktaAddIPToBlockedIpZone.return_error")  # Ensure return_error is not called

    OktaAddIPToBlockedIpZone.main()

    OktaAddIPToBlockedIpZone.is_private_ip.assert_called_once_with("9.9.9.9")
    OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info.assert_called_once()
    OktaAddIPToBlockedIpZone.update_blocked_ip_zone.assert_called_once_with("zone123", ["1.1.1.1/32"], "9.9.9.9")
    OktaAddIPToBlockedIpZone.return_error.assert_not_called()


def test_main_private_ip_arg(mocker):
    """
    Given: A private IPv4 address.
    When: Calling main.
    Then: Should call return_error and exit.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "args", return_value={"ip": "192.168.1.100"})
    mock_ipv4_address = mocker.MagicMock(spec=ipaddress.IPv4Address)
    mock_ipv4_address.version = 4
    mocker.patch("OktaAddIPToBlockedIpZone.ipaddress.ip_address", return_value=mock_ipv4_address)

    mocker.patch("OktaAddIPToBlockedIpZone.is_private_ip", return_value=True)

    mock_return_error = mocker.patch("OktaAddIPToBlockedIpZone.return_error")
    mocker.patch("OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info")
    mocker.patch("OktaAddIPToBlockedIpZone.update_blocked_ip_zone")

    OktaAddIPToBlockedIpZone.main()
    OktaAddIPToBlockedIpZone.ipaddress.ip_address.assert_called_once_with("192.168.1.100")
    OktaAddIPToBlockedIpZone.is_private_ip.assert_called_once_with("192.168.1.100")
    mock_return_error.assert_called_once_with("The IP 192.168.1.100 is private/internal and should not be added.")
    OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info.assert_not_called()


@pytest.mark.parametrize(
    "ip_arg, expected_error_msg",
    [
        ("invalid-ip", "The input 'invalid-ip' is not a valid IP address."),
        ("2001:db8::1", "The IP 2001:db8::1 is not an IPv4 address. This script currently supports only IPv4."),
    ],
)
def test_main_ip_validation_failures(mocker, ip_arg, expected_error_msg):
    """
    Given: An invalid IP or a non-IPv4 address as argument.
    When: Calling main.
    Then: Should call return_error with the specific validation message.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "args", return_value={"ip": ip_arg})
    mock_return_error = mocker.patch("OktaAddIPToBlockedIpZone.return_error")
    mocker.patch("OktaAddIPToBlockedIpZone.is_private_ip")
    mocker.patch("OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info")
    mocker.patch("OktaAddIPToBlockedIpZone.update_blocked_ip_zone")

    OktaAddIPToBlockedIpZone.main()
    mock_return_error.assert_called_once_with(expected_error_msg)
    OktaAddIPToBlockedIpZone.is_private_ip.assert_not_called()
    OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info.assert_not_called()


def test_main_get_blocked_ip_zone_info_failure(mocker):
    """
    Given: get_blocked_ip_zone_info raises an exception.
    When: Calling main.
    Then: Should call return_error with both the error message and the exception object.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "args", return_value={"ip": "9.9.9.9"})
    mock_ipv4_address = mocker.MagicMock(spec=ipaddress.IPv4Address)
    mock_ipv4_address.version = 4
    mocker.patch("OktaAddIPToBlockedIpZone.ipaddress.ip_address", return_value=mock_ipv4_address)
    mocker.patch("OktaAddIPToBlockedIpZone.is_private_ip", return_value=False)

    # Define the exception instance separately
    test_exception = DemistoException("Zone lookup failed")
    mocker.patch("OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info", side_effect=test_exception)
    mock_return_error = mocker.patch("OktaAddIPToBlockedIpZone.return_error")

    OktaAddIPToBlockedIpZone.main()

    # The assertion now checks for both the message string and the exception instance
    mock_return_error.assert_called_once_with("Error blocking IP in Okta zone: Zone lookup failed", test_exception)


def test_main_update_blocked_ip_zone_failure(mocker):
    """
    Given: update_blocked_ip_zone raises an exception.
    When: Calling main.
    Then: Should call return_error with both the error message and the exception object.
    """
    mocker.patch.object(OktaAddIPToBlockedIpZone.demisto, "args", return_value={"ip": "9.9.9.9"})
    mock_ipv4_address = mocker.MagicMock(spec=ipaddress.IPv4Address)
    mock_ipv4_address.version = 4
    mocker.patch("OktaAddIPToBlockedIpZone.ipaddress.ip_address", return_value=mock_ipv4_address)
    mocker.patch("OktaAddIPToBlockedIpZone.is_private_ip", return_value=False)

    mocker.patch("OktaAddIPToBlockedIpZone.get_blocked_ip_zone_info", return_value={"zone_id": "zone123", "zone_gateways": []})

    # Define the exception instance to be raised
    test_exception = DemistoException("Zone update failed")
    mocker.patch("OktaAddIPToBlockedIpZone.update_blocked_ip_zone", side_effect=test_exception)
    mock_return_error = mocker.patch("OktaAddIPToBlockedIpZone.return_error")

    OktaAddIPToBlockedIpZone.main()

    # Assert that the return_error function was called with both arguments
    mock_return_error.assert_called_once_with("Error blocking IP in Okta zone: Zone update failed", test_exception)

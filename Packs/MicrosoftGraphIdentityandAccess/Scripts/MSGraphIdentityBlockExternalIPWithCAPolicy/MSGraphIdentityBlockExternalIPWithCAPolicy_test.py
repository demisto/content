import pytest
from unittest.mock import MagicMock

from MSGraphIdentityBlockExternalIPWithCAPolicy import (
    is_private_ip,
    get_azure_command_error_details,
    _execute_command_and_handle_error,
    get_named_ip_location,
    update_existing_named_location,
    create_new_named_ip_location,
    create_conditional_access_policy,
    block_external_ip_with_ca_policy_main_logic,
)


# Mock dependencies globally
@pytest.fixture(autouse=True)
def common_mocks(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.demisto")
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.is_error", return_value=False)
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.return_error", side_effect=Exception)
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.return_results")
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.CommandResults", MagicMock())
    mocker.patch("time.sleep", return_value=None)


def test_is_private_ip_valid():
    assert is_private_ip("192.168.0.1") is True
    assert is_private_ip("8.8.8.8") is False


def test_is_private_ip_invalid(mocker):
    debug = mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.demisto.debug")
    assert is_private_ip("abc.def") is False
    debug.assert_called_once()


def test_get_error_from_json_string():
    """
    Test that a JSON error string embedded after 'Error in API call:' is properly parsed.
    """
    res = {"Contents": 'Error in API call: {"error": {"code": "X", "message": "bad"}}'}
    expected = "X: bad"
    assert get_azure_command_error_details(res) == expected


def test_get_error_from_dict():
    res = {"Contents": {"error": {"code": "Y", "message": "denied"}}}
    assert get_azure_command_error_details(res) == "Y: denied"


def test_get_error_fallback_string():
    res = {"Contents": "Something wrong"}
    assert get_azure_command_error_details(res) == "Something wrong"


def test_get_error_empty():
    assert get_azure_command_error_details({}) == "Unknown error"


class BadStr:
    def __str__(self):
        raise Exception("boom")


def test_get_error_with_forced_exception(mocker):
    mock_debug = mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.demisto.debug")
    res = {"Contents": BadStr()}
    msg = get_azure_command_error_details(res)
    assert "Error extracting error message" in msg
    mock_debug.assert_called()


def test_execute_command_success(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.demisto.executeCommand", return_value=[{"Contents": {"id": "123"}}])
    result = _execute_command_and_handle_error("cmd", {}, "Fail")
    assert result == {"id": "123"}


def test_execute_command_empty(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.demisto.executeCommand", return_value=[])
    with pytest.raises(Exception, match="Empty or invalid command result"):
        _execute_command_and_handle_error("cmd", {}, "Fail")


def test_execute_command_error(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.is_error", return_value=True)
    mocker.patch(
        "MSGraphIdentityBlockExternalIPWithCAPolicy.demisto.executeCommand",
        return_value=[{"Contents": '{"error": {"code": "X", "message": "fail"}}'}],
    )
    with pytest.raises(Exception, match="X: fail"):
        _execute_command_and_handle_error("cmd", {}, "Fail")


def test_get_named_ip_location_found(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy._execute_command_and_handle_error", return_value={"value": [{"id": "x"}]})
    loc = get_named_ip_location("test")
    assert loc["id"] == "x"


def test_get_named_ip_location_not_found(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy._execute_command_and_handle_error", return_value={"value": []})
    assert get_named_ip_location("test") is None


def test_update_named_location_adds_ip(mocker):
    execute = mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy._execute_command_and_handle_error")
    update_existing_named_location("123", "test", ["1.1.1.1/32"], "2.2.2.2/32")
    execute.assert_called_once()
    assert "2.2.2.2/32" in execute.call_args[0][1]["ips"]


def test_update_named_location_duplicate_ip(mocker):
    debug = mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.demisto.debug")
    update_existing_named_location("123", "test", ["1.1.1.1/32"], "1.1.1.1/32")
    debug.assert_called_once_with("IP 1.1.1.1/32 already exists in named location 'test'. No update needed.")


def test_create_named_ip_location_success(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy._execute_command_and_handle_error", return_value={"id": "loc-id"})
    result = create_new_named_ip_location("name", "1.2.3.4")
    assert result == "loc-id"


def test_create_named_ip_location_fail(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy._execute_command_and_handle_error", return_value={})
    with pytest.raises(Exception, match="Named location creation did not return a valid ID."):
        create_new_named_ip_location("name", "1.2.3.4")


def test_create_ca_policy(mocker):
    execute = mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy._execute_command_and_handle_error")
    create_conditional_access_policy("p", "loc")
    assert execute.call_args[0][0] == "msgraph-identity-ca-policy-create"


def test_block_ip_main_new_location(mocker):
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.get_named_ip_location", return_value=None)
    mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.create_new_named_ip_location", return_value="id")
    create_policy = mocker.patch("MSGraphIdentityBlockExternalIPWithCAPolicy.create_conditional_access_policy")
    msg = block_external_ip_with_ca_policy_main_logic("8.8.8.8", "loc", "policy")
    assert ("A new named location 'loc' was created for IP 8.8.8.8 and a new Conditional Access policy 'policy' was created to"
            " block access from this IP.") in msg
    create_policy.assert_called_once()


def test_block_ip_main_existing_location(mocker):
    mocker.patch(
        "MSGraphIdentityBlockExternalIPWithCAPolicy.get_named_ip_location",
        return_value={"id": "x", "ipRanges": []}
    )
    expected_update_message = "IP 8.8.4.4 was successfully added to the existing named location 'loc'."
    update = mocker.patch(
        "MSGraphIdentityBlockExternalIPWithCAPolicy.update_existing_named_location",
        return_value=expected_update_message  # The expected message for this scenario
    )
    msg = block_external_ip_with_ca_policy_main_logic("8.8.4.4", "loc", "policy")
    assert msg == expected_update_message
    update.assert_called_once_with("x", "loc", [], "8.8.4.4/32")


def test_block_ip_main_private_ip():
    with pytest.raises(Exception, match="appears to be internal/private"):
        block_external_ip_with_ca_policy_main_logic("192.168.1.1", "loc", "policy")


def test_block_ip_main_missing_ip():
    with pytest.raises(Exception, match="Missing required argument"):
        block_external_ip_with_ca_policy_main_logic(None, "loc", "policy")

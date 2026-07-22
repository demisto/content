"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json

import pytest
from CommonServerPython import *
from CommonServerPython import DemistoException
from freezegun import freeze_time
from jamfV2 import check_authentication_parameters


def load_xml_response(file_name: str) -> str:
    with open(file_name, encoding="utf-8") as xml_file:
        return xml_file.read()


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_computers_command(mocker):
    """
    Given
    - Get computers command with no arguments.
    When
    - Run get computers command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_computers_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {}
    mock_response = util_load_json("test_data/get_computer/get_computers_raw_response.json")

    mocker.patch.object(client, "get_computers_inventory_request", return_value=mock_response)

    computer_response = get_computers_command(client, args)
    expected_response = util_load_json("test_data/get_computer/get_computers_context.json")
    assert computer_response[0].outputs == expected_response


def test_get_computers_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get computers command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamfV2 import Client, get_computers_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"limit": 10, "page": 2}
    mock_response = util_load_json("test_data/get_computer/get_computers_limit_raw_response.json")

    mocker.patch.object(client, "get_computers_inventory_request", return_value=mock_response)

    response = get_computers_command(client, args)
    expected_response = util_load_json("test_data/get_computer/get_computers_limit_context.json")
    assert response[0].outputs == expected_response


def test_get_computers_by_id_command(mocker):
    """
    Given
    - Computer ID.
    When
    - Run get computer by id command
    Then
    - Get results on specific computer ID.
    """
    from jamfV2 import Client, get_computer_by_id_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": 1}
    mock_response = util_load_json("test_data/get_computer/get_computer_by_id_raw_response.json")

    mocker.patch.object(client, "get_computer_inventory_detail_request", return_value=mock_response)

    response = get_computer_by_id_command(client, args)
    expected_response = util_load_json("test_data/get_computer/get_computer_by_id_context.json")
    assert response.outputs == expected_response


def test_get_computers_by_match_command(mocker):
    """
    Given
    - Match arguments
    When
    - Run get computers command
    Then
    - Ensure the result are according to the id and match args.
    """
    from jamfV2 import Client, get_computer_by_match_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"filter": "udid==CA40F812-60A3-11E4-90B8-12DF261F2C7E"}
    mock_response = util_load_json("test_data/get_computer/get_computer_by_match_raw_response.json")

    mocker.patch.object(client, "get_computers_inventory_request", return_value=mock_response)

    response = get_computer_by_match_command(client, args)
    expected_response = util_load_json("test_data/get_computer/get_computer_by_match_context.json")
    assert response[0].outputs == expected_response


def test_get_computer_general_subset_command(mocker):
    """
    Given
    - Name of the computer and subset arguments.
    When
    - Run get computer subset command
    Then
    - Ensure the command output matched the given query.
    """
    from jamfV2 import Client, get_computer_subset_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"identifier": "name", "identifier_value": "Computer 95"}

    mock_response = util_load_json("test_data/get_computer/get_computer_general_subset_raw_response.json")

    mocker.patch.object(client, "get_computers_inventory_request", return_value=mock_response)

    computer_response = get_computer_subset_command(client, args, "General")
    expected_response = util_load_json("test_data/get_computer/get_computer_general_subset_context.json")

    assert computer_response.outputs == expected_response


def test_get_computer_general_subset_deprecated_command(mocker):
    """
    Given
    - Name of the computer and subset arguments.
    When
    - Run get computer subset command
    Then
    - Ensure the command output matched the given query.
    """
    from jamfV2 import Client, get_computer_subset_deprecated_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"identifier": "name", "identifier_value": "Computer 95"}

    mock_response = util_load_json("test_data/get_computer_subset/get_computer_by_name_general_subset_raw_response.json")

    mocker.patch.object(client, "get_computer_subset_deprecated_request", return_value=mock_response)

    computer_response = get_computer_subset_deprecated_command(client, args, "General")
    expected_response = util_load_json("test_data/get_computer_subset/get_computer_by_name_general_subset_context.json")

    assert computer_response.outputs == expected_response


def test_computer_lock_command_with_id(mocker):
    """
    Given
    - Computer lock command with a numeric computer id and passcode/lock_message.
    When
    - Run computer lock command.
    Then
    - Ensure managementId is resolved from the id, the DEVICE_LOCK MDM command is queued,
      and the context outputs match the preserved schema (name/command_uuid/href/computer_id).
    """
    from jamfV2 import Client, computer_lock_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": "138", "passcode": "123456", "lock_message": "Locked"}

    resolve_mock = mocker.patch.object(client, "resolve_computer_management_id", return_value="6bc9fc18-fa52")
    post_mock = mocker.patch.object(
        client,
        "post_mdm_command",
        return_value=[{"id": "52", "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/52"}],
    )

    result = computer_lock_command(client, args)

    resolve_mock.assert_called_once_with("138")
    post_mock.assert_called_once_with(
        "6bc9fc18-fa52",
        {"commandType": "DEVICE_LOCK", "pin": "123456", "message": "Locked"},
    )
    assert result.outputs == {
        "name": "DeviceLock",
        "command_uuid": "52",
        "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/52",
        "computer_id": "138",
    }


def test_computer_lock_command_with_management_id(mocker):
    """
    Given
    - Computer lock command with an explicit management_id and a phone_number.
    When
    - Run computer lock command.
    Then
    - Ensure managementId resolution is skipped, the phoneNumber is passed through,
      and the management_id is included in the context outputs.
    """
    from jamfV2 import Client, computer_lock_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"management_id": "6bc9fc18-fa52", "phone_number": "123-456-7890"}

    resolve_mock = mocker.patch.object(client, "resolve_computer_management_id")
    post_mock = mocker.patch.object(
        client,
        "post_mdm_command",
        return_value=[{"id": "52", "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/52"}],
    )

    result = computer_lock_command(client, args)

    resolve_mock.assert_not_called()
    post_mock.assert_called_once_with(
        "6bc9fc18-fa52",
        {"commandType": "DEVICE_LOCK", "phoneNumber": "123-456-7890"},
    )
    assert result.outputs == {
        "name": "DeviceLock",
        "command_uuid": "52",
        "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/52",
        "management_id": "6bc9fc18-fa52",
    }


def test_computer_lock_command_missing_identifiers(mocker):
    """
    Given
    - Computer lock command without id and without management_id.
    When
    - Run computer lock command.
    Then
    - Ensure return_error is raised (validation of at least one identifier).
    """
    from jamfV2 import Client, computer_lock_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    return_error_mock = mocker.patch("jamfV2.return_error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        computer_lock_command(client, {"passcode": "123456"})

    return_error_mock.assert_called_once()


def test_computer_erase_command(mocker):
    """
    Given
    - Erase computer command with id and passcode.
    When
    - Run erase computer command.
    Then
    - Ensure the dedicated erase endpoint is called with {"pin": passcode} and the
      preserved context outputs (name/command_uuid/computer_id) are emitted.
    """
    from jamfV2 import Client, computer_erase_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": "138", "passcode": "123456"}

    erase_mock = mocker.patch.object(
        client,
        "computer_erase_request",
        return_value={"deviceId": "138", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )

    result = computer_erase_command(client, args)

    erase_mock.assert_called_once_with("138", "123456")
    assert result.outputs == {
        "name": "EraseDevice",
        "command_uuid": "b2a5b2e8-814b-461a-a406-02231c11f179",
        "computer_id": "138",
    }


def test_resolve_computer_management_id(mocker):
    """
    Given
    - A numeric computer id.
    When
    - Client.resolve_computer_management_id is called.
    Then
    - Ensure it GETs computers-inventory GENERAL section and returns general.managementId
      (device-level, not the per-user userManagementInfo managementId).
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        return_value={"id": "138", "general": {"managementId": "6bc9fc18-fa52"}},
    )

    management_id = client.resolve_computer_management_id("138")

    assert management_id == "6bc9fc18-fa52"
    assert http_mock.call_args.kwargs["url_suffix"] == "/api/v3/computers-inventory/138"
    assert http_mock.call_args.kwargs["params"] == {"section": "GENERAL"}


def test_post_mdm_command(mocker):
    """
    Given
    - A managementId and commandData payload.
    When
    - Client.post_mdm_command is called.
    Then
    - Ensure it POSTs to /api/v2/mdm/commands with the correct clientData/commandData body
      and returns the API response list.
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        return_value=[{"id": "52", "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/52"}],
    )

    response = client.post_mdm_command("6bc9fc18-fa52", {"commandType": "DEVICE_LOCK", "pin": "123456"})

    assert response == [{"id": "52", "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/52"}]
    assert http_mock.call_args.kwargs["method"] == "POST"
    assert http_mock.call_args.kwargs["url_suffix"] == "/api/v2/mdm/commands"
    assert http_mock.call_args.kwargs["json_data"] == {
        "clientData": [{"managementId": "6bc9fc18-fa52"}],
        "commandData": {"commandType": "DEVICE_LOCK", "pin": "123456"},
    }


def test_computer_erase_request(mocker):
    """
    Given
    - A numeric computer id and passcode.
    When
    - Client.computer_erase_request is called.
    Then
    - Ensure it POSTs to the dedicated /api/v1/computer-inventory/{id}/erase endpoint with {"pin": passcode}.
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        return_value={"deviceId": "138", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )

    response = client.computer_erase_request("138", "123456")

    assert response == {"deviceId": "138", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"}
    assert http_mock.call_args.kwargs["method"] == "POST"
    assert http_mock.call_args.kwargs["url_suffix"] == "/api/v1/computer-inventory/138/erase"
    assert http_mock.call_args.kwargs["json_data"] == {"pin": "123456"}


def test_computer_erase_request_without_passcode(mocker):
    """
    Given
    - A numeric computer id and no passcode.
    When
    - Client.computer_erase_request is called.
    Then
    - Ensure the request body omits the "pin" field entirely (sends {} rather than {"pin": None}).
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        return_value={"deviceId": "138", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )

    response = client.computer_erase_request("138")

    assert response == {"deviceId": "138", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"}
    assert http_mock.call_args.kwargs["method"] == "POST"
    assert http_mock.call_args.kwargs["url_suffix"] == "/api/v1/computer-inventory/138/erase"
    assert http_mock.call_args.kwargs["json_data"] == {}
    assert "pin" not in http_mock.call_args.kwargs["json_data"]


def test_get_users_command_by_id(mocker):
    """
    Given
    - get-users command with an id argument.
    When
    - Run get_users_command.
    Then
    - Ensure the Pro API by-id endpoint is called and the single user is normalized
      (realname -> name, phone -> phone_number) with new Pro fields preserved.
    """
    from jamfV2 import Client, get_users_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    raw_user = {
        "id": "1",
        "realname": "John Doe",
        "email": "john@example.com",
        "phone": "123-456-7890",
        "position": "Engineer",
        "managedAppleId": "john@managed.example.com",
        "enableCustomPhotoUrl": False,
        "customPhotoUrl": "",
    }
    by_id_mock = mocker.patch.object(client, "get_user_by_id_request", return_value=raw_user)

    results = get_users_command(client, {"id": "1"})

    by_id_mock.assert_called_once_with("1")
    outputs = results[0].outputs
    assert outputs == [
        {
            "id": "1",
            "realname": "John Doe",
            "email": "john@example.com",
            "phone": "123-456-7890",
            "position": "Engineer",
            "managedAppleId": "john@managed.example.com",
            "enableCustomPhotoUrl": False,
            "customPhotoUrl": "",
            "name": "John Doe",
            "phone_number": "123-456-7890",
        }
    ]
    assert results[1].outputs == {"total_results": 1, "page_size": 50, "current_page": 0}


def test_get_users_command_by_name_filter(mocker):
    """
    Given
    - get-users command with a name argument.
    When
    - Run get_users_command.
    Then
    - Ensure the Pro list endpoint is called with the RSQL username filter and
      the response is normalized.
    """
    from jamfV2 import Client, get_users_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    pro_response = {
        "totalCount": 1,
        "results": [{"id": "5", "realname": "Jane", "email": "jane@example.com", "phone": "555"}],
    }
    list_mock = mocker.patch.object(client, "get_users_pro_request", return_value=pro_response)

    results = get_users_command(client, {"name": "jane"})

    list_mock.assert_called_once_with(limit=50, page=0, filter_query='username=="jane"')
    assert results[0].outputs == [
        {
            "id": "5",
            "realname": "Jane",
            "email": "jane@example.com",
            "phone": "555",
            "name": "Jane",
            "phone_number": "555",
        }
    ]


def test_get_users_command_by_email_filter(mocker):
    """
    Given
    - get-users command with an email argument.
    When
    - Run get_users_command.
    Then
    - Ensure the Pro list endpoint is called with the RSQL email filter.
    """
    from jamfV2 import Client, get_users_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    pro_response = {
        "totalCount": 1,
        "results": [{"id": "9", "realname": "Bob", "email": "bob@example.com", "phone": "777"}],
    }
    list_mock = mocker.patch.object(client, "get_users_pro_request", return_value=pro_response)

    results = get_users_command(client, {"email": "bob@example.com"})

    list_mock.assert_called_once_with(limit=50, page=0, filter_query='email=="bob@example.com"')
    assert results[0].outputs == [
        {
            "id": "9",
            "realname": "Bob",
            "email": "bob@example.com",
            "phone": "777",
            "name": "Bob",
            "phone_number": "777",
        }
    ]


def test_get_users_command_list_with_pagination(mocker):
    """
    Given
    - get-users command with limit and page arguments and no id/name/email.
    When
    - Run get_users_command.
    Then
    - Ensure server-side pagination is used (page/page-size passed through, no client-side
      slicing) and all returned users are normalized. totalCount drives the paging output.
    """
    from jamfV2 import Client, get_users_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    # The API already returns only the requested page; the command must NOT slice further.
    pro_response = {
        "totalCount": 42,
        "results": [
            {"id": "1", "realname": "User One", "email": "one@example.com", "phone": "111"},
            {"id": "2", "realname": "User Two", "email": "two@example.com", "phone": "222"},
        ],
    }
    list_mock = mocker.patch.object(client, "get_users_pro_request", return_value=pro_response)

    results = get_users_command(client, {"limit": 10, "page": 2})

    list_mock.assert_called_once_with(limit=10, page=2, filter_query=None)
    outputs = results[0].outputs
    # No client-side slicing: both users from the page are returned as-is.
    assert len(outputs) == 2
    assert outputs[0]["name"] == "User One"
    assert outputs[0]["phone_number"] == "111"
    assert outputs[1]["name"] == "User Two"
    assert outputs[1]["phone_number"] == "222"
    assert results[1].outputs == {"total_results": 42, "page_size": 10, "current_page": 2}


def test_get_mobile_devices_command(mocker):
    """
    Given
    - Get mobile devices command with no arguments.
    When
    - Run get mobile devices command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_mobile_devices_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {}
    mock_response = util_load_json("test_data/get_mobile_devices/get_mobile_devices_raw_response.json")

    mocker.patch.object(client, "get_mobile_devices_request", return_value=mock_response)

    devices_response = get_mobile_devices_command(client, args)
    expected_response = util_load_json("test_data/get_mobile_devices/get_mobile_devices_context.json")
    assert devices_response[0].outputs == expected_response


def test_get_mobile_devices_limit_command(mocker):
    """
    Given
    - Limit and page arguments
    When
    - Run get mobile devices command
    Then
    - Ensure the result are according to the limit and page
    """
    from jamfV2 import Client, get_mobile_devices_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"limit": 10, "page": 1}
    mock_response = util_load_json("test_data/get_mobile_devices/get_mobile_devices_raw_response.json")

    mocker.patch.object(client, "get_mobile_devices_request", return_value=mock_response)

    devices_response = get_mobile_devices_command(client, args)
    expected_response = util_load_json("test_data/get_mobile_devices/get_mobile_devices_limit_context.json")
    assert devices_response[0].outputs == expected_response


def test_get_mobile_devices_by_id_command(mocker):
    """
    Given
    - Mobile device ID.
    When
    - Run get mobile devices command
    Then
    - Get results on specific mobile device ID.
    """
    from jamfV2 import Client, get_mobile_device_by_id_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": 1}
    mock_response = util_load_json("test_data/get_mobile_devices/get_mobile_device_by_id_raw_response.json")

    mocker.patch.object(client, "get_mobile_devices_request", return_value=mock_response)

    devices_response = get_mobile_device_by_id_command(client, args)
    expected_response = util_load_json("test_data/get_mobile_devices/get_mobile_device_by_id_context.json")
    assert devices_response.outputs == expected_response


def test_get_mobile_devices_by_match_command(mocker):
    """
    Given
    - Match argument
    When
    - Run get mobile devices command
    Then
    - Ensure the result are according to the match arg.
    """
    from jamfV2 import Client, get_mobile_devices_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"match": "ab12cdc060a311e490b812*"}
    mock_response = util_load_json("test_data/get_mobile_devices/get_mobile_device_by_match_raw_response.json")

    mocker.patch.object(client, "get_mobile_devices_request", return_value=mock_response)

    devices_response = get_mobile_devices_command(client, args)
    expected_response = util_load_json("test_data/get_mobile_devices/get_mobile_device_by_match_context.json")
    assert devices_response[0].outputs == expected_response


def test_get_mobile_device_general_subset_command(mocker):
    """
    Given
    - UDID of the mobile device and subset arguments.
    When
    - Run get mobile device general subset command
    Then
    - Ensure the command output matched the given query.
    """
    from jamfV2 import Client, get_mobile_device_subset_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"identifier": "udid", "identifier_value": "ab12f4c660a311e490b812df261f2c7e"}
    mock_response = util_load_json("test_data/get_mobile_device_subset/get_mobile_device_by_udid_subset_raw_response.json")

    mocker.patch.object(client, "get_mobile_devices_subset_request", return_value=mock_response)

    device_response = get_mobile_device_subset_command(client, args, "General")
    expected_response = util_load_json("test_data/get_mobile_device_subset/get_mobile_device_by_udid_subset_context.json")
    assert device_response.outputs == expected_response


def test_get_computers_by_app_command(mocker):
    """
    Given
    - Application argument.
    When
    - Run get computers by app command
    Then
    - Ensure the response matches the default limit.
    """
    from jamfV2 import Client, get_computers_by_app_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"application": "safar*"}
    mock_response = util_load_json("test_data/get_computer_by_app/get_computer_by_app_raw_response.json")

    mocker.patch.object(client, "get_computers_by_app_request", return_value=mock_response)

    computer_response = get_computers_by_app_command(client, args)
    expected_response = util_load_json("test_data/get_computer_by_app/get_computer_by_app_context.json")
    assert computer_response[0].outputs == expected_response


def test_resolve_mobile_device_management_id(mocker):
    """
    Given
    - A numeric mobile device id.
    When
    - Client.resolve_mobile_device_management_id is called.
    Then
    - Ensure it GETs the mobile-devices detail endpoint and returns the top-level managementId.
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        return_value={"id": "1", "managementId": "73226fb6-d507"},
    )

    management_id = client.resolve_mobile_device_management_id("1")

    assert management_id == "73226fb6-d507"
    assert http_mock.call_args.kwargs["method"] == "GET"
    assert http_mock.call_args.kwargs["url_suffix"] == "/api/v2/mobile-devices/1/detail"


def test_resolve_mobile_device_management_id_missing(mocker):
    """
    Given
    - A mobile device detail response missing the managementId.
    When
    - Client.resolve_mobile_device_management_id is called.
    Then
    - Ensure a DemistoException is raised.
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    mocker.patch.object(client, "_http_request", return_value={"id": "1"})

    with pytest.raises(DemistoException):
        client.resolve_mobile_device_management_id("1")


def test_mobile_device_lost_command_with_id(mocker):
    """
    Given
    - Mobile device lost-mode command with a numeric id and lost_mode_message/lost_mode_phone.
    When
    - Run mobile device lost command.
    Then
    - Ensure managementId is resolved from the id, the ENABLE_LOST_MODE MDM command is queued,
      and the context outputs match the schema (name/id/href/management_id).
    """
    from jamfV2 import Client, mobile_device_lost_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": "1", "lost_mode_message": "Lost", "lost_mode_phone": "123-456-7890"}

    resolve_mock = mocker.patch.object(client, "resolve_mobile_device_management_id", return_value="73226fb6-d507")
    post_mock = mocker.patch.object(
        client,
        "post_mdm_command",
        return_value=[{"id": "53", "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/53"}],
    )

    result = mobile_device_lost_command(client, args)

    resolve_mock.assert_called_once_with("1")
    post_mock.assert_called_once_with(
        "73226fb6-d507",
        {"commandType": "ENABLE_LOST_MODE", "lostModeMessage": "Lost", "lostModePhone": "123-456-7890"},
    )
    assert result.outputs == {
        "name": "EnableLostMode",
        "id": "53",
        "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/53",
        "management_id": "73226fb6-d507",
    }


def test_mobile_device_lost_command_with_management_id(mocker):
    """
    Given
    - Mobile device lost-mode command with an explicit management_id and a footnote.
    When
    - Run mobile device lost command.
    Then
    - Ensure managementId resolution is skipped and the footnote is passed through.
    """
    from jamfV2 import Client, mobile_device_lost_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"management_id": "73226fb6-d507", "lost_mode_message": "Lost", "lost_mode_footnote": "Reward"}

    resolve_mock = mocker.patch.object(client, "resolve_mobile_device_management_id")
    post_mock = mocker.patch.object(
        client,
        "post_mdm_command",
        return_value=[{"id": "53", "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/53"}],
    )

    result = mobile_device_lost_command(client, args)

    resolve_mock.assert_not_called()
    post_mock.assert_called_once_with(
        "73226fb6-d507",
        {"commandType": "ENABLE_LOST_MODE", "lostModeMessage": "Lost", "lostModeFootnote": "Reward"},
    )
    assert result.outputs == {
        "name": "EnableLostMode",
        "id": "53",
        "href": "https://yourServer.jamfcloud.com/api/v2/mdm/commands/53",
        "management_id": "73226fb6-d507",
    }


def test_mobile_device_lost_command_missing_message_and_phone(mocker):
    """
    Given
    - Mobile device lost-mode command without lost_mode_message and without lost_mode_phone.
    When
    - Run mobile device lost command.
    Then
    - Ensure return_error is raised (validation requires at least one of message/phone).
    """
    from jamfV2 import Client, mobile_device_lost_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    return_error_mock = mocker.patch("jamfV2.return_error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        mobile_device_lost_command(client, {"id": "1", "lost_mode_footnote": "Reward"})

    return_error_mock.assert_called_once()


def test_mobile_device_erase_command(mocker):
    """
    Given
    - Mobile device erase command with id and the new boolean options.
    When
    - Run mobile device erase command.
    Then
    - Ensure the dedicated erase request is called with the boolean fields and the
      preserved context outputs (name/command_uuid/id) are emitted.
    """
    from jamfV2 import Client, mobile_device_erase_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {
        "id": "114",
        "preserve_data_plan": "true",
        "disallow_proximity_setup": "true",
        "clear_activation_lock": "true",
        "return_to_service": "false",
    }

    erase_mock = mocker.patch.object(
        client,
        "mobile_device_erase_request",
        return_value={"deviceId": "114", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )
    mocker.patch.object(client, "resolve_mobile_device_management_id", return_value="73226fb6-d507")

    result = mobile_device_erase_command(client, args)

    erase_mock.assert_called_once_with(
        "114",
        preserve_data_plan=True,
        disallow_proximity_setup=True,
        clear_activation_lock=True,
        return_to_service=False,
    )
    assert result.outputs == {
        "name": "EraseDevice",
        "command_uuid": "b2a5b2e8-814b-461a-a406-02231c11f179",
        "id": "114",
        "management_id": "73226fb6-d507",
    }


def test_mobile_device_erase_command_alias_only(mocker):
    """
    Given
    - Mobile device erase command using only the deprecated clear_activation_code alias.
    When
    - Run mobile device erase command.
    Then
    - Ensure the alias value is used for clearActivationLock.
    """
    from jamfV2 import Client, mobile_device_erase_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": "114", "clear_activation_code": "true"}

    erase_mock = mocker.patch.object(
        client,
        "mobile_device_erase_request",
        return_value={"deviceId": "114", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )
    mocker.patch.object(client, "resolve_mobile_device_management_id", return_value="73226fb6-d507")

    mobile_device_erase_command(client, args)

    erase_mock.assert_called_once_with(
        "114",
        preserve_data_plan=False,
        disallow_proximity_setup=False,
        clear_activation_lock=True,
        return_to_service=False,
    )


def test_mobile_device_erase_command_alias_precedence(mocker):
    """
    Given
    - Mobile device erase command with both clear_activation_lock and the deprecated
      clear_activation_code alias set to conflicting values.
    When
    - Run mobile device erase command.
    Then
    - Ensure the canonical clear_activation_lock wins over the deprecated alias.
    """
    from jamfV2 import Client, mobile_device_erase_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": "114", "clear_activation_lock": "false", "clear_activation_code": "true"}

    erase_mock = mocker.patch.object(
        client,
        "mobile_device_erase_request",
        return_value={"deviceId": "114", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )
    mocker.patch.object(client, "resolve_mobile_device_management_id", return_value="73226fb6-d507")

    mobile_device_erase_command(client, args)

    erase_mock.assert_called_once_with(
        "114",
        preserve_data_plan=False,
        disallow_proximity_setup=False,
        clear_activation_lock=False,
        return_to_service=False,
    )


def test_mobile_device_erase_request(mocker):
    """
    Given
    - A mobile device id and erase option booleans.
    When
    - Client.mobile_device_erase_request is called.
    Then
    - Ensure it POSTs to the dedicated v2 erase endpoint with the correct JSON body.
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        return_value={"deviceId": "114", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"},
    )

    response = client.mobile_device_erase_request(
        "114",
        preserve_data_plan=False,
        disallow_proximity_setup=False,
        clear_activation_lock=True,
        return_to_service=False,
    )

    assert response == {"deviceId": "114", "commandUuid": "b2a5b2e8-814b-461a-a406-02231c11f179"}
    assert http_mock.call_args.kwargs["method"] == "POST"
    assert http_mock.call_args.kwargs["url_suffix"] == "/api/v2/mobile-devices/114/erase"
    assert http_mock.call_args.kwargs["json_data"] == {
        "preserveDataPlan": False,
        "disallowProximitySetup": False,
        "clearActivationLock": True,
        "returnToService": False,
    }


def test_mdm_command_status_filter_from_individual_args(mocker):
    """
    Given
    - jamf-mdm-command-status command with individual args (status, command_name).
    When
    - Run mdm_command_status_command.
    Then
    - Ensure the RSQL filter is built from the individual args (ANDed with ';'),
      page/page-size passed through, and results/paging returned.
    """
    from jamfV2 import Client, mdm_command_status_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    api_response = {
        "totalCount": 1,
        "results": [
            {
                "uuid": "b2a5b2e8-814b-461a-a406-02231c11f179",
                "commandType": "REMOVE_PROFILE",
                "commandState": "PENDING",
                "dateSent": "2024-01-01T00:00:00Z",
                "dateCompleted": None,
                "client": {"managementId": "4810a46e-2941-414e-a6c0-c1bf303e2117", "clientType": "COMPUTER"},
            }
        ],
    }
    request_mock = mocker.patch.object(client, "get_mdm_commands_request", return_value=api_response)

    results = mdm_command_status_command(
        client,
        {
            "management_id": "4810a46e-2941-414e-a6c0-c1bf303e2117",
            "status": "Pending",
            "command_name": "REMOVE_PROFILE",
            "limit": 25,
            "page": 1,
        },
    )

    request_mock.assert_called_once_with(
        filter_query='clientManagementId=="4810a46e-2941-414e-a6c0-c1bf303e2117";status=="Pending";command=="REMOVE_PROFILE"',
        limit=25,
        page=1,
    )
    assert results[0].outputs == api_response["results"]
    assert results[1].outputs == {"total_results": 1, "page_size": 25, "current_page": 1}


def test_mdm_command_status_management_id_filter_field(mocker):
    """
    Given
    - jamf-mdm-command-status command with only the management_id arg.
    When
    - Run mdm_command_status_command.
    Then
    - Ensure the built RSQL filter uses the flat 'clientManagementId' field, not the dotted 'client.managementId' response path.
    """
    from jamfV2 import Client, mdm_command_status_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    request_mock = mocker.patch.object(client, "get_mdm_commands_request", return_value={"totalCount": 0, "results": []})

    mdm_command_status_command(client, {"management_id": "4810a46e-2941-414e-a6c0-c1bf303e2117"})

    request_mock.assert_called_once_with(
        filter_query='clientManagementId=="4810a46e-2941-414e-a6c0-c1bf303e2117"',
        limit=50,
        page=0,
    )


def test_mdm_command_status_raw_filter_override(mocker):
    """
    Given
    - jamf-mdm-command-status command with a raw 'filter' arg AND individual args.
    When
    - Run mdm_command_status_command.
    Then
    - Ensure the raw filter takes precedence and the individual args are ignored.
    """
    from jamfV2 import Client, mdm_command_status_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    request_mock = mocker.patch.object(client, "get_mdm_commands_request", return_value={"totalCount": 0, "results": []})

    mdm_command_status_command(
        client,
        {"filter": "clientType==COMPUTER_USER", "status": "Pending", "command_uuid": "should-be-ignored"},
    )

    request_mock.assert_called_once_with(filter_query="clientType==COMPUTER_USER", limit=50, page=0)


def test_mdm_command_status_missing_args_validation(mocker):
    """
    Given
    - jamf-mdm-command-status command with no filter and no individual filter args.
    When
    - Run mdm_command_status_command.
    Then
    - Ensure return_error is raised (a filter is mandatory).
    """
    from jamfV2 import Client, mdm_command_status_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    request_mock = mocker.patch.object(client, "get_mdm_commands_request")
    mocker.patch("jamfV2.return_error", side_effect=SystemExit)

    with pytest.raises(SystemExit):
        mdm_command_status_command(client, {"limit": 50, "page": 0})

    request_mock.assert_not_called()


def test_computers_endpoint_request(mocker):
    """
    test helper function for the endpoint command.
    """
    from jamfV2 import Client, computers_endpoint_request

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)

    mock_response = util_load_json("test_data/get_computer/get_computer_general_subset_raw_response.json")

    mocker.patch.object(client, "get_computers_inventory_request", return_value=mock_response)

    mapped_response_list, _ = computers_endpoint_request(client, filter_query="id==1")

    expected_mapped_response_list = [
        {
            "id": "1",
            "name": "Computer 95",
            "ip": "123.243.192.20",
            "platform": "Mac",
            "mac_address": "68:5B:35:CA:12:56",
            "udid": "CA40F812-60A3-11E4-90B8-12DF261F2C7E",
        }
    ]

    assert mapped_response_list == expected_mapped_response_list


def test_endpoint_command(mocker):
    """
    Given:
        - endpoint_command
    When:
        - Filtering using both id and hostname
    Then:
        - Verify that duplicates are removed (since the mock is called twice the same endpoint is retrieved, but if
        working properly, only one result should be returned).
    """
    from CommonServerPython import Common
    from jamfV2 import Client, endpoint_command

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": "1", "ip": "123.243.192.20", "hostname": "Computer 95"}

    mock_mapped_response = [
        {
            "id": "1",
            "name": "Computer 95",
            "ip": "123.243.192.20",
            "platform": "Mac",
            "mac_address": "68:5B:35:CA:12:56",
            "udid": "CA40F812-60A3-11E4-90B8-12DF261F2C7E",
        }
    ]

    mocker.patch("jamfV2.computers_endpoint_request", return_value=(mock_mapped_response, []))

    outputs = endpoint_command(client, args)

    get_endpoints_response = {
        Common.Endpoint.CONTEXT_PATH: [
            {
                "ID": "1",
                "Hostname": "Computer 95",
                "OS": "Mac",
                "Vendor": "JAMF v2",
                "MACAddress": "68:5B:35:CA:12:56",
                "IPAddress": "123.243.192.20",
            }
        ]
    }

    results = outputs[0].to_context()
    assert results.get("EntryContext") == get_endpoints_response
    assert len(outputs) == 1


@pytest.mark.parametrize(
    "client_id, client_secret, username, password",
    [
        ("client_id", "client_secret", None, None),
        (None, None, "username", "password"),
    ],
)
def test_check_authentication_parameters__no_exception(client_id, client_secret, username, password):
    """
    Given:
        - client_id, client_secret, username, and password
        case 1: client_id and client_secret are provided, but username, password are not
        case 2: client_id, client_secret are not provided, but username, password are provided
    When:
        - check_authentication_parameters is called
    Then:
        - Ensure the function dose not raise an exception
    """
    check_authentication_parameters(client_id, client_secret, username, password)


@pytest.mark.parametrize(
    "client_id, client_secret, username, password",
    [
        ("client_id", "client_secret", "username", "password"),
        (None, None, None, None),
        ("client_id", None, "username", None),
        (None, "client_secret", None, "password"),
    ],
)
def test_check_authentication_parameters__raises_exception(client_id, client_secret, username, password):
    """
    Given:
        - client_id, client_secret, username, and password
        case 1: None of the parameters are provided
        case 2: client_id and username are provided, but client_secret, password are not
        case 3: client_secret and password are provided, but client_id, username are not

    When:
        - check_authentication_parameters is called
    Then:
        - Ensure the function raises an exception
    """
    with pytest.raises(DemistoException):
        check_authentication_parameters(client_id, client_secret, username, password)


def test_generate_token__basic_auth_no_token(mocker):
    """
    Given:
        - A Client instance with username and password and basic_auth_flag set to True
    When:
        - _generate_token is called but no token is generated
    Then:
        - Ensure the http_request will use the username and password for authentication (basic auth) since
        their is no token, and the basic_auth_flag is set to True

    """

    from jamfV2 import Client

    mocker.patch.object(Client, "_http_request")
    mocker.patch.object(Client, "_get_token", side_effect=DemistoException("Mocked exception"))
    client = Client(
        base_url="https://example.com", verify=False, proxy=False, token=None, username="username", password="password"
    )
    mocker.patch("jamfV2.get_integration_context")
    mocker.patch("jamfV2.set_integration_context")
    client._classic_api_post(url_suffix="test", data=None, error_handler=None)

    assert client._http_request.call_args.kwargs.get("auth") == ("username", "password")


@freeze_time("2024-04-01")
def test_generate_basic_auth_token(mocker):
    """
    Given:
        - A Client instance with username and password
    When:
        - generate_basic_auth_token is called
    Then:
        - Ensure the function returns the token and expiration time correctly
        - Ensure the http_request is called with the correct arguments
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_http_request").return_value = {"token": "mocked token", "expires": "2022-12-31T23:59:59Z"}
    client = Client(base_url="https://example.com", verify=False, proxy=False, username="username", password="password")

    assert client.generate_basic_auth_token() == ("mocked token", 1672531199)
    assert client._http_request.call_args.kwargs == {
        "method": "POST",
        "url_suffix": "api/v1/auth/token",
        "resp_type": "json",
        "auth": ("username", "password"),
    }  # noqa


@freeze_time("2024-04-01")
def test_generate_client_credentials_token(mocker):
    """
    Given:
        - A Client instance with client_id and client_secret
    When:
        - generate_client_credentials_token is called
    Then:
        - Ensure the function returns the token and expiration time correctly
        - Ensure the http_request is called with the correct arguments
    """
    from jamfV2 import Client

    mocker.patch.object(Client, "_http_request").return_value = {"access_token": "mocked token", "expires_in": 1119}
    client = Client(
        base_url="https://example.com", verify=False, proxy=False, client_id="client_id", client_secret="client_secret"
    )
    assert client.generate_client_credentials_token() == ("mocked token", 1711930719.0)
    assert client._http_request.call_args.kwargs["url_suffix"] == "/api/v1/oauth/token"
    assert client._http_request.call_args.kwargs["data"] == {
        "client_id": "client_id",
        "grant_type": "client_credentials",
        "client_secret": "client_secret",
    }  # noqa
    assert client._http_request.call_args.kwargs["headers"] == {"Content-Type": "application/x-www-form-urlencoded"}


def test_generate_token(mocker):
    """
    Given:
        - A Client instance with client_id and client_secret or username and password
    When:
        - generate_token is called
    Then:
        - Ensure the function calls the correct token generation function based on the provided parameters
    """
    from jamfV2 import Client

    client_credentials_token = mocker.patch.object(
        Client, "generate_client_credentials_token", return_value=("mocked token", 1711930719.0)
    )
    basic_auth_token = mocker.patch.object(Client, "generate_basic_auth_token", return_value=("mocked token", 1672531199))

    Client(base_url="https://example.com", verify=False, proxy=False, client_id="client_id", client_secret="client_secret")
    assert client_credentials_token.call_count == 1

    Client(base_url="https://example.com", verify=False, proxy=False, username="username", password="password")
    assert basic_auth_token.call_count == 1


def test_get_computer_configuration_profiles_by_id(mocker):
    """
    Given:
        - Computer ID
    When:
        - get_profile_configuration_osx is called
    Then:
        - Ensure the function returns the correct output
    """
    from jamfV2 import Client, get_profile_configuration_osx

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": 1}
    mock_response = util_load_json(
        "test_data/get_computer_configuration_profiles/get_computer_configuration_profiles_by_id_raw_response.json"
    )
    mocker.patch.object(client, "get_osxconfigurationprofiles_by_id", return_value=mock_response)

    outputs = get_profile_configuration_osx(client, args)
    assert outputs.outputs["general"]["id"] == 1


def test_get_mobile_configuration_profiles_by_id(mocker):
    """
    Given:
        - Mobile ID
    When:
        - get_profile_configuration_mobile is called
    Then:
        - Ensure the function returns the correct output
    """
    from jamfV2 import Client, get_profile_configuration_mobile

    mocker.patch.object(Client, "_get_token")
    client = Client(base_url="https://paloaltonfr3.jamfcloud.com", verify=False)
    args = {"id": 1}
    mock_response = util_load_json(
        "test_data/get_mobile_configuration_profiles/get_mobile_configuration_profiles_by_id_raw_response.json"
    )
    mocker.patch.object(client, "get_mobiledeviceconfigurationprofiles_by_id", return_value=mock_response)

    outputs = get_profile_configuration_mobile(client, args)
    assert outputs.outputs["general"]["id"] == 1


@pytest.mark.parametrize(
    "query, expected",
    [
        pytest.param(
            "general.name=='MacBook'",
            ["GENERAL"],
            id="Simple single keyword (Full Path)",
        ),
        pytest.param(
            "hardware.serialNumber=='XYZ123'",
            ["HARDWARE"],
            id="Simple single keyword (Full Path - Updated from Alias)",
        ),
        pytest.param(
            "HARDWARE.MACADDRESS=='00:00:00:00'",
            ["HARDWARE"],
            id="Case Insensitivity check",
        ),
        pytest.param(
            "general.assetTag=='123' and general.barcode1=='456'",
            ["GENERAL"],
            id="Multiple keywords same section",
        ),
        pytest.param(
            "hardware.model=='MacBook Pro' and operatingsystem.version=='14.1'",
            ["HARDWARE", "OPERATING_SYSTEM"],
            id="Multiple keywords different sections (Full Paths)",
        ),
        pytest.param(
            "userandlocation.buildingId=in=(1, 2, 3)",
            ["USER_AND_LOCATION"],
            id="Using the =in= operator",
        ),
        pytest.param(
            "purchasing.purchased!='2023-01-01'",
            ["PURCHASING"],
            id="Using the != operator",
        ),
        pytest.param(
            "general.remoteManagement.managed==true",
            ["GENERAL"],
            id="Deeply nested full path",
        ),
        pytest.param(
            "udid=='550e8400-e29b'",
            [],
            id="Key with no mapped section (udid)",
        ),
        pytest.param(
            "id==10 and hardware.appleSilicon==true",
            ["HARDWARE"],
            id="Combination of mapped and unmapped keys",
        ),
        pytest.param(
            "userandlocation.email=='test@me.com' or (hardware.make=='Apple' and userandlocation.departmentId==5)",
            ["HARDWARE", "USER_AND_LOCATION"],
            id="Complex query OR/AND",
        ),
        pytest.param(
            "operatingsystem.activeDirectoryStatus=='Bound' or operatingsystem.fileVault2Status=='All'",
            ["OPERATING_SYSTEM"],
            id="Operating System specific keys",
        ),
        pytest.param(
            "security.firewallEnabled==true and diskencryption.fileVault2Enabled==true",
            ["DISK_ENCRYPTION", "SECURITY"],
            id="Security and Disk Encryption",
        ),
        pytest.param(
            "general.lastLoggedInUsernameSelfService=='admin'",
            ["GENERAL"],
            id="Deeply nested names",
        ),
        pytest.param(
            "purchasing.lifeExpectancy>=3",
            ["PURCHASING"],
            id="Numeric operators",
        ),
        pytest.param(
            "purchasing.warrantyDate<'2025-01-01' and general.reportDate>'2024-01-01'",
            ["GENERAL", "PURCHASING"],
            id="Date based fields",
        ),
        pytest.param(
            "hardware.model=='Air' and hardware.macAddress=='00' and hardware.appleSilicon==false",
            ["HARDWARE"],
            id="Duplicate sections deduplication",
        ),
        pytest.param(
            "OPERATINGSYSTEM.SUPPLEMENTALBUILDVERSION=='23F80' AND operatingsystem.build=='23F70'",
            ["OPERATING_SYSTEM"],
            id="Mixed casing in operators and keys",
        ),
        pytest.param(
            "general.name=='X' and hardware.serialNumber=='Y' and operatingsystem.version=='Z' and "
            "security.activationLockEnabled==true and userandlocation.email=='A' and "
            "diskencryption.fileVault2Enabled==true and purchasing.vendor=='B'",
            ["DISK_ENCRYPTION", "GENERAL", "HARDWARE", "OPERATING_SYSTEM", "PURCHASING", "SECURITY", "USER_AND_LOCATION"],
            id="Universal query (All sections using Full Paths)",
        ),
        pytest.param(
            "unknownField=='foo' and 123==456",
            [],
            id="Unrelated or unknown fields",
        ),
    ],
)
def test_get_sections_from_query(query, expected):
    """
    Given:
        - A query string
    When:
        - get_rsql_sections is called
    Then:
        - Ensure the function returns the correct output
    """
    from jamfV2 import get_sections_from_query

    actual_sections = get_sections_from_query(query)

    assert set(actual_sections) == set(expected), f"Failed for query: {query}\nExpected: {expected}\nActual: {actual_sections}"

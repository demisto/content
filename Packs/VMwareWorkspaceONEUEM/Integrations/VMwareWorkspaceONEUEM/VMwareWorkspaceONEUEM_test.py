import json
import io
import pytest
from CommonServerPython import *
from VMwareWorkspaceONEUEM import Client, HTTP_ERROR, MESSAGES
from test_data import input_data

SERVER_URL = "https://host.awmdm.com"
BASE_URL = "https://host.awmdm.com/API/mdm/"

client = Client("user", "user123", BASE_URL, {"aw-tenant-code": "abed", "Accept": "application/json;version=2"})


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.mark.parametrize("status_code,error_msg", input_data.exception_handler_params)
def test_exception_handler_when_error_is_returned(status_code, error_msg, requests_mock):
    """
    To test no content error, proxy error and internal server error in exception handler function of client class.
    """
    requests_mock.get(BASE_URL, status_code=status_code)

    with pytest.raises(DemistoException) as ve:
        Client.http_request(client, method="GET")
    assert str(ve.value) == error_msg


@pytest.mark.parametrize("status_code,file_name", input_data.authentication_params)
def test_exception_handler_authentication_error(status_code, file_name, requests_mock, capfd):
    """
    To test authentication error in exception handler function of client class.
    """
    api_error_msg = util_load_json(file_name)
    requests_mock.get(BASE_URL, json=api_error_msg, status_code=status_code)

    with capfd.disabled():
        with pytest.raises(DemistoException) as de:
            Client.http_request(client, method="GET")
        assert str(de.value) == HTTP_ERROR[status_code]


def test_test_module_success(requests_mock):
    """
    To test test_module command when success response come.
    """
    from VMwareWorkspaceONEUEM import test_module

    requests_mock.get(BASE_URL + "devices/search", status_code=200)

    response = test_module(client)
    assert response == "ok"


@pytest.fixture
def test_main_with_strip_params(mocker):
    """
    To test params are strip in main method.
    """
    import VMwareWorkspaceONEUEM

    params = {
        "credentials": {
            "identifier": "   user   ",
            "password": "   user123   ",  # NOSONAR
        },
        "aw_tenant_code": "  abcd  ",
        "url": SERVER_URL,
    }
    expected = {
        "identifier": "user",
        "password": "   user123   ",  # NOSONAR
    }
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(VMwareWorkspaceONEUEM, "test_module", return_value="ok")

    VMwareWorkspaceONEUEM.main()

    assert params["credentials"] == expected


def test_vmwuem_device_os_updates_list_command_when_valid_response_is_returned(requests_mock):
    """
    To test vmwuem_device_os_updates_list command when valid response return.
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_os_updates_list_command

    uuid = "3c119913-9341-428f-b8b5-35271550c2df"

    expected_response = util_load_json("test_data/vmwuem_device_osupdates_list_command_response.json")

    requests_mock.get(BASE_URL + "devices/{}/osupdate".format(uuid), json=expected_response)

    expected_context_output = util_load_json("test_data/vmwuem_device_osupdates_list_command_context.json")

    with open("test_data/vmwuem_device_osupdates_list_command_readable_output.md") as f:
        expected_readable_output = f.read()

    args = {"uuid": uuid}
    response = vmwuem_device_os_updates_list_command(client, args)

    assert response.outputs_prefix == "VMwareWorkspaceONEUEM.OSUpdate"
    assert response.outputs_key_field == "Uuid"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


@pytest.mark.parametrize("status_code,error_msg,args", input_data.device_osupdates_list_cmd_arg)
def test_vmwuem_device_os_updates_list_command_when_invalid_args_are_provided(status_code, error_msg, args, requests_mock):
    """
    To test vmwuem_device_os_updates_list command when invalid arguments are provided.
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_os_updates_list_command

    requests_mock.get(BASE_URL + "devices/{}/osupdate".format(args["uuid"]), status_code=status_code)

    with pytest.raises(DemistoException) as de:
        vmwuem_device_os_updates_list_command(client, args)

    assert str(de.value) == error_msg


def test_vmwuem_device_os_updates_list_command_when_no_args_are_provided():
    """
    To test vmwuem_device_os_updates_list command when no arguments are provided.
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_os_updates_list_command

    with pytest.raises(ValueError) as ve:
        vmwuem_device_os_updates_list_command(client, args={"uuid": ""})
    assert str(ve.value) == MESSAGES["REQUIRED_ARGUMENT"].format("uuid")


def test_vmwuem_device_os_updates_list_command_when_no_records_found(requests_mock):
    """
    To test vmwuem_device_os_updates_list command when no records found.
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_os_updates_list_command

    uuid = "7752a0be-4c0a-429a-97c0-228b1fd6ba0f"
    expected_response = {"OSUpdateList": []}
    requests_mock.get(BASE_URL + "devices/{}/osupdate".format(uuid), json=expected_response)

    response = vmwuem_device_os_updates_list_command(client, args={"uuid": uuid})

    assert response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("osupdate(s)")


def test_vmwuem_device_osupdates_list_command_when_laptop_device_provided(requests_mock):
    """
    To test vmwuem_device_osupdates_list command when laptop device provide in arguments.
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_os_updates_list_command

    uuid = "7752a0be-4c0a-429a-97c0-228b1fd6ba0f"

    expected_response = util_load_json("test_data/vmwuem_device_osupdates_list_command_response_laptop.json")

    requests_mock.get(BASE_URL + "devices/{}/osupdate".format(uuid), json=expected_response)

    expected_context_output = util_load_json("test_data/vmwuem_device_osupdates_list_command_context_laptop.json")

    with open("test_data/vmwuem_device_osupdates_list_command_readable_output_laptop.md") as f:
        expected_readable_output = f.read()

    args = {"uuid": uuid}
    response = vmwuem_device_os_updates_list_command(client, args)

    assert response.outputs_prefix == "VMwareWorkspaceONEUEM.OSUpdate"
    assert response.outputs_key_field == "Uuid"
    assert response.outputs == expected_context_output
    assert response.readable_output == expected_readable_output


def test_vmuem_devices_search_command_when_no_records_found(requests_mock):
    """
    Test no records found test case for vmuem-devices-search
    """
    from VMwareWorkspaceONEUEM import vmwuem_devices_search_command

    requests_mock.get(BASE_URL + "devices/search", text="", status_code=200)

    command_results = vmwuem_devices_search_command(client, {})
    assert command_results.outputs is None
    assert command_results.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("device")


@pytest.mark.parametrize("args, message, message_name, format_params", input_data.vmuem_devices_search_validation_errors_params)
def test_vmuem_devices_search_command_when_invalid_args_are_provided(args, message, message_name, format_params):
    """
    Test multiple erroneous parameters and their validation messages for vmuem-devices-search
    """
    from VMwareWorkspaceONEUEM import vmwuem_devices_search_command

    with pytest.raises(ValueError) as e:
        vmwuem_devices_search_command(client, args)
    message = message or MESSAGES[message_name].format(*format_params)
    assert e.value.args[0] == message


def test_vmuem_devices_search_command_when_valid_response_is_returned(requests_mock):
    """
    Test for successful execution of devices_search_success
    """
    from VMwareWorkspaceONEUEM import vmwuem_devices_search_command

    response = util_load_json("test_data/devices_search_resp.json")
    ec = util_load_json("test_data/devices_search_ec.json")
    requests_mock.get(BASE_URL + "devices/search", json=response)

    command_results = vmwuem_devices_search_command(client, {})

    assert command_results.outputs == ec["outputs"]
    assert command_results.readable_output == ec["readable_output"]
    assert command_results.outputs_prefix == "VMwareWorkspaceONEUEM.Device"
    assert command_results.outputs_key_field == "Uuid"


def test_vmuem_device_get_command_when_no_records_found_json_response(requests_mock):
    """
    Test no records found test case for vmuem-device-get when response is json
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_get_command

    response = util_load_json("test_data/get_device_404_no_records_found_message.json")

    requests_mock.get(
        BASE_URL + "devices/{uuid}".format(uuid="12345678-1234-1234-1234-123456789ABC"), json=response, status_code=404
    )

    with pytest.raises(DemistoException) as e:
        vmwuem_device_get_command(client, {"uuid": "12345678-1234-1234-1234-123456789ABC"})

    assert e.value.args[0] == HTTP_ERROR[404]


def test_vmuem_device_get_command_when_no_records_found_html_response(requests_mock):
    """
    Test no records found test case for vmuem-device-get when response is html
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_get_command

    with open("test_data/get_device_404_no_records_found_message.html") as file:
        response = file.read()

    requests_mock.get(BASE_URL + "devices/{uuid}".format(uuid="1234"), text=response, status_code=404)
    with pytest.raises(DemistoException) as e:
        vmwuem_device_get_command(client, {"uuid": "1234"})

    assert e.value.args[0] == HTTP_ERROR[404]


def test_vmuemm_device_get_command_when_no_args_are_provided():
    """
    Test for empty arguments provided to command vmuem-device-get
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_get_command

    with pytest.raises(ValueError) as e:
        vmwuem_device_get_command(client, {})
    assert e.value.args[0] == MESSAGES["REQUIRED_ARGUMENT"].format("uuid")


def test_vmuemm_device_get_command_when_uuid_is_null_string():
    """
    Test for arguments containing empty uuid provided to command vmuem-device-get
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_get_command

    with pytest.raises(ValueError) as e:
        vmwuem_device_get_command(client, {"uuid": ""})
    assert e.value.args[0] == MESSAGES["REQUIRED_ARGUMENT"].format("uuid")


def test_camel_to_pascal():
    """
    Test the function camel_to_pascal for a diverse input
    """
    from VMwareWorkspaceONEUEM import camel_to_pascal

    camel_dict = util_load_json("test_data/camel_response.json")
    expected_pascal_dict = util_load_json("test_data/pascal_context.json")
    pascal_dict = camel_to_pascal(camel_dict)

    assert expected_pascal_dict == pascal_dict


def test_vmuem_device_get_command_when_valid_response_is_returned(requests_mock):
    """
    Test for successful execution of vmwuem_device_get_command
    """
    from VMwareWorkspaceONEUEM import vmwuem_device_get_command

    response = util_load_json("test_data/device_get_resp.json")
    ec = util_load_json("test_data/device_get_ec.json")
    requests_mock.get(BASE_URL + "devices/{uuid}".format(uuid="12345678-1234-1234-1234-123456789ABC"), json=response)

    command_results = vmwuem_device_get_command(client, {"uuid": "12345678-1234-1234-1234-123456789ABC"})

    assert command_results.outputs == ec["outputs"]
    assert command_results.readable_output == ec["readable_output"]
    assert command_results.outputs_prefix == "VMwareWorkspaceONEUEM.Device"
    assert command_results.outputs_key_field == "Uuid"

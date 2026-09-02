import json
from datetime import datetime
from unittest.mock import Mock

import demistomock as demisto
import pytest
from CommonServerPython import *
from VBRRESTAPI import (
    DATE_FORMAT,
    MAX_INT,
    Client,
    FetchClient,
    search_with_paging,
    overwrite_last_fetch_time,
    validate_ipv4,
    validate_ipv6,
    validate_time,
    validate_uuid,
    validate_bool,
    validate_int,
    validate_float,
    is_api_version_higher_or_equal_than,
    process_command,
    handle_command_with_token_refresh,
    validate_filter_parameter,
    convert_to_json,
    get_vcentername,
    process_error,
    get_inventory_objects_command,
    get_backup_object_command,
    get_all_repository_states_command,
    get_all_malware_events_command,
    get_all_restore_points_command,
    start_instant_recovery_command,
    start_instant_recovery_customized_command,
    start_instant_recovery_hyperv_vm_command,
    start_instant_recovery_hyperv_vm_customized_command,
    get_session_command,
    get_session_logs_command,
    create_malware_event_command,
    get_access_token,
    get_security_analyzer_best_practices_command,
    start_security_analyzer_command,
    get_security_analyzer_last_run_command,
    get_job_states_command,
    get_authorization_events_command,
    start_vsphere_quick_backup_command,
    get_yara_rules_command,
    start_malware_backup_scan_command,
    mount_entra_id_tenant_command,
    unmount_entra_id_tenant_command,
    get_entra_id_items_command,
    get_entra_id_item_restore_points_command,
    compare_entra_id_item_properties_command,
    start_disk_publishing_command,
    stop_disk_publishing_command,
    get_disk_publishing_mount_point_command,
    general_api_request_command,
    check_license,
)

SERVER_URL = "https://test_url.com"
REQUEST_TIMEOUT = 120


class ApiMock:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.call_count = 0
        self.call_args_list = []

    def __call__(self, **args: dict) -> dict:
        self.call_args_list.append(args)
        skip = args.get("skip")
        limit = args.get("limit")
        data = self.response["data"]
        response = data[skip : skip + limit]
        self.call_count += 1
        return {"data": response}


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client(server_url=SERVER_URL, verify=None, proxy=None, headers=None, auth=None, timeout=REQUEST_TIMEOUT)


@pytest.mark.parametrize(
    "string, expected",
    [
        ("abc\\def", "abc"),
        ("xyz", "xyz"),
        ("", ""),
    ],
)
def test_get_vcentername(string, expected):
    assert get_vcentername(string) == expected


def test_convert_to_json_with_exception():
    string = "invalid_json"
    with pytest.raises(ValueError):
        convert_to_json(string)


@pytest.mark.parametrize("string, expected", [('{"key": "value"}', {"key": "value"}), ("", {})])
def test_convert_to_json(string, expected):
    assert convert_to_json(string) == expected


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "127.0.0.1",  # good format ipv4
    ],
)
def test_validate_ipv4(arg):
    try:
        validate_ipv4(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # bad format ipv4 => exception
    ],
)
def test_validate_ipv4_with_exception(arg):
    with pytest.raises(ValueError):
        validate_ipv4(arg)


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "fe60::b873:6a33:6f1a:809b",  # good format ipv6
    ],
)
def test_validate_ipv6(arg):
    try:
        validate_ipv6(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # bad format ipv6 => exception
    ],
)
def test_validate_ipv6_with_exception(arg):
    with pytest.raises(ValueError):
        validate_ipv6(arg)


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "af75ddaa-d680-4c50-ac82-07834a007707",  # good format uuid
    ],
)
def test_validate_uuid(arg):
    try:
        validate_uuid(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # bad format uuid => exception
    ],
)
def test_validate_uuid_with_exception(arg):
    with pytest.raises(ValueError):
        validate_uuid(arg)


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "2024-04-24T16:03:59.204Z",  # good format time
    ],
)
def test_validate_time(arg):
    try:
        validate_time(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # bad format time => exception
    ],
)
def test_validate_time_with_exception(arg):
    with pytest.raises(ValueError):
        validate_time(arg)


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "202",  # str int
    ],
)
def test_validate_int(arg):
    try:
        validate_int(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # not int => exception
    ],
)
def test_validate_int_with_exception(arg):
    with pytest.raises(ValueError):
        validate_int(arg)


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "true",  # only str that represent bool value can be casted
        "False",
        "TRUE",  # any register
    ],
)
def test_validate_bool(arg):
    try:
        validate_bool(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # not our bool value => exception
    ],
)
def test_validate_bool_with_exception(arg):
    with pytest.raises(ValueError):
        validate_bool(arg)


@pytest.mark.parametrize(
    "arg",
    [
        "",  # empty str (skiping arg)
        "3.14",  # double value
    ],
)
def test_validate_float(arg):
    try:
        validate_float(arg)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "arg",
    [
        "wtgwte"  # not our bool value => exception
    ],
)
def test_validate_float_with_exception(arg):
    with pytest.raises(ValueError):
        validate_float(arg)


@pytest.mark.parametrize(
    "current_version, comp_version, expected",
    [
        ("1.3-rev2", "1.3-rev2", True),  # equal versions
        ("1.3-rev3", "1.3-rev2", True),  # higher rev
        ("2.3-rev2", "1.3-rev2", True),  # higher major
        ("1.4-rev2", "1.3-rev2", True),  # higher minor
        ("1.3-rev1", "1.3-rev2", False),  # lower rev
        ("1.2-rev2", "1.3-rev2", False),  # lower minor
        ("0.3-rev2", "1.3-rev2", False),  # lower major
    ],
)
def test_is_api_version_higher_or_equal_than(current_version, comp_version, expected):
    assert is_api_version_higher_or_equal_than(current_version, comp_version) == expected


@pytest.mark.parametrize(
    "response, expected_result",
    [({"type": "Subscription", "package": "Suite"}, None), ({"type": "Subscription", "edition": "Standard"}, "Exception")],
)
def test_check_license(response, expected_result):
    if expected_result:
        with pytest.raises(ValueError):
            check_license(response)
    else:
        check_license(response)


def test_get_access_token(client, mocker):
    expected_token = "token"
    mocker.patch("VBRRESTAPI.Client.get_access_token_request", return_value={"access_token": "token"})

    token = get_access_token(client, "username", "password")

    assert token == expected_token


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {"data": [{"id": 1, "name": "repository 1"}, {"id": 2, "name": "repository 2"}]},
            {
                "outputs_prefix": "Veeam.VBR.get_repository_states.data",
                "outputs_key_field": "",
                "outputs": [{"id": 1, "name": "repository 1"}, {"id": 2, "name": "repository 2"}],
                "raw_response": [{"id": 1, "name": "repository 1"}, {"id": 2, "name": "repository 2"}],
            },
        )
    ],
)
def test_get_all_repository_states_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_all_repository_states_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_int")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.validate_float")

    args = {}
    command_results = get_all_repository_states_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {"data": [{"id": 1, "name": "event 1"}, {"id": 2, "name": "event 2"}]},
            {
                "outputs_prefix": "Veeam.VBR.get_malware_events.data",
                "outputs_key_field": "",
                "outputs": [{"id": 1, "name": "event 1"}, {"id": 2, "name": "event 2"}],
                "raw_response": [{"id": 1, "name": "event 1"}, {"id": 2, "name": "event 2"}],
            },
        )
    ],
)
def test_get_all_malware_events_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_all_malware_events_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_int")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.validate_time")

    args = {}
    command_results = get_all_malware_events_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {"data": [{"id": 1, "name": "restore point 1"}, {"id": 2, "name": "restore point 2"}]},
            {
                "outputs_prefix": "Veeam.VBR.get_restore_points.data",
                "outputs_key_field": "",
                "outputs": [{"id": 1, "name": "restore point 1"}, {"id": 2, "name": "restore point 2"}],
                "raw_response": [{"id": 1, "name": "restore point 1"}, {"id": 2, "name": "restore point 2"}],
            },
        )
    ],
)
def test_get_all_restore_points_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_all_restore_points_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_int")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.validate_time")

    args = {}
    command_results = get_all_restore_points_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results, expected_filter",
    [
        (
            {"data": [{"id": 1, "name": "object 1"}, {"id": 2, "name": "object 2"}]},
            {
                "outputs_prefix": "Veeam.VBR.get_inventory_objects.data",
                "outputs_key_field": "",
                "outputs": [{"id": 1, "name": "object 1"}, {"id": 2, "name": "object 2"}],
                "raw_response": [{"id": 1, "name": "object 1"}, {"id": 2, "name": "object 2"}],
            },
            {
                "type": "GroupExpression",
                "operation": "and",
                "items": [
                    {"type": "PredicateExpression", "operation": "equals", "property": "Name", "value": "object_name"},
                    {"type": "PredicateExpression", "operation": "in", "property": "Type", "value": "vi_type"},
                ],
            },
        )
    ],
)
def test_get_inventory_objects_command(client, mocker, response, expected_command_results, expected_filter):
    mock_get_inventory_objects_request = mocker.patch("VBRRESTAPI.Client.get_inventory_objects_request", return_value=response)
    mocker.patch("VBRRESTAPI.convert_to_json", return_value={})
    mocker.patch("VBRRESTAPI.assign_params", return_value={})
    mocker.patch("VBRRESTAPI.validate_int")
    mocker.patch("VBRRESTAPI.validate_bool")

    args = {"objectName": "object_name", "viType": "vi_type"}
    command_results = get_inventory_objects_command(client, args)

    func_args = mock_get_inventory_objects_request.call_args[0]
    assert func_args[3] == expected_filter
    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results, expected_mode",
    [
        (
            {"state": "Starting", "id": "1111"},
            {
                "outputs_prefix": "Veeam.VBR.start_recovery",
                "outputs_key_field": "",
                "outputs": {"state": "Starting", "id": "1111"},
                "raw_response": {"state": "Starting", "id": "1111"},
            },
            "OriginalLocation",
        )
    ],
)
def test_start_instant_recovery_command(client, mocker, response, expected_command_results, expected_mode):
    mock_start_instant_recovery_request = mocker.patch("VBRRESTAPI.Client.start_instant_recovery_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.assign_params", return_value={})

    args = {}
    command_results = start_instant_recovery_command(client, args)

    func_args = mock_start_instant_recovery_request.call_args[0]
    assert func_args[1] == expected_mode
    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results, expected_mode",
    [
        (
            {"state": "Starting", "id": "1111"},
            {
                "outputs_prefix": "Veeam.VBR.start_recovery",
                "outputs_key_field": "",
                "outputs": {"state": "Starting", "id": "1111"},
                "raw_response": {"state": "Starting", "id": "1111"},
            },
            "Customized",
        )
    ],
)
def test_start_instant_recovery_customized_command(client, mocker, response, expected_command_results, expected_mode):
    mock_start_instant_recovery_customized_request = mocker.patch(
        "VBRRESTAPI.Client.start_instant_recovery_customized_request", return_value=response
    )
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.assign_params", return_value={})

    args = {}
    command_results = start_instant_recovery_customized_command(client, args)

    func_args = mock_start_instant_recovery_customized_request.call_args[0]
    assert func_args[1] == expected_mode
    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results, expected_mode",
    [
        (
            {"state": "Starting", "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"},
            {
                "outputs_prefix": "Veeam.VBR.start_hv_recovery",
                "outputs_key_field": "",
                "outputs": {"state": "Starting", "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"},
                "raw_response": {"state": "Starting", "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"},
            },
            "OriginalLocation",
        )
    ],
)
def test_start_instant_recovery_hyperv_vm_command(client, mocker, response, expected_command_results, expected_mode):
    mock_request = mocker.patch("VBRRESTAPI.Client.start_instant_recovery_hyperv_vm_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.assign_params", return_value={})

    args = {}
    command_results = start_instant_recovery_hyperv_vm_command(client, args)

    func_args = mock_request.call_args[0]
    assert func_args[1] == expected_mode
    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results, expected_mode",
    [
        (
            {"state": "Starting", "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"},
            {
                "outputs_prefix": "Veeam.VBR.start_hv_recovery",
                "outputs_key_field": "",
                "outputs": {"state": "Starting", "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"},
                "raw_response": {"state": "Starting", "id": "497f6eca-6276-4993-bfeb-53cbbbba6f08"},
            },
            "Customized",
        )
    ],
)
def test_start_instant_recovery_hyperv_vm_customized_command(client, mocker, response, expected_command_results, expected_mode):
    mock_request = mocker.patch("VBRRESTAPI.Client.start_instant_recovery_hyperv_vm_customized_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.assign_params", return_value={})

    args = {}
    command_results = start_instant_recovery_hyperv_vm_customized_command(client, args)

    func_args = mock_request.call_args[0]
    assert func_args[1] == expected_mode
    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results, expected_args",
    [
        (
            {"data": [{"id": 1, "name": "event 1"}]},
            {
                "outputs_prefix": "Veeam.VBR",
                "outputs_key_field": "",
                "outputs": [{"id": 1, "name": "event 1"}],
                "raw_response": [{"id": 1, "name": "event 1"}],
            },
            {"post_event_ids": ["1"]},
        )
    ],
)
def test_create_malware_event_command(client, mocker, response, expected_command_results, expected_args):
    mock_create_malware_event_command = mocker.patch("VBRRESTAPI.Client.create_malware_event_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_ipv6")
    mocker.patch("VBRRESTAPI.validate_ipv4")
    mocker.patch("VBRRESTAPI.validate_time")
    mocker.patch("VBRRESTAPI.assign_params", return_value={})
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})
    mock_set_integration_context = mocker.patch.object(demisto, "setIntegrationContext")

    args = {}
    command_results = create_malware_event_command(client, args)

    mock_create_malware_event_command.assert_called_once()
    set_context_args = mock_set_integration_context.call_args[0]
    assert set_context_args[0] == expected_args
    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {"id": 1, "name": "object 1", "path": "vcentername/path"},
            {
                "outputs_prefix": "Veeam.VBR.backup_object",
                "outputs_key_field": "",
                "outputs": {"id": 1, "name": "object 1", "path": "vcentername/path", "vcenter_name": "vcentername/path"},
                "raw_response": {"id": 1, "name": "object 1", "path": "vcentername/path", "vcenter_name": "vcentername/path"},
            },
        )
    ],
)
def test_get_backup_object_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_backup_object_request", return_value=response)
    mocker.patch("VBRRESTAPI.get_vcentername", return_value=response["path"])
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {}
    command_results = get_backup_object_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {"id": 1, "name": "session 1"},
            {
                "outputs_prefix": "Veeam.VBR.get_session",
                "outputs_key_field": "",
                "outputs": {"id": 1, "name": "session 1"},
                "raw_response": {"id": 1, "name": "session 1"},
                "replace_existing": True,
            },
        )
    ],
)
def test_get_session_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_session_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {}
    command_results = get_session_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]
    assert command_results.replace_existing == expected_command_results["replace_existing"]


GET_SESSION_LOGS_RESPONSE = util_load_json("test_data/get_session_logs_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_SESSION_LOGS_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.get_session_logs",
                "outputs_key_field": "",
                "outputs": GET_SESSION_LOGS_RESPONSE,
                "raw_response": GET_SESSION_LOGS_RESPONSE,
            },
        )
    ],
)
def test_get_session_logs_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_session_logs_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {"id_": "cc5de5c2-3ce4-4b67-af45-3733c3fc0a1e"}
    command_results = get_session_logs_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                "items": [
                    {"id": "1", "bestPractise": "Enable encryption", "status": "Violation", "note": ""},
                    {"id": "2", "bestPractise": "Configure notifications", "status": "OK", "note": ""},
                ]
            },
            {
                "outputs_prefix": "Veeam.VBR.security_analyzer_best_practices.items",
                "outputs_key_field": "",
                "outputs": [
                    {"id": "1", "bestPractise": "Enable encryption", "status": "Violation", "note": ""},
                    {"id": "2", "bestPractise": "Configure notifications", "status": "OK", "note": ""},
                ],
                "raw_response": [
                    {"id": "1", "bestPractise": "Enable encryption", "status": "Violation", "note": ""},
                    {"id": "2", "bestPractise": "Configure notifications", "status": "OK", "note": ""},
                ],
            },
        )
    ],
)
def test_get_security_analyzer_best_practices_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_security_analyzer_best_practices_request", return_value=response)

    command_results = get_security_analyzer_best_practices_command(client, {})

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            {
                "data": [
                    {
                        "id": "c1d2e3f4-a5b6-7890-cdef-123456789abc",
                        "name": "SureBackup Job 1",
                        "type": "SureBackup",
                    }
                ]
            },
            {
                "outputs_prefix": "Veeam.VBR.get_job_states.data",
                "outputs_key_field": "",
                "outputs": [
                    {
                        "id": "c1d2e3f4-a5b6-7890-cdef-123456789abc",
                        "name": "SureBackup Job 1",
                        "type": "SureBackup",
                    }
                ],
                "raw_response": [
                    {
                        "id": "c1d2e3f4-a5b6-7890-cdef-123456789abc",
                        "name": "SureBackup Job 1",
                        "type": "SureBackup",
                    }
                ],
            },
        ),
    ],
)
def test_get_job_states_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_job_states_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_int")
    mocker.patch("VBRRESTAPI.validate_bool")

    args = {}
    command_results = get_job_states_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


START_SECURITY_ANALYZER_RESPONSE = util_load_json("test_data/start_security_analyzer_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            START_SECURITY_ANALYZER_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.start_security_analyzer",
                "outputs_key_field": "",
                "outputs": START_SECURITY_ANALYZER_RESPONSE,
                "raw_response": START_SECURITY_ANALYZER_RESPONSE,
            },
        )
    ],
)
def test_start_security_analyzer_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.start_security_analyzer_request", return_value=response)

    command_results = start_security_analyzer_command(client, {})

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GET_SECURITY_ANALYZER_LAST_RUN_RESPONSE = util_load_json("test_data/get_security_analyzer_last_run_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_SECURITY_ANALYZER_LAST_RUN_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.security_analyzer_last_run",
                "outputs_key_field": "",
                "outputs": GET_SECURITY_ANALYZER_LAST_RUN_RESPONSE,
                "raw_response": GET_SECURITY_ANALYZER_LAST_RUN_RESPONSE,
            },
        )
    ],
)
def test_get_security_analyzer_last_run_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_security_analyzer_last_run_request", return_value=response)

    command_results = get_security_analyzer_last_run_command(client, {})

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GET_AUTHORIZATION_EVENTS_RESPONSE = util_load_json("test_data/get_authorization_events_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_AUTHORIZATION_EVENTS_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.get_authorization_events.data",
                "outputs_key_field": "",
                "outputs": GET_AUTHORIZATION_EVENTS_RESPONSE["data"],
                "raw_response": GET_AUTHORIZATION_EVENTS_RESPONSE["data"],
            },
        )
    ],
)
def test_get_authorization_events_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_authorization_events_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_int")
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.validate_time")

    args = {}
    command_results = get_authorization_events_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GET_YARA_RULES_RESPONSE = util_load_json("test_data/get_yara_rules_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_YARA_RULES_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.get_yara_rules.data",
                "outputs_key_field": "",
                "outputs": GET_YARA_RULES_RESPONSE["data"],
                "raw_response": GET_YARA_RULES_RESPONSE["data"],
            },
        )
    ],
)
def test_get_yara_rules_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_yara_rules_request", return_value=response)

    command_results = get_yara_rules_command(client, {})

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


START_VSPHERE_QUICK_BACKUP_RESPONSE = util_load_json("test_data/start_vsphere_quick_backup_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            START_VSPHERE_QUICK_BACKUP_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.start_vsphere_quick_backup",
                "outputs_key_field": "",
                "outputs": START_VSPHERE_QUICK_BACKUP_RESPONSE,
                "raw_response": START_VSPHERE_QUICK_BACKUP_RESPONSE,
            },
        )
    ],
)
def test_start_vsphere_quick_backup_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.start_vsphere_quick_backup_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_bool")

    args = {"name": "my-vm", "platform": "VMware", "type": "VirtualMachine", "hostName": "esxi.example.com"}
    command_results = start_vsphere_quick_backup_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


START_MALWARE_BACKUP_SCAN_RESPONSE = util_load_json("test_data/start_malware_backup_scan_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            START_MALWARE_BACKUP_SCAN_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.start_malware_backup_scan",
                "outputs_key_field": "",
                "outputs": START_MALWARE_BACKUP_SCAN_RESPONSE,
                "raw_response": START_MALWARE_BACKUP_SCAN_RESPONSE,
            },
        )
    ],
)
def test_start_malware_backup_scan_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.start_malware_backup_scan_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_bool")
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_time")
    client._headers = {"x-api-version": "1.3-rev2"}

    args = {
        "backupId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "backupObjectId": "b2c3d4e5-f6a7-8901-bcde-f01234567891",
        "scanMode": "MostRecent",
        "useAntivirusEngine": "true",
        "useYaraRule": "false",
        "yaraRule": "{}",
        "useMostRecentPoint": "true",
        "startDate": "2024-04-24T00:00:00Z",
        "useOldestPoint": "false",
        "endDate": "2024-04-24T23:59:59Z",
        "continueScan": "false",
    }
    command_results = start_malware_backup_scan_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


MOUNT_ENTRA_ID_TENANT_RESPONSE = util_load_json("test_data/mount_entra_id_tenant_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            MOUNT_ENTRA_ID_TENANT_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.mount_entra_id_tenant",
                "outputs_key_field": "",
                "outputs": MOUNT_ENTRA_ID_TENANT_RESPONSE,
                "raw_response": MOUNT_ENTRA_ID_TENANT_RESPONSE,
            },
        )
    ],
)
def test_mount_entra_id_tenant_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.mount_entra_id_tenant_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {"backupId": "61a85b62-41a9-4421-aa4f-568e3989fed8"}
    command_results = mount_entra_id_tenant_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


UNMOUNT_ENTRA_ID_TENANT_RESPONSE = util_load_json("test_data/unmount_entra_id_tenant_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            UNMOUNT_ENTRA_ID_TENANT_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.unmount_entra_id_tenant",
                "outputs_key_field": "",
                "outputs": UNMOUNT_ENTRA_ID_TENANT_RESPONSE,
                "raw_response": UNMOUNT_ENTRA_ID_TENANT_RESPONSE,
            },
        )
    ],
)
def test_unmount_entra_id_tenant_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.unmount_entra_id_tenant_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_bool")

    args = {"sessionId": "783241eb-5b56-4456-9736-379206ffc600", "gracefulStop": "true"}
    command_results = unmount_entra_id_tenant_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GET_ENTRA_ID_ITEMS_RESPONSE = util_load_json("test_data/get_entra_id_items_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_ENTRA_ID_ITEMS_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.get_entra_id_items.data",
                "outputs_key_field": "",
                "outputs": GET_ENTRA_ID_ITEMS_RESPONSE.get("data"),
                "raw_response": GET_ENTRA_ID_ITEMS_RESPONSE.get("data"),
            },
        )
    ],
)
def test_get_entra_id_items_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_entra_id_items_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_int")

    args = {
        "backupId": "61a85b62-41a9-4421-aa4f-568e3989fed8",
        "type": "User",
        "limit": "100",
    }
    command_results = get_entra_id_items_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GET_ENTRA_ID_ITEM_RESTORE_POINTS_RESPONSE = util_load_json("test_data/get_entra_id_item_restore_points_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_ENTRA_ID_ITEM_RESTORE_POINTS_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.get_entra_id_item_restore_points.data",
                "outputs_key_field": "",
                "outputs": GET_ENTRA_ID_ITEM_RESTORE_POINTS_RESPONSE.get("data"),
                "raw_response": GET_ENTRA_ID_ITEM_RESTORE_POINTS_RESPONSE.get("data"),
            },
        )
    ],
)
def test_get_entra_id_item_restore_points_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_entra_id_item_restore_points_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_int")

    args = {"backupId": "61a85b62-41a9-4421-aa4f-568e3989fed8", "itemId": "fee6a1c9-6f07-4729-bf46-d3d4f45c7ad0", "limit": "5"}
    command_results = get_entra_id_item_restore_points_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


COMPARE_ENTRA_ID_ITEM_PROPERTIES_RESPONSE = util_load_json("test_data/compare_entra_id_item_properties_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            COMPARE_ENTRA_ID_ITEM_PROPERTIES_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.compare_entra_id_item_properties",
                "outputs_key_field": "",
                "outputs": COMPARE_ENTRA_ID_ITEM_PROPERTIES_RESPONSE,
                "raw_response": COMPARE_ENTRA_ID_ITEM_PROPERTIES_RESPONSE,
            },
        )
    ],
)
def test_compare_entra_id_item_properties_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.compare_entra_id_item_properties_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")
    mocker.patch("VBRRESTAPI.validate_bool")

    args = {
        "sessionId": "783241eb-5b56-4456-9736-379206ffc600",
        "itemId": "fee6a1c9-6f07-4729-bf46-d3d4f45c7ad0",
        "itemType": "User",
        "oldRestorePointId": "8004f69b-c462-4412-bfd8-ea697052ea61",
        "showUnchangedAttributes": "false",
    }
    command_results = compare_entra_id_item_properties_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


START_DISK_PUBLISHING_RESPONSE = util_load_json("test_data/start_disk_publishing_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            START_DISK_PUBLISHING_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.start_disk_publishing",
                "outputs_key_field": "",
                "outputs": START_DISK_PUBLISHING_RESPONSE,
                "raw_response": START_DISK_PUBLISHING_RESPONSE,
            },
        )
    ],
)
def test_start_disk_publishing_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.start_disk_publishing_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {
        "restorePointId": "58d8ce8c-2e04-47c7-8f11-a17875b1eed3",
        "allowedIps": '["192.168.1.1"]',
    }
    command_results = start_disk_publishing_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


STOP_DISK_PUBLISHING_RESPONSE = util_load_json("test_data/stop_disk_publishing_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            STOP_DISK_PUBLISHING_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.stop_disk_publishing",
                "outputs_key_field": "",
                "outputs": STOP_DISK_PUBLISHING_RESPONSE,
                "raw_response": STOP_DISK_PUBLISHING_RESPONSE,
            },
        )
    ],
)
def test_stop_disk_publishing_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.stop_disk_publishing_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {"mountId": "cc5de5c2-3ce4-4b67-af45-3733c3fc0a1e"}
    command_results = stop_disk_publishing_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GET_DISK_PUBLISHING_MOUNT_POINT_RESPONSE = util_load_json("test_data/get_disk_publishing_mount_point_response.json")


@pytest.mark.parametrize(
    "response, expected_command_results",
    [
        (
            GET_DISK_PUBLISHING_MOUNT_POINT_RESPONSE,
            {
                "outputs_prefix": "Veeam.VBR.get_disk_publishing_mount_point",
                "outputs_key_field": "",
                "outputs": GET_DISK_PUBLISHING_MOUNT_POINT_RESPONSE,
                "raw_response": GET_DISK_PUBLISHING_MOUNT_POINT_RESPONSE,
            },
        )
    ],
)
def test_get_disk_publishing_mount_point_command(client, mocker, response, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.get_disk_publishing_mount_point_request", return_value=response)
    mocker.patch("VBRRESTAPI.validate_uuid")

    args = {"mountId": "bce89e03-9269-4cb0-aa49-c8b04d4273d5"}
    command_results = get_disk_publishing_mount_point_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


GENERAL_API_REQUEST_RESPONSE = util_load_json("test_data/general_api_request_response.json")


@pytest.mark.parametrize(
    "response, args, expected_command_results",
    [
        (
            GENERAL_API_REQUEST_RESPONSE,
            {"path": "api/v1/jobs", "method": "get", "params": '{"limit": "10", "skip": "0"}'},
            {
                "outputs_prefix": "Veeam.VBR.general_api_request",
                "outputs_key_field": "",
                "outputs": GENERAL_API_REQUEST_RESPONSE,
                "raw_response": GENERAL_API_REQUEST_RESPONSE,
            },
        ),
        (
            GENERAL_API_REQUEST_RESPONSE,
            {"path": "api/v1/jobs", "method": "post", "data": '{"name": "Updated Job"}'},
            {
                "outputs_prefix": "Veeam.VBR.general_api_request",
                "outputs_key_field": "",
                "outputs": GENERAL_API_REQUEST_RESPONSE,
                "raw_response": GENERAL_API_REQUEST_RESPONSE,
            },
        ),
    ],
)
def test_general_api_request_command(client, mocker, response, args, expected_command_results):
    mocker.patch("VBRRESTAPI.Client.general_api_request", return_value=response)

    command_results = general_api_request_command(client, args)

    assert command_results.outputs_prefix == expected_command_results["outputs_prefix"]
    assert command_results.outputs_key_field == expected_command_results["outputs_key_field"]
    assert command_results.outputs == expected_command_results["outputs"]
    assert command_results.raw_response == expected_command_results["raw_response"]


MALWARE_EVENTS_WITH_NEEDED_TYPE = util_load_json("test_data/get_malware_events.json")
MALWARE_EVENTS_WITHOUT_NEEDED_TYPE = util_load_json("test_data/malware_events_without_needed_type.json")
MALWARE_EVENTS_WITHOUT_NEEDED_SEVERITY = util_load_json("test_data/malware_events_without_needed_severity.json")
MALWARE_INCIDENTS = [
    {
        "name": "Veeam - Malware activity detected on string",
        "occurred": "2024-04-24T15:42:22.198Z",
        "rawJSON": (
            '{"type": "YaraScan", "state": "Created", "source": "External", "severity": '
            '"Infected", "id": "b9b6d52f-d8ac-448f-ac32-5b86e07d05fa", "detectionTimeUtc": '
            '"2024-04-24T15:42:22.198Z", "machine": {"displayName": "string", "uuid": "string", '
            '"backupObjectId": "dd628dc1-3f7b-46ef-9b3c-f7dd6439c999"}, '
            '"details": "event", "createdBy": "string", "engine": "string", '
            '"description": "event; Hostname: string", "incident_type": "YaraScan", "type_description": '
            '"YARA scan", "source_description": "Third-party malware detection software"}'
        ),
        "severity": IncidentSeverity.CRITICAL,
    }
]
DEFAULT_FETCH = 20


@pytest.mark.parametrize(
    "start_time, existed_ids, max_events_for_fetch, response_data, expected_results",
    [
        # 1 test case: max_events_for_fetch = DEFAULT_FETCH, events with needed type
        # and source => we expect events and its ids;
        (
            datetime.now(),
            set(),
            DEFAULT_FETCH,
            MALWARE_EVENTS_WITH_NEEDED_TYPE,
            (MALWARE_INCIDENTS, {"b9b6d52f-d8ac-448f-ac32-5b86e07d05fa"}, {"b9b6d52f-d8ac-448f-ac32-5b86e07d05fa"}),
        ),
        # 2 test case: events without needed type and source => we expect 0 events;
        (datetime.now(), set(), DEFAULT_FETCH, MALWARE_EVENTS_WITHOUT_NEEDED_TYPE, ([], set(), set())),
        # 3 test case: max_events_for_fetch = 0,
        # events with needed type and source => we expect 0 events cause we have 'max_events_for_fetch' = 0;
        (datetime.now(), set(), 0, MALWARE_EVENTS_WITH_NEEDED_TYPE, ([], set(), set())),
        # 4 test case: events without needed severity => we expect 0 events;
        (datetime.now(), set(), DEFAULT_FETCH, MALWARE_EVENTS_WITHOUT_NEEDED_SEVERITY, ([], set(), set())),
    ],
)
def test_get_malware_incidents(client, mocker, start_time, existed_ids, max_events_for_fetch, response_data, expected_results):
    mock_search_with_paging = mocker.patch("VBRRESTAPI.search_with_paging")
    mock_search_with_paging.return_value = response_data

    mock_overwrite_last_fetch_time = mocker.patch("VBRRESTAPI.overwrite_last_fetch_time")
    mock_overwrite_last_fetch_time.return_value = start_time.strftime(DATE_FORMAT)

    fetch_client = FetchClient(client, {})
    malware_incidents, malwareIds, last_fetch_time = fetch_client.get_malware_incidents(
        start_time, existed_ids, max_events_for_fetch
    )

    assert malware_incidents == expected_results[0]
    assert malwareIds == expected_results[1]

    malware_incidents, malwareIds, last_fetch_time = fetch_client.get_malware_incidents(
        start_time, malwareIds, max_events_for_fetch
    )
    assert mock_search_with_paging.call_count == 2
    assert len(malware_incidents) == 0
    assert malwareIds == expected_results[2]


@pytest.mark.parametrize(
    "last_fetch_time, event, expected_result",
    [
        # 1 test case: 'last_fetch_time' = 2024-05-24T15:42:22.198Z => we expect 'last_fetch_time' remain the same
        ("2024-05-24T15:42:22.198Z", MALWARE_EVENTS_WITH_NEEDED_TYPE[0], "2024-05-24T15:42:22.198Z"),
        # 2 test case: 'last_fetch_time' = 2019-08-24T14:15:22Z => we expect 'last_fetch_time' change to event 'detectiontimeutc'
        ("2019-08-24T14:15:22Z", MALWARE_EVENTS_WITH_NEEDED_TYPE[0], "2024-04-24T15:42:22.198Z"),
    ],
)
def test_overwrite_last_fetch_time(last_fetch_time, event, expected_result):
    last_time = overwrite_last_fetch_time(last_fetch_time, event)
    assert last_time == expected_result


GET_CONF_BACKUP_RESPONSE = util_load_json("test_data/get_configuration_backup_response.json")
CONF_BACKUP_INCIDENT = {
    "name": "Veeam -  has no configuration backups",
    "occurred": datetime.now().strftime(DATE_FORMAT),
    "rawJSON": (
        '{"isEnabled": true, "backupRepositoryId": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", "restorePointsToKeep": 10, '
        '"notifications": {"SNMPEnabled": true, "SMTPSettings": {"settingsType": "Custom", "isEnabled": false, '
        '"recipients": [], "subject": "[%JobResult%] %JobName% (%Time%)", "notifyOnSuccess": true, '
        '"notifyOnWarning": true, "notifyOnError": true}}, "schedule": {"isEnabled": true, "daily": '
        '{"dailyKind": "Everyday", "isEnabled": true, "localTime": "10:00", "days": '
        '["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]}, "monthly": '
        '{"dayOfWeek": "saturday", "dayNumberInMonth": "Fourth", "isEnabled": false, "localTime": "22:00", '
        '"dayOfMonth": null, "months": ["January", "February", "March", "April", "May", "June", "July", '
        '"August", "September", "October", "November", "December"]}}, "lastSuccessfulBackup": '
        '{"lastSuccessfulTime": "2024-05-13T10:00:51.018689-07:00", "sessionId": '
        '"8465a7d4-6033-45db-b446-bb36fcf1eab5"}, "encryption": {"isEnabled": false, '
        '"passwordId": "00000000-0000-0000-0000-000000000000"}, '
        '"details": "Last successful backup: 2024-05-13T10:00:51.018689-07:00", '
        '"incident_type": "Configuration Backup"}'
    ),
    "severity": IncidentSeverity.MEDIUM,
}


@pytest.mark.parametrize(
    "last_successful_backup_date, backup_older_then_days, response_data, expected_results",
    [
        # 1 test case: backup_older_then_days = 0 => we expect events
        # and new 'last_successful_backup_date' cause the last successful backup was a lot of days ago;
        ("", 0, GET_CONF_BACKUP_RESPONSE, (CONF_BACKUP_INCIDENT, "2024-05-13T10:00:51.018689-07:00")),
        # 2 test case: last_successful_backup_date = 2024-06-13T10:00:51.018689-07:00 =>
        # we expect 0 events and no change of 'last_successful_backup_date'
        # because the last successful backup date is newer than the event's
        ("2024-06-13T10:00:51.018689-07:00", 0, GET_CONF_BACKUP_RESPONSE, ({}, "2024-06-13T10:00:51.018689-07:00")),
        # 3 test case: last_successful_backup_date = 2024-04-13T10:00:51.018689-07:00 =>
        # we expect events and new 'last_successful_backup_date'
        # because last successfull backup date older than the event's
        (
            "2024-04-13T10:00:51.018689-07:00",
            0,
            GET_CONF_BACKUP_RESPONSE,
            (CONF_BACKUP_INCIDENT, "2024-05-13T10:00:51.018689-07:00"),
        ),
    ],
)
def test_get_configuration_backup_incident(
    client, mocker, last_successful_backup_date, backup_older_then_days, response_data, expected_results
):
    mock_handle_command_with_token_refresh = mocker.patch("VBRRESTAPI.handle_command_with_token_refresh")
    mock_handle_command_with_token_refresh.return_value = response_data

    fetch_client = FetchClient(client, {})
    backup_incident, backupDate = fetch_client.get_configuration_backup_incident(
        last_successful_backup_date, backup_older_then_days
    )
    if backup_incident:
        expected_results[0]["occurred"] = backup_incident["occurred"]

    assert backup_incident == expected_results[0]
    assert backupDate == expected_results[1]

    backup_incident, backupDate = fetch_client.get_configuration_backup_incident(backupDate, backup_older_then_days)
    assert mock_handle_command_with_token_refresh.call_count == 2
    assert len(backup_incident) == 0
    assert backupDate == expected_results[1]


REPOS_SPACE_EVENTS = util_load_json("test_data/repos_space_events.json")
REPOS_SPACE_INCIDENTS = [
    {
        "name": "Veeam - Repository Default Backup Repository is running low on disk space. Free space: 68.9",
        "occurred": "2024-05-16T07:21:32Z",
        "rawJSON": (
            '{"type": "WinLocal", "id": "88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec", '
            '"name": "Default Backup Repository", "description": "Created by Veeam Backup", '
            '"hostId": "6745a759-2205-4cd2-b172-8ec8f7e60ef8", "hostName": "WIN-Q4F3IF4VR1L", '
            '"path": "C:\\\\Backup", "capacityGB": 149.4, "freeGB": 68.9, "usedSpaceGB": 30.6, '
            '"details": "Created by Veeam Backup; Repository Name: Default Backup Repository; '
            'Free Space (GB): 68.9; Hostname: WIN-Q4F3IF4VR1L", "incident_type": "Repository Capacity"}'
        ),
        "severity": IncidentSeverity.HIGH,
    }
]


@pytest.mark.parametrize(
    "existed_ids, max_events_for_fetch, free_space_less_then, response_data, expected_results",
    [
        # 1 test case: 'free_space_less_then' == 50 =>
        # we expect 0 events because our event has 69 free gb
        (set(), DEFAULT_FETCH, 50, REPOS_SPACE_EVENTS, ([], set())),
        # 2 test case: 'free_space_less_then' == 200 =>
        # we expect new event because our event has 69 free gb
        (set(), DEFAULT_FETCH, 200, REPOS_SPACE_EVENTS, (REPOS_SPACE_INCIDENTS, {"88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec"})),
        # 3 test case: 'free_space_less_then' == 200 but we have event id in 'existed_ids' =>
        # we expect 0 events because this event already exist
        (
            {"88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec"},
            DEFAULT_FETCH,
            200,
            REPOS_SPACE_EVENTS,
            ([], {"88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec"}),
        ),
        # 4 test case: 'max_events_for_fetch' == 0 =>
        # we expect 0 events cause we have 'max_events_for_fetch' = 0;
        (set(), 0, 200, REPOS_SPACE_EVENTS, ([], set())),
    ],
)
def test_get_repository_space_incidents(
    client, mocker, existed_ids, max_events_for_fetch, free_space_less_then, response_data, expected_results
):
    mock_search_with_paging = mocker.patch("VBRRESTAPI.search_with_paging")
    mock_search_with_paging.return_value = response_data

    fetch_client = FetchClient(client, {})
    free_space_incidents, repositoryIds = fetch_client.get_repository_space_incidents(
        existed_ids, max_events_for_fetch, free_space_less_then
    )
    if free_space_incidents:
        expected_results[0][0]["occurred"] = free_space_incidents[0]["occurred"]

    assert free_space_incidents == expected_results[0]
    assert repositoryIds == expected_results[1]

    free_space_incidents, repositoryIds = fetch_client.get_repository_space_incidents(
        repositoryIds, max_events_for_fetch, free_space_less_then
    )
    assert mock_search_with_paging.call_count == 2
    assert len(free_space_incidents) == 0
    assert repositoryIds == expected_results[1]


GET_SECURITY_ANALYZER_BEST_PRACTICES_RESPONSE = util_load_json("test_data/get_security_analyzer_best_practices_response.json")
SECURITY_ANALYZER_EVENTS = GET_SECURITY_ANALYZER_BEST_PRACTICES_RESPONSE["items"]


SECURITY_ANALYZER_INCIDENT = [
    {
        "name": (
            "Veeam - Configuration is not compliant with security best practices. "
            "Affected parameter: Ensure backup encryption is enabled"
        ),
        "occurred": "",
        "rawJSON": (
            '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "bestPractice": "Ensure backup encryption is enabled", '
            '"status": "Violation", "note": "Encryption not configured", '
            '"details": "Ensure backup encryption is enabled; Status: Violation; Note: Encryption not configured", '
            '"incident_type": "Security Analyzer Violation"}'
        ),
        "severity": IncidentSeverity.CRITICAL,
    }
]

SECURITY_ANALYZER_EVENTS_EMPTY_NOTE = util_load_json("test_data/security_analyzer_events_empty_note.json")
SECURITY_ANALYZER_INCIDENT_EMPTY_NOTE = [
    {
        "name": (
            "Veeam - Configuration is not compliant with security best practices. "
            "Affected parameter: Ensure backup encryption is enabled"
        ),
        "occurred": "",
        "rawJSON": (
            '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "bestPractice": "Ensure backup encryption is enabled", '
            '"status": "Violation", "note": "", '
            '"details": "Ensure backup encryption is enabled; Status: Violation; Note: N/A", '
            '"incident_type": "Security Analyzer Violation"}'
        ),
        "severity": IncidentSeverity.CRITICAL,
    }
]


@pytest.mark.parametrize(
    "existed_ids, response_data, expected_results",
    [
        # 1: new violation with no prior ids => creates incident
        (set(), SECURITY_ANALYZER_EVENTS, (SECURITY_ANALYZER_INCIDENT, {"a1b2c3d4-e5f6-7890-abcd-ef1234567890"})),
        # 2: violation id already in existed_ids => no new incident, id kept
        ({"a1b2c3d4-e5f6-7890-abcd-ef1234567890"}, SECURITY_ANALYZER_EVENTS, ([], {"a1b2c3d4-e5f6-7890-abcd-ef1234567890"})),
        # 3: only non-violation statuses => no incident
        (
            set(),
            [
                {
                    "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                    "bestPractice": "Configure email notifications",
                    "status": "OK",
                    "note": "",
                }
            ],
            ([], set()),
        ),
        # 4: violation with empty note => note replaced with N/A
        (
            set(),
            SECURITY_ANALYZER_EVENTS_EMPTY_NOTE,
            (SECURITY_ANALYZER_INCIDENT_EMPTY_NOTE, {"a1b2c3d4-e5f6-7890-abcd-ef1234567890"}),
        ),
    ],
)
def test_get_security_analyzer_incident(client, mocker, existed_ids, response_data, expected_results):
    mock_request = mocker.patch("VBRRESTAPI.handle_command_with_token_refresh")
    mock_request.return_value = {"items": response_data}

    fetch_client = FetchClient(client, {})
    incidents, security_ids = fetch_client.get_security_analyzer_incidents(existed_ids)

    if incidents:
        expected_results[0][0]["occurred"] = incidents[0]["occurred"]

    assert incidents == expected_results[0]
    assert security_ids == expected_results[1]

    # second call with returned ids should produce no new incidents
    incidents, security_ids = fetch_client.get_security_analyzer_incidents(security_ids)
    assert mock_request.call_count == 2
    assert len(incidents) == 0
    assert security_ids == expected_results[1]


SURE_BACKUP_EVENTS = util_load_json("test_data/sure_backup_events.json")
SURE_BACKUP_INCIDENTS = [
    {
        "name": "Veeam - SureBackup job SureBackup Job 1 (backup verification and content scan only) has failed",
        "occurred": "",
        "rawJSON": (
            '{"id": "f1e2d3c4-b5a6-7890-fedc-ba9876543210", "name": "SureBackup Job 1", '
            '"description": "SureBackup Job Description", "objectsCount": 5, '
            '"lastResult": "Failed", "lastRun": "2024-05-16T07:21:32Z", '
            '"status": "Stopped", "type": "SureBackupContentScan", '
            '"details": "SureBackup Job Description; Job Name: SureBackup Job 1; '
            'Object Count: 5; Last Run: 2024-05-16T07:21:32Z", '
            '"incident_type": "SureBackup Content Scan Failed"}'
        ),
        "severity": IncidentSeverity.CRITICAL,
    }
]


@pytest.mark.parametrize(
    "existed_ids, response_data, expected_results",
    [
        # 1: new failed job with no prior ids => creates incident
        (set(), SURE_BACKUP_EVENTS, (SURE_BACKUP_INCIDENTS, {"f1e2d3c4-b5a6-7890-fedc-ba9876543210"})),
        # 2: failed job id already in existed_ids => no new incident, id kept
        ({"f1e2d3c4-b5a6-7890-fedc-ba9876543210"}, SURE_BACKUP_EVENTS, ([], {"f1e2d3c4-b5a6-7890-fedc-ba9876543210"})),
        # 3: non-failed job => no incident
        (
            set(),
            [
                {
                    "id": "a0b1c2d3-e4f5-6789-abcd-ef0123456789",
                    "name": "SureBackup Job 2",
                    "description": "Desc",
                    "objectsCount": 3,
                    "lastResult": "Success",
                    "lastRun": "2024-05-16T07:21:32Z",
                    "status": "Stopped",
                    "type": "SureBackupContentScan",
                }
            ],
            ([], set()),
        ),
    ],
)
def test_get_sure_backup_incidents(client, mocker, existed_ids, response_data, expected_results):
    mock_search_with_paging = mocker.patch("VBRRESTAPI.search_with_paging")
    mock_search_with_paging.return_value = response_data

    fetch_client = FetchClient(client, {})
    incidents, sure_backup_ids = fetch_client.get_sure_backup_incidents(existed_ids)

    if incidents:
        expected_results[0][0]["occurred"] = incidents[0]["occurred"]

    assert incidents == expected_results[0]
    assert sure_backup_ids == expected_results[1]

    # second call with returned ids should produce no new incidents
    incidents, sure_backup_ids = fetch_client.get_sure_backup_incidents(sure_backup_ids)
    assert mock_search_with_paging.call_count == 2
    assert len(incidents) == 0
    assert sure_backup_ids == expected_results[1]


@pytest.mark.parametrize(
    "last_run, errors_by_command, expected_result",
    [
        (
            {"sure_backup_ids": ["f1e2d3c4-b5a6-7890-fedc-ba9876543210", "a0b1c2d3-e4f5-6789-abcd-ef0123456789"]},
            {"error_count_in_sure_backup": 0},
            ({"f1e2d3c4-b5a6-7890-fedc-ba9876543210", "a0b1c2d3-e4f5-6789-abcd-ef0123456789"}, [], set()),
        ),
    ],
)
def test_fetch_sure_backup_incidents(client, mocker, last_run, errors_by_command, expected_result):
    mock_get_sure_backup_incidents = mocker.patch.object(FetchClient, "get_sure_backup_incidents")
    mock_get_sure_backup_incidents.return_value = ([], set())

    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_sure_backup_incidents()

    args = mock_get_sure_backup_incidents.call_args[0]
    assert args[0] == expected_result[0]
    assert fetch_client.incidents == expected_result[1]
    assert set(fetch_client.next_run["sure_backup_ids"]) == expected_result[2]
    assert fetch_client.errors_by_command["error_count_in_sure_backup"] == 0


@pytest.mark.parametrize(
    "last_run, errors_by_command, expected_incidents",
    [
        ({"sure_backup_ids": []}, {"error_count_in_sure_backup": 1}, [{"type": "incident_on_error"}]),
    ],
)
def test_fetch_sure_backup_incidents_with_exception(client, mocker, last_run, errors_by_command, expected_incidents):
    mocker.patch.object(FetchClient, "get_sure_backup_incidents", side_effect=Exception("API failure"))
    mock_process_error = mocker.patch("VBRRESTAPI.process_error")
    mock_process_error.return_value = ({"type": "incident_on_error"}, 2)
    mocker.patch.object(demisto, "debug")

    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_sure_backup_incidents()

    mock_process_error.assert_called_once()
    assert fetch_client.incidents == expected_incidents
    assert fetch_client.errors_by_command["error_count_in_sure_backup"] == 2


@pytest.mark.parametrize(
    "last_run, max_results, errors_by_command, expected_result",
    [
        ({"repository_ids": [1, 2, 3]}, 10, {"error_count_in_free_space_incidents": 0}, ({1, 2, 3}, [], set())),
    ],
)
def test_fetch_repository_space_incidents(client, mocker, last_run, max_results, errors_by_command, expected_result):
    mock_get_repository_space_incidents = mocker.patch.object(FetchClient, "get_repository_space_incidents")
    mock_get_repository_space_incidents.return_value = ([], set())

    free_space_less_then = 200
    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_repository_space_incidents(max_results, free_space_less_then)

    args = mock_get_repository_space_incidents.call_args[0]
    assert args[0] == expected_result[0]
    assert fetch_client.incidents == expected_result[1]
    assert set(fetch_client.next_run["repository_ids"]) == expected_result[2]


@pytest.mark.parametrize(
    "last_run, max_results, errors_by_command, expected_result",
    [
        (
            {"repository_ids": [1, 2, 3]},
            10,
            {"error_count_in_free_space_incidents": 1},
            ([{"type": "incident_on_error"}], [1, 2, 3]),
        ),
    ],
)
def test_fetch_repository_space_incidents_with_exception(
    client, mocker, last_run, max_results, errors_by_command, expected_result
):
    mocker.patch.object(FetchClient, "get_repository_space_incidents", side_effect=Exception("error"))
    mock_process_error = mocker.patch("VBRRESTAPI.process_error")
    mock_process_error.return_value = ({"type": "incident_on_error"}, 1)
    mocker.patch.object(demisto, "debug")

    free_space_less_then = 200
    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_repository_space_incidents(max_results, free_space_less_then)

    mock_process_error.assert_called_once()
    assert fetch_client.incidents == expected_result[0]
    assert fetch_client.next_run["repository_ids"] == expected_result[1]


@pytest.mark.parametrize(
    "last_run, max_results, errors_by_command, expected_result",
    [
        (
            {"malware_ids": [1, 2, 3]},
            10,
            {"error_count_in_malware_incidents": 0},
            ({1, 2, 3, 4, 5}, {"post_event_ids": []}, [], set()),
        ),
    ],
)
def test_fetch_malware_events(client, mocker, last_run, max_results, errors_by_command, expected_result):
    mock_get_malware_incidents = mocker.patch.object(FetchClient, "get_malware_incidents")
    mock_get_malware_incidents.return_value = ([], set(), "2024-05-24T15:42:22.198Z")
    mocker.patch.object(demisto, "getIntegrationContext", return_value={"post_event_ids": [4, 5]})
    mock_set_integration_context = mocker.patch.object(demisto, "setIntegrationContext")

    first_fetch_time = "2024-05-24T15:42:22.198Z"
    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_malware_events(first_fetch_time, max_results)

    args = mock_get_malware_incidents.call_args[0]
    assert args[1] == expected_result[0]
    set_context_args = mock_set_integration_context.call_args[0]
    assert set_context_args[0] == expected_result[1]
    assert fetch_client.incidents == expected_result[2]
    assert set(fetch_client.next_run["malware_ids"]) == expected_result[3]


@pytest.mark.parametrize(
    "last_run, errors_by_command, expected_result",
    [({"backup_date": "2024-05-24T15:42:22.198Z"}, {"error_count_in_configuration_backup": 0}, "2024-05-24T15:42:22.198Z")],
)
def test_fetch_configuration_backup_incident(client, mocker, last_run, errors_by_command, expected_result):
    mock_get_configuration_backup_incident = mocker.patch.object(FetchClient, "get_configuration_backup_incident")
    mock_get_configuration_backup_incident.return_value = ({}, "2024-05-24T15:42:22.198Z")

    backup_older_then_days = 30
    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_configuration_backup_incident(backup_older_then_days)

    args = mock_get_configuration_backup_incident.call_args[0]
    assert args[0] == expected_result


@pytest.mark.parametrize(
    "last_run, errors_by_command, expected_result",
    [
        (
            {"security_ids": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890", "b2c3d4e5-f6a7-8901-bcde-f12345678901"]},
            {"error_count_in_security_analyzer": 0},
            ({"a1b2c3d4-e5f6-7890-abcd-ef1234567890", "b2c3d4e5-f6a7-8901-bcde-f12345678901"}, [], set()),
        ),
    ],
)
def test_fetch_security_analyzer_incidents(client, mocker, last_run, errors_by_command, expected_result):
    mock_handle = mocker.patch.object(FetchClient, "get_security_analyzer_incidents")
    mock_handle.return_value = ([], set())

    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_security_analyzer_incidents()

    args = mock_handle.call_args[0]
    assert args[0] == expected_result[0]
    assert fetch_client.incidents == expected_result[1]
    assert set(fetch_client.next_run["security_ids"]) == expected_result[2]
    assert fetch_client.errors_by_command["error_count_in_security_analyzer"] == 0


@pytest.mark.parametrize(
    "last_run, errors_by_command, expected_incidents",
    [
        ({"security_ids": []}, {"error_count_in_security_analyzer": 1}, [{"type": "incident_on_error"}]),
    ],
)
def test_fetch_security_analyzer_incidents_with_exception(client, mocker, last_run, errors_by_command, expected_incidents):
    mocker.patch.object(FetchClient, "get_security_analyzer_incidents", side_effect=Exception("API failure"))
    mock_process_error = mocker.patch("VBRRESTAPI.process_error")
    mock_process_error.return_value = ({"type": "incident_on_error"}, 2)
    mocker.patch.object(demisto, "debug")

    fetch_client = FetchClient(client, {**last_run, "errors_by_command": errors_by_command})
    fetch_client.fetch_security_analyzer_incidents()

    mock_process_error.assert_called_once()
    assert fetch_client.incidents == expected_incidents
    assert fetch_client.errors_by_command["error_count_in_security_analyzer"] == 2


FETCH_ERROR_INCIDENT = {
    "name": "Veeam - Fetch incident error has occurred on ",
    "occurred": datetime.now().strftime(DATE_FORMAT),
    "rawJSON": '{"incident_type": "Incident Fetch Error", "details": "Sample error message"}',
    "severity": IncidentSeverity.MEDIUM,
}


@pytest.mark.parametrize(
    "error_count, error_message, expected_results",
    [
        # 1 test case: first error -> 1 error_count and 0 incidents
        (0, "Sample error message", (1, {})),
        # 2 test case: sixth error in a row -> 6 error_count and new incident
        (5, "Sample error message", (6, FETCH_ERROR_INCIDENT)),
    ],
)
def test_process_error(error_count, error_message, expected_results):
    incident, new_error_count = process_error(error_count, error_message)
    if incident:
        expected_results[1]["occurred"] = incident["occurred"]

    assert new_error_count == expected_results[0]
    assert incident == expected_results[1]


RESPONSE = [
    (MALWARE_INCIDENTS, ["b9b6d52f-d8ac-448f-ac32-5b86e07d05fa"], "2024-04-24T15:42:22.198Z"),
    (REPOS_SPACE_INCIDENTS, ["88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec"]),
    ([CONF_BACKUP_INCIDENT], "2024-05-13T10:00:51.018689-07:00"),
    ([SECURITY_ANALYZER_INCIDENT], ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"]),
    (SURE_BACKUP_INCIDENTS, ["f1e2d3c4-b5a6-7890-fedc-ba9876543210"]),
]

LAST_RUN = {
    "last_fetch": "2024-04-24T15:42:22.198Z",
    "malware_ids": ["b9b6d52f-d8ac-448f-ac32-5b86e07d05fa"],
    "repository_ids": ["88788f9e-d8f5-4eb4-bc4f-9b3f5403bcec"],
    "security_ids": ["a1b2c3d4-e5f6-7890-abcd-ef1234567890"],
    "sure_backup_ids": ["f1e2d3c4-b5a6-7890-fedc-ba9876543210"],
    "backup_date": "2024-05-13T10:00:51.018689-07:00",
    "errors_by_command": {},
}


@pytest.mark.parametrize(
    "last_run, first_fetch_time, response_data, expected_results",
    [
        # 1 test case:
        ({}, "2024-04-23T15:42:22.198Z", RESPONSE, (LAST_RUN, 5))
    ],
)
def test_fetch_incidents(client, mocker, last_run, first_fetch_time, response_data, expected_results):
    fetch_client = FetchClient(client, last_run)

    def malware_side_effect(first_fetch_time, max_results):
        fetch_client.incidents.extend(response_data[0][0])
        fetch_client.next_run["malware_ids"] = response_data[0][1]
        fetch_client.next_run["last_fetch"] = response_data[0][2]

    def repo_side_effect(max_results, free_space_less_then):
        fetch_client.incidents.extend(response_data[1][0])
        fetch_client.next_run["repository_ids"] = response_data[1][1]

    def backup_side_effect(backup_older_then_days):
        fetch_client.incidents.extend(response_data[2][0])
        fetch_client.next_run["backup_date"] = response_data[2][1]

    def security_side_effect():
        fetch_client.incidents.extend(response_data[3][0])
        fetch_client.next_run["security_ids"] = response_data[3][1]

    def sure_backup_side_effect():
        fetch_client.incidents.extend(response_data[4][0])
        fetch_client.next_run["sure_backup_ids"] = response_data[4][1]

    mock_fetch_malware_events = mocker.patch.object(FetchClient, "fetch_malware_events", side_effect=malware_side_effect)
    mock_fetch_repository_space_incidents = mocker.patch.object(
        FetchClient, "fetch_repository_space_incidents", side_effect=repo_side_effect
    )
    mock_fetch_configuration_backup_incident = mocker.patch.object(
        FetchClient, "fetch_configuration_backup_incident", side_effect=backup_side_effect
    )
    mock_fetch_security_analyzer_incidents = mocker.patch.object(
        FetchClient, "fetch_security_analyzer_incidents", side_effect=security_side_effect
    )
    mock_fetch_sure_backup_incidents = mocker.patch.object(
        FetchClient, "fetch_sure_backup_incidents", side_effect=sure_backup_side_effect
    )

    next_run, incidents = fetch_client.fetch_incidents(
        first_fetch_time=first_fetch_time,
        max_malware_events_for_fetch=DEFAULT_FETCH,
        max_repos_space_events_for_fetch=DEFAULT_FETCH,
        backup_older_then_days=30,
        free_space_less_then=200,
        fetch_malware_incidents=True,
        fetch_backup_repository_events=True,
        fetch_configuration_backup_events=True,
        fetch_security_analyzer_events=True,
        fetch_sure_backup_events=True,
    )
    mock_fetch_malware_events.assert_called_once()
    mock_fetch_repository_space_incidents.assert_called_once()
    mock_fetch_configuration_backup_incident.assert_called_once()
    mock_fetch_security_analyzer_incidents.assert_called_once()
    mock_fetch_sure_backup_incidents.assert_called_once()

    assert next_run == expected_results[0]
    assert len(incidents) == expected_results[1]


RESPONSE_DATA = {"data": [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}]}


@pytest.mark.parametrize(
    "page_size, size_limit, response, expected_result, expected_calls",
    [
        (
            3,
            0,
            RESPONSE_DATA,
            [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}],
            [{"skip": 0, "limit": 3}, {"skip": 3, "limit": 3}],
        ),
        (100, 0, RESPONSE_DATA, [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}], [{"skip": 0, "limit": 100}]),
        (4, 2, RESPONSE_DATA, [{"id": 1}, {"id": 2}], [{"skip": 0, "limit": 2}]),
        (3, 3, RESPONSE_DATA, [{"id": 1}, {"id": 2}, {"id": 3}], [{"skip": 0, "limit": 3}]),
    ],
)
def test_search_with_paging(mocker, page_size, size_limit, response, expected_result, expected_calls):
    method_mock = ApiMock(response)
    args = {}
    result = search_with_paging(method_mock, args, page_size, size_limit)

    assert result == expected_result
    actual_calls = method_mock.call_args_list
    for actual_call, expected_call in zip(actual_calls, expected_calls):
        assert actual_call == expected_call

    assert method_mock.call_count == len(expected_calls)


def test_validate_filter_parameter():
    try:
        value = 128  # normal int value
        validate_filter_parameter(value)
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "value",
    [
        -1,  # negative int
        MAX_INT + 1,  # more than max_int value
    ],
)
def test_validate_filter_parameter_with_exception(value):
    with pytest.raises(ValueError):
        validate_filter_parameter(value)


@pytest.mark.parametrize(
    "command",
    [
        ("veeam-vbr-get-session"),
        ("veeam-vbr-get-configuration-backup"),  # all real commands
    ],
)
def test_process_command(client, mocker, command):
    mock_handle_command_with_token_refresh = mocker.patch("VBRRESTAPI.handle_command_with_token_refresh")
    try:
        process_command(command, client, datetime.now(), {}, {})
        mock_handle_command_with_token_refresh.assert_called_once()
    except Exception as e:
        pytest.fail(f"raised {e}")


@pytest.mark.parametrize(
    "command",
    [
        ("test-"),
        ("vbr-get-"),  # not real commands
    ],
)
def test_process_command_with_exception(client, mocker, command):
    mocker.patch("VBRRESTAPI.handle_command_with_token_refresh")
    with pytest.raises(NotImplementedError):
        process_command(command, client, datetime.now(), {}, {})


def test_handle_command_with_token_refresh_attempts(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        "VBRRESTAPI.demisto.getIntegrationContext", side_effect=[{}, {}, {}, {}, {"token": "valid"}]
    )  # only on 3 attempt give context
    mock_setIntegrationContext = mocker.patch("VBRRESTAPI.demisto.setIntegrationContext")
    mock_get_api_key = mocker.patch("VBRRESTAPI.get_api_key", return_value="new_api_key")
    mock_set_api_key = mocker.patch("VBRRESTAPI.set_api_key")
    mocker.patch("VBRRESTAPI.Client.get_license_request", return_value={})
    mocker.patch("VBRRESTAPI.check_license")

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [
        DemistoException(message="test", res=response),
        DemistoException(message="test", res=response),
        {"res": "success"},
    ]  # 3 attemps -> last success

    result = handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert result == {"res": "success"}
    assert mock_getIntegrationContext.call_count == 5  # 3 calls + 2 on exception
    assert mock_get_api_key.call_count == 2
    assert mock_setIntegrationContext.call_count == 4  # 2 resets + 2 setting token
    assert mock_set_api_key.call_count == 3
    assert mock_command.call_count == 3


def test_handle_command_with_token_refresh_attempts_exception(client, mocker):
    mock_getIntegrationContext = mocker.patch("VBRRESTAPI.demisto.getIntegrationContext", side_effect=[{}, {}, {}, {}, {}, {}])
    mock_setIntegrationContext = mocker.patch("VBRRESTAPI.demisto.setIntegrationContext")
    mock_get_api_key = mocker.patch("VBRRESTAPI.get_api_key", return_value="new_api_key")
    mock_set_api_key = mocker.patch("VBRRESTAPI.set_api_key")
    mocker.patch("VBRRESTAPI.Client.get_license_request", return_value={})
    mocker.patch("VBRRESTAPI.check_license")

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [
        DemistoException(message="test", res=response),
        DemistoException(message="test", res=response),
        DemistoException(message="test", res=response),
    ]  # all 3 attemps fail

    with pytest.raises(ValueError):
        handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert mock_getIntegrationContext.call_count == 6  # 3 calls + 1 on exception
    assert mock_get_api_key.call_count == 3
    assert mock_setIntegrationContext.call_count == 6  # 3 resets + 3 setting token
    assert mock_set_api_key.call_count == 3
    assert mock_command.call_count == 3


def test_handle_command_with_token_refresh(client, mocker):
    mock_getIntegrationContext = mocker.patch(
        "VBRRESTAPI.demisto.getIntegrationContext", side_effect=[{}, {"token": "new_api_key"}, {}, {"token": "new_api_key"}]
    )
    mock_setIntegrationContext = mocker.patch("VBRRESTAPI.demisto.setIntegrationContext")
    mock_get_api_key = mocker.patch("VBRRESTAPI.get_api_key", return_value="new_api_key")
    mock_set_api_key = mocker.patch("VBRRESTAPI.set_api_key")
    mocker.patch("VBRRESTAPI.Client.get_license_request", return_value={})
    mocker.patch("VBRRESTAPI.check_license")

    mock_command = Mock()
    response = requests.models.Response()
    response.status_code = 401
    mock_command.side_effect = [DemistoException(message="test", res=response), {"res": "success"}]
    result = handle_command_with_token_refresh(mock_command, {}, client, max_attempts=3)

    assert result == {"res": "success"}

    assert mock_getIntegrationContext.call_count == 3
    assert mock_get_api_key.call_count == 2
    assert mock_setIntegrationContext.call_count == 3
    assert mock_set_api_key.call_count == 2
    assert mock_command.call_count == 2

    mock_setIntegrationContext.assert_any_call({"token": "new_api_key"})
    mock_set_api_key.assert_any_call(client, "new_api_key")

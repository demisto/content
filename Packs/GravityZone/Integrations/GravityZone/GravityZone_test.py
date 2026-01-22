import json
import os
from unittest.mock import patch
from freezegun import freeze_time
import pytest


SERVER_URL = "https://localhost"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_client():
    from GravityZone import Client

    return Client(url=SERVER_URL, verify=False, api_key="fake")


def load_api_mocked_data(requests_mock, command_name):
    command_renamed = command_name.replace("-", "_")
    function_name = f"{command_renamed}_command"

    api_file_path = os.path.join(os.path.dirname(__file__), "test_data", f"{function_name}_api.json")
    data = util_load_json(api_file_path)

    # Group responses by URL and method
    url_responses = {}
    for item in data:
        url = f"{SERVER_URL}{item['request']['url']}"
        method = "get" if item["request"].get("get", False) else "post"
        url_responses.setdefault((method, url), []).append(item["response"])

    # Register each URL/method with a callback to return responses sequentially
    for (method, url), responses in url_responses.items():
        response_iter = iter(responses)

        def get_callback(request, context, response_iter=response_iter, responses=responses):
            try:
                resp = next(response_iter)
            except StopIteration:
                resp = responses[-1]
            if "content" in resp:
                context.status_code = resp.get("status_code", 200)
                for k, v in resp.get("headers", {}).items():
                    context.headers[k] = v
                return resp["content"].encode()
            return resp

        def post_callback(request, context, response_iter=response_iter, responses=responses):
            try:
                return next(response_iter)
            except StopIteration:
                return responses[-1]

        if method == "post":
            requests_mock.post(url, json=post_callback)
        else:
            requests_mock.get(url, content=get_callback)


def assert_command_mocked_data(command_name, command_response, polling_func=None, client=None):
    test_data_dir = os.path.join(os.path.dirname(__file__), "test_data")

    command_renamed = command_name.replace("-", "_")
    function_name = f"{command_renamed}_command"

    if polling_func is not None and client is not None:
        while getattr(command_response, "scheduled_command", None):
            command_response = polling_func(command_response.scheduled_command._args, client)

    if isinstance(command_response, list):
        command_response = command_response[0]

    context = command_response.to_context()

    raw_response = context.get("Contents")
    human_readable = context.get("HumanReadable")
    outputs = context.get("EntryContext")

    def assert_file_content(actual, expected_paths, error_msg):
        if not any(os.path.exists(p) for p in expected_paths):
            raise FileNotFoundError(f"No expected file found for {function_name} in paths: {expected_paths}")
        for expected_path in expected_paths:
            if not os.path.exists(expected_path):
                continue
            with open(expected_path, encoding="utf-8") as f:
                expected = f.read() if expected_path.endswith((".md", ".txt")) else json.load(f)
                assert actual == expected, f"{error_msg} for {function_name}"

    assert_file_content(
        raw_response,
        [
            os.path.join(test_data_dir, f"{function_name}_raw_response.json"),
            os.path.join(test_data_dir, f"{function_name}_raw_response.txt"),
        ],
        "Raw response does not match",
    )
    assert_file_content(
        human_readable, [os.path.join(test_data_dir, f"{function_name}_human_readable.md")], "Human readable does not match"
    )
    assert_file_content(
        outputs, [os.path.join(test_data_dir, f"{function_name}_entry_context.json")], "Entry context does not match"
    )


@patch("GravityZone.demisto")
def test_fetch_incidents_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling fetch-incidents command
    Then
            Make sure the fetched incidents values are as expected.
    """

    # Prepare
    from GravityZone import fetch_incidents_command

    mock_demisto.command.return_value = "fetch-incidents"
    mock_demisto.args.return_value = {}
    mock_demisto.getLastRun.return_value = {}
    mock_demisto.integrationInstance.return_value = "GravityZone"
    mock_demisto.params.return_value = {"max_fetch": 2, "first_fetch": "3 days"}
    load_api_mocked_data(requests_mock, "fetch-incidents")
    client = get_client()
    fetch_incidents_command(client, {})

    assert mock_demisto.incidents.call_count == 1
    assert len(mock_demisto.incidents.call_args[0][0]) == 2

    incidents = mock_demisto.incidents.call_args[0][0]
    for incident in incidents:
        assert "name" in incident
        assert "occurred" in incident
        assert "rawJSON" in incident

    incident_names = [incident.get("name") for incident in incidents]
    assert incident_names == ["477", "475"]


@patch("GravityZone.demisto")
def test_get_remote_data_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling get-remote-data command
    Then
            Make sure the mirrored incident values are as expected.
    """

    # Prepare
    from GravityZone import get_remote_data_command

    mock_demisto.command.return_value = "get-remote-data"
    mock_demisto.params.return_value = {"mirror_direction": "Both"}
    mock_demisto.integrationInstance.return_value = "GravityZone"
    load_api_mocked_data(requests_mock, "get-remote-data")
    client = get_client()
    result = get_remote_data_command(client, {"id": "6940ee975f5c8b75247c3f38", "lastUpdate": "2024-01-01T00:00:00Z"})
    assert result is not None, "get_remote_data_command returned None"
    local_data = result.extract_for_local() if hasattr(result, "extract_for_local") else None
    assert local_data is not None, "extract_for_local() returned None"
    assert isinstance(local_data, list), "extract_for_local() did not return a list"
    assert len(local_data) > 0, "extract_for_local() returned an empty list"
    assert local_data[0].get("id") == "6940ee975f5c8b75247c3f38"


@patch("GravityZone.demisto")
def test_get_modified_remote_data_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling get-modified-remote-data command
    Then
            Make sure the mirrored incident values are as expected.
    """
    # Prepare
    from GravityZone import get_modified_remote_data_command

    mock_demisto.command.return_value = "get-modified-remote-data"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "get-modified-remote-data")
    client = get_client()
    result = get_modified_remote_data_command(client, {"lastUpdate": ""})
    assert result.to_entry().get("Contents") == ["6940ee975f5c8b75247c3f38", "6940eeadaa87b3d57af088aa"]


@freeze_time("2025-12-16 13:00:00 UTC")
@patch("GravityZone.demisto")
def test_get_mapping_fields_command(mock_demisto, mocker, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling get-mapping-fields command
    Then
            Make sure the mappings values are as expected.
    """
    # Prepare
    from GravityZone import get_mapping_fields_command

    mock_demisto.command.return_value = "get-mapping-fields"
    mock_demisto.params.return_value = {}
    client = get_client()
    response = get_mapping_fields_command(client, {})
    schemes = response.extract_mapping()
    assert len(schemes) == 2

    xdr_scheme = next((s for s in schemes if s == "GravityZone XDR"), None)
    edr_scheme = next((s for s in schemes if s == "GravityZone EDR"), None)

    assert xdr_scheme is not None
    assert edr_scheme is not None


@freeze_time("2025-12-16 13:00:00 UTC")
@patch("GravityZone.demisto")
def test_test_module(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling test-module command
    Then
            Make sure the command works.
    """

    # Prepare
    from GravityZone import test_module

    mock_demisto.command.return_value = "test-module"
    mock_demisto.params.return_value = {
        "first_fetch": "3 days",
    }
    mock_demisto.args.return_value = {}
    load_api_mocked_data(requests_mock, "test-module")
    client = get_client()

    # Execute command
    result = test_module(client=client, args={})

    # Assert
    assert result == "ok"


@patch("GravityZone.demisto")
def test_gz_list_endpoints_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-list-endpoints command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_list_endpoints_command

    mock_demisto.command.return_value = "gz-list-endpoints"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-list-endpoints")
    client = get_client()

    # Execute command
    command_response = gz_list_endpoints_command(client=client, args={})

    # Assert command response
    assert_command_mocked_data("gz-list-endpoints", command_response)


@patch("GravityZone.demisto")
def test_endpoint_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import endpoint_command

    mock_demisto.command.return_value = "endpoint"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "endpoint")
    client = get_client()

    # Execute command
    command_response = endpoint_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("endpoint", command_response)


@patch("GravityZone.demisto")
def test_get_endpoint_by_id_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-get-endpoint-by-id command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """
    # Prepare
    from GravityZone import gz_get_endpoint_by_id_command

    mock_demisto.command.return_value = "gz_get_endpoint_by_id"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz_get_endpoint_by_id")
    client = get_client()

    # Execute command
    command_response = gz_get_endpoint_by_id_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("gz_get_endpoint_by_id", command_response)


@patch("GravityZone.demisto")
def test_gz_isolate_endpoint_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-isolate-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_isolate_endpoint_command, gz_poll_task_status_command

    mock_demisto.command.return_value = "gz-isolate-endpoint"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-isolate-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_isolate_endpoint_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("gz-isolate-endpoint", command_response, polling_func=gz_poll_task_status_command, client=client)


@patch("GravityZone.demisto")
def test_gz_deisolate_endpoint_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-deisolate-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_deisolate_endpoint_command, gz_poll_task_status_command

    mock_demisto.command.return_value = "gz-deisolate-endpoint"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-deisolate-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_deisolate_endpoint_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("gz-deisolate-endpoint", command_response, polling_func=gz_poll_task_status_command, client=client)


@patch("GravityZone.demisto")
def test_gz_kill_process_on_endpoint_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-kill-process-on-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_kill_process_on_endpoint_command,
        gz_poll_task_status_command,
    )

    mock_demisto.command.return_value = "gz-kill-process-on-endpoint"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-kill-process-on-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_kill_process_on_endpoint_command(
        client=client,
        args={
            "id": "ENDPOINT_ID",
            "pid": "5876",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-kill-process-on-endpoint", command_response, polling_func=gz_poll_task_status_command, client=client
    )


@patch("GravityZone.demisto")
def test_gz_run_command_on_endpoint_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-run-command-on-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_run_command_on_endpoint_command,
        gz_poll_investigation_activity_status_command,
    )

    mock_demisto.command.return_value = "gz-run-command-on-endpoint"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-run-command-on-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_run_command_on_endpoint_command(
        client=client,
        args={
            "id": "6942a43afe8d4e463ca5c197",
            "command": "ls -1",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-run-command-on-endpoint", command_response, polling_func=gz_poll_investigation_activity_status_command, client=client
    )


@patch("GravityZone.demisto")
def test_gz_get_process_tree_for_hash_on_endpoint(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-get-process-tree-for-hash-on-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_get_process_tree_for_hash_on_endpoint_command,
        gz_poll_live_search_status_command,
    )

    mock_demisto.command.return_value = "gz-get-process-tree-for-hash-on-endpoint"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-get-process-tree-for-hash-on-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_get_process_tree_for_hash_on_endpoint_command(
        client=client,
        args={
            "id": "ENDPOINT_ID",
            "process_hash": "PROCESS_HASH",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-get-process-tree-for-hash-on-endpoint",
        command_response,
        polling_func=gz_poll_live_search_status_command,
        client=client,
    )


@patch("GravityZone.demisto")
def test_gz_get_endpoints_running_process_hash_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-get-endpoints-running-process-hash command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_get_endpoints_running_process_hash_command,
        gz_poll_live_search_status_command,
    )

    mock_demisto.command.return_value = "gz-get-endpoints-running-process-hash"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-get-endpoints-running-process-hash")
    client = get_client()

    # Execute command
    command_response = gz_get_endpoints_running_process_hash_command(
        client=client,
        args={
            "process_hash": "PROCESS_HASH",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-get-endpoints-running-process-hash", command_response, polling_func=gz_poll_live_search_status_command, client=client
    )


@patch("GravityZone.demisto")
def test_gz_poll_task_status_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-poll-task-status command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_poll_task_status_command

    mock_demisto.command.return_value = "gz-poll-task-status"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-poll-task-status")
    client = get_client()

    # Execute command
    result = gz_poll_task_status_command(
        client=client,
        args={
            "task_id": "6941944218d1fb8aea04019b",
            "metadata": '{"targetId":"ENDPOINT_ID","processId":10252}',
        },
    )

    # Assert command response
    assert_command_mocked_data("gz-poll-task-status", result)


@patch("GravityZone.demisto")
def test_gz_poll_live_search_status_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-poll-live-search-status command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_poll_live_search_status_command

    mock_demisto.command.return_value = "gz-poll-live-search-status"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-poll-live-search-status")
    client = get_client()

    # Execute command
    result = gz_poll_live_search_status_command(
        client=client,
        args={
            "task_id": "694266e8b349a87d10079634",
            "search_type": "fake",
            "metadata": '{"process_hash": "process_hash"}',
        },
    )

    # Assert command response
    assert_command_mocked_data("gz-poll-live-search-status", result)


@patch("GravityZone.demisto")
def test_gz_poll_investigation_activity_status_command(mock_demisto, mocker, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-poll-investigation-activity-status command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_poll_investigation_activity_status_command

    mock_demisto.command.return_value = "gz-poll-investigation-activity-status"
    mock_demisto.params.return_value = {}
    mocker.patch(
        "GravityZone.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 3,
            "File": "downloaded_file.txt",
            "FileID": "abc",
        },
    )
    load_api_mocked_data(requests_mock, "gz-poll-investigation-activity-status")
    client = get_client()

    # Execute command
    result = gz_poll_investigation_activity_status_command(
        client=client,
        args={
            "target_id": "6942a43afe8d4e463ca5c197",
            "activity_id": "6943db6115457d24450196d3",
            "metadata": '{"activityType":2,"command":"ls -1"}',
        },
    )

    # Assert command response
    assert_command_mocked_data("gz-poll-investigation-activity-status", result)


@pytest.mark.parametrize(
    "args, api_mock_name",
    [
        ({}, "gz-list-incidents"),
        ({"endpoint_id": "ENDPOINT_ID"}, "gz-list-incidents-2"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_list_incidents_command(mock_demisto, requests_mock, args, api_mock_name):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-list-incidents command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_list_incidents_command

    mock_demisto.command.return_value = "gz-list-incidents"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, api_mock_name)
    client = get_client()

    # Execute command
    command_response = gz_list_incidents_command(client=client, args=args)

    # Assert command response
    assert_command_mocked_data(api_mock_name, command_response)


@pytest.mark.parametrize(
    "incident_id",
    [
        ("INCIDENT_ID_1"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_get_incident_by_id_edr_command(mock_demisto, requests_mock, incident_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-get-incident-by-id command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_get_incident_by_id_command

    mock_demisto.command.return_value = "gz-get-incident-by-id"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-get-incident-by-id-edr")
    client = get_client()

    # Execute command
    command_response = gz_get_incident_by_id_command(client=client, args={"id": incident_id})

    # Assert command response
    assert_command_mocked_data("gz-get-incident-by-id-edr", command_response)


@pytest.mark.parametrize(
    "incident_id",
    [
        ("INCIDENT_ID_1"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_get_incident_by_id_xdr_command(mock_demisto, requests_mock, incident_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-get-incident-by-id command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_get_incident_by_id_command

    mock_demisto.command.return_value = "gz-get-incident-by-id"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-get-incident-by-id-xdr")
    client = get_client()

    # Execute command
    command_response = gz_get_incident_by_id_command(client=client, args={"id": incident_id})

    # Assert command response
    assert_command_mocked_data("gz-get-incident-by-id-xdr", command_response)


@pytest.mark.parametrize(
    "incident_id, note",
    [
        ("INCIDENT_ID_1", "This is a test note from unit test."),
    ],
)
@patch("GravityZone.demisto")
def test_gz_add_incident_note_command(mock_demisto, requests_mock, incident_id, note):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-add-incident-note command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_add_incident_note_command

    mock_demisto.command.return_value = "gz-add-incident-note"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-add-incident-note")
    client = get_client()

    # Execute command
    command_response = gz_add_incident_note_command(
        client=client,
        args={
            "id": incident_id,
            "note": note,
        },
    )

    # Assert command response
    assert_command_mocked_data("gz-add-incident-note", command_response)


@pytest.mark.parametrize(
    "incident_id, status_param, api_mock_name",
    [
        ("INCIDENT_ID_1", "PENDING", "gz-change-incident-status-pending"),
        ("INCIDENT_ID_1", "ACTIVE", "gz-change-incident-status-active"),
        ("INCIDENT_ID_1", "DONE", "gz-change-incident-status-done"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_change_incident_status_command(mock_demisto, requests_mock, incident_id, status_param, api_mock_name):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-change-incident-status command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_change_incident_status_command

    mock_demisto.command.return_value = "gz-change-incident-status"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, api_mock_name)
    client = get_client()

    # Execute command
    command_response = gz_change_incident_status_command(
        client=client,
        args={
            "id": incident_id,
            "status": status_param,
        },
    )

    # Assert command response
    assert_command_mocked_data(api_mock_name, command_response)


@pytest.mark.parametrize(
    "incident_id, status_param, note",
    [
        ("INCIDENT_ID_1", 0, "incident pending"),
        ("INCIDENT_ID_1", 1, "incident active"),
        ("INCIDENT_ID_1", 2, "incident done"),
    ],
)
@patch("GravityZone.demisto")
def test_update_remote_system_command(mock_demisto, requests_mock, incident_id, status_param, note):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling update-remote-system command
    Then
            Make sure the the return value is as expected.
    """

    # Prepare
    from GravityZone import update_remote_system_command

    mock_demisto.command.return_value = "update-remote-system"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "update-remote-system")
    client = get_client()

    # Execute command
    command_response = update_remote_system_command(
        client=client,
        args={
            "remoteId": incident_id,
            "data": {},
            "entries": [],
            "status": status_param,
            "incidentChanged": True,
            "delta": {"closeNotes": note},
        },
    )

    # Assert command response
    assert command_response == incident_id


@pytest.mark.parametrize(
    "endpoint_id, mock_data_suffix",
    [("6942a43afe8d4e463ca5c197", ""), ("ENDPOINT_ID", "-failed")],
)
@patch("GravityZone.demisto")
def test_gz_download_file_from_endpoint_command(mock_demisto, mocker, requests_mock, endpoint_id, mock_data_suffix):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-download-file-from-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_download_file_from_endpoint_command,
        gz_poll_investigation_activity_status_command,
    )

    mock_demisto.command.return_value = "gz-download-file-from-endpoint"
    mock_demisto.params.return_value = {}
    mocker.patch(
        "GravityZone.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 3,
            "File": "downloaded_file.txt",
            "FileID": "abc",
        },
    )
    load_api_mocked_data(requests_mock, f"gz-download-file-from-endpoint{mock_data_suffix}")
    client = get_client()

    # Execute command
    command_response = gz_download_file_from_endpoint_command(
        client=client,
        args={
            "id": endpoint_id,
            "remote_file": "/home/ENDPOINT_NAME/test.txt",
            "output_file": "downloaded_file.txt",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        f"gz-download-file-from-endpoint{mock_data_suffix}",
        command_response,
        polling_func=gz_poll_investigation_activity_status_command,
        client=client,
    )


@pytest.mark.parametrize(
    "endpoint_id",
    [("6942a43afe8d4e463ca5c197")],
)
@patch("GravityZone.demisto")
def test_gz_download_investigation_package_from_endpoint_command(mock_demisto, mocker, requests_mock, endpoint_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-download-investigation-package-from-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_download_investigation_package_from_endpoint_command,
        gz_poll_investigation_activity_status_command,
    )

    mock_demisto.command.return_value = "gz-download-investigation-package-from-endpoint"
    mock_demisto.params.return_value = {}
    mocker.patch(
        "GravityZone.fileResult",
        return_value={
            "Contents": "",
            "ContentsFormat": "text",
            "Type": 3,
            "File": "investigation_package.zip",
            "FileID": "abc",
        },
    )
    load_api_mocked_data(requests_mock, "gz-download-investigation-package-from-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_download_investigation_package_from_endpoint_command(
        client=client,
        args={"id": endpoint_id, "output_file": "investigation_package.zip"},
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-download-investigation-package-from-endpoint",
        command_response,
        polling_func=gz_poll_investigation_activity_status_command,
        client=client,
    )


@pytest.mark.parametrize(
    "endpoint_id",
    [("6942a43afe8d4e463ca5c197")],
)
@patch("GravityZone.demisto")
def test_gz_upload_file_to_endpoint_command(mock_demisto, requests_mock, endpoint_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-upload-file-to-endpoint command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_upload_file_to_endpoint_command,
        gz_poll_task_status_command,
    )

    mock_demisto.command.return_value = "gz-upload-file-to-endpoint"
    mock_demisto.getFilePath.return_value = {
        "id": "abc",
        "path": os.path.join(os.path.dirname(__file__), "test_data", "file_to_upload.txt"),
        "name": "file_to_upload.txt",
    }
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-upload-file-to-endpoint")
    client = get_client()

    # Execute command
    command_response = gz_upload_file_to_endpoint_command(
        client=client,
        args={"id": endpoint_id, "remote_location": "/home/ENDPOINT_NAME/", "entry_id": "abc"},
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-upload-file-to-endpoint", command_response, polling_func=gz_poll_task_status_command, client=client
    )

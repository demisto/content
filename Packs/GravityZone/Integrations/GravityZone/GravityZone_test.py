import json
import os
from typing import cast
from unittest.mock import patch
from freezegun import freeze_time
import pytest

from CommonServerPython import CommandResults


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
    assert incident_names == ["GravityZone Incident #477", "GravityZone Incident #475"]
    assert mock_demisto.setLastRun.call_count == 1


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
    result = get_modified_remote_data_command(client, {"lastUpdate": "2026-01-01T00:00:00Z"})
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
def test_gz_endpoint_list_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-list command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_endpoint_list_command

    mock_demisto.command.return_value = "gz-endpoint-list"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-list")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_list_command(client=client, args={})

    # Assert command response
    assert_command_mocked_data("gz-endpoint-list", command_response)


@patch("GravityZone.demisto")
def test_gz_endpoint_get_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-get command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """
    # Prepare
    from GravityZone import gz_endpoint_get_command

    mock_demisto.command.return_value = "gz-endpoint-get"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-get")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_get_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("gz-endpoint-get", command_response)


@patch("GravityZone.demisto")
def test_gz_endpoint_users_loggedin_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-users-loggedin command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_endpoint_users_loggedin_command, gz_poll_endpoint_users_loggedin_status_command

    mock_demisto.command.return_value = "gz-endpoint-users-loggedin"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-users-loggedin")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_users_loggedin_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-users-loggedin",
        command_response,
        polling_func=gz_poll_endpoint_users_loggedin_status_command,
        client=client,
    )


@patch("GravityZone.demisto")
def test_gz_endpoint_create_memory_dump_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-create-memory-dump command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_endpoint_create_memory_dump_command, gz_endpoint_memory_dump_status_command

    mock_demisto.command.return_value = "gz-endpoint-create-memory-dump"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-create-memory-dump")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_create_memory_dump_command(
        client=client,
        args={"id": "ENDPOINT_ID", "path": "C:\\dumps\\", "password": "ComplexPass123!"},
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-create-memory-dump",
        command_response,
        polling_func=lambda poll_args, poll_client: gz_endpoint_memory_dump_status_command(poll_client, poll_args),
        client=client,
    )


@patch("GravityZone.demisto")
def test_gz_endpoint_create_memory_dump_command_no_polling(mock_demisto, requests_mock):
    from GravityZone import gz_endpoint_create_memory_dump_command
    from CommonServerPython import CommandResults

    mock_demisto.command.return_value = "gz-endpoint-create-memory-dump"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-create-memory-dump")
    client = get_client()

    command_response = cast(
        CommandResults,
        gz_endpoint_create_memory_dump_command(
            client=client,
            args={"id": "ENDPOINT_ID", "path": "C:\\dumps\\", "password": "ComplexPass123!", "polling": "false"},
        ),
    )

    assert getattr(command_response, "scheduled_command", None) is None
    context = command_response.to_context()
    output = context["EntryContext"]["GravityZone.MemoryDump(val.EndpointID && val.EndpointID == obj.EndpointID)"]

    assert output["TaskID"] == "TASK_ID"
    assert output["TaskType"] == "CreateMemoryDump"
    assert output["Status"] == "Pending"
    assert output["EndpointID"] == "ENDPOINT_ID"
    assert output["EndDate"] == ""
    assert output["ErrorCode"] == ""
    assert output["Error"] == ""
    assert output["DownloadURL"] == ""


@patch("GravityZone.check_endpoint_memory_dump_status")
def test_gz_endpoint_memory_dump_status_command_defaults_polling_true(mock_check_status):
    from GravityZone import gz_endpoint_memory_dump_status_command
    from GravityZone import Client

    client = cast(Client, object())

    gz_endpoint_memory_dump_status_command(client, {"task_id": "TASK_ID", "endpoint_id": "ENDPOINT_ID"})

    mock_check_status.assert_called_once_with(
        {"task_id": "TASK_ID", "endpoint_id": "ENDPOINT_ID", "polling": True},
        client,
    )


@patch("GravityZone.demisto")
def test_gz_endpoint_memory_dump_status_command(mock_demisto, requests_mock):
    from GravityZone import gz_endpoint_memory_dump_status_command

    mock_demisto.command.return_value = "gz-endpoint-memory-dump-status"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-memory-dump-status")
    client = get_client()

    command_response = gz_endpoint_memory_dump_status_command(
        client,
        {"task_id": "TASK_ID", "endpoint_id": "ENDPOINT_ID"},
    )

    assert_command_mocked_data(
        "gz-endpoint-memory-dump-status",
        command_response,
        polling_func=lambda poll_args, poll_client: gz_endpoint_memory_dump_status_command(poll_client, poll_args),
        client=client,
    )


def test_check_endpoint_users_loggedin_status_returns_error_on_unexpected_task_type():
    from GravityZone import check_endpoint_users_loggedin_status

    class MockClient:
        def get_task_status(self, _task_id):
            return {"status": 3, "type": 27, "subtasks": []}

    result = check_endpoint_users_loggedin_status(
        {"task_id": "TASK_ID", "endpoint_id": "ENDPOINT_ID"},
        MockClient(),
    )

    assert isinstance(result, CommandResults)
    assert result.readable_output is not None
    assert "unexpected type" in result.readable_output
    assert "GetActiveSessions" in result.readable_output


def test_check_endpoint_memory_dump_status_returns_error_on_unexpected_task_type():
    from GravityZone import check_endpoint_memory_dump_status

    class MockClient:
        def get_task_status(self, _task_id):
            return {"status": 3, "type": 26, "subtasks": []}

    result = check_endpoint_memory_dump_status(
        {"task_id": "TASK_ID", "endpoint_id": "ENDPOINT_ID"},
        MockClient(),
    )

    assert isinstance(result, CommandResults)
    assert result.readable_output is not None
    assert "unexpected type" in result.readable_output
    assert "CreateMemoryDump" in result.readable_output


def test_extract_active_sessions_from_task_handles_missing_optional_fields():
    from GravityZone import _extract_active_sessions_from_task

    task_output = {
        "status": 3,
        "subtasks": [
            {
                "endpointId": "endpoint-1",
                "endpointName": "host-1",
                "status": 3,
                "result": [
                    {
                        "connection": {
                            "started": "2021-05-19T10:37:56Z",
                            "type": "local",
                        },
                        "user": {
                            "displayName": "user@example.com",
                        },
                    }
                ],
            }
        ],
    }

    sessions = _extract_active_sessions_from_task(task_output)

    assert len(sessions) == 1
    assert sessions[0]["Username"] == "user@example.com"
    assert sessions[0]["ConnectionType"] == "local"
    assert sessions[0]["StartTime"] == "2021-05-19T10:37:56Z"
    assert "UserSID" not in sessions[0]
    assert "DomainSID" not in sessions[0]
    assert "OrganizationalUnitDN" not in sessions[0]
    assert "MemberOfSIDs" not in sessions[0]


def test_extract_endpoint_summary_from_task_returns_hostname_for_matching_endpoint_id():
    from GravityZone import _extract_endpoint_summary_from_task

    task_output = {
        "subtasks": [
            {
                "endpointId": "endpoint-2",
                "endpointName": "host-2",
            },
            {
                "endpointId": "endpoint-1",
                "endpointName": "host-1-updated",
            },
        ]
    }

    endpoint_id, hostname = _extract_endpoint_summary_from_task(task_output, "endpoint-1")

    assert endpoint_id == "endpoint-1"
    assert hostname == "host-1-updated"


def test_build_users_loggedin_results_outputs_endpoint_scoped_context():
    from GravityZone import _build_users_loggedin_results

    task_output = {
        "status": 3,
        "subtasks": [
            {
                "endpointId": "endpoint-1",
                "endpointName": "host-1-updated",
                "status": 3,
                "result": [],
            }
        ],
    }

    result = _build_users_loggedin_results(task_output, "endpoint-1")

    assert result.outputs_prefix == "GravityZone.Endpoint"
    assert result.outputs_key_field == "ID"
    assert result.outputs == {
        "ID": "endpoint-1",
        "Hostname": "host-1-updated",
        "ActiveSessions": [],
    }


def test_extract_memory_dump_summary_uses_matching_endpoint_subtask_and_download_url():
    from GravityZone import _extract_memory_dump_summary

    task_output = {
        "subtasks": [
            {
                "endpointId": "endpoint-other",
                "status": 3,
                "downloadURL": "https://example.com/other",
            },
            {
                "endpointId": "endpoint-1",
                "status": 3,
                "downloadURL": "https://example.com/memory-dump",
            },
        ]
    }

    endpoint_id, endpoint_hostname, subtask, download_url = _extract_memory_dump_summary(task_output, "endpoint-1")
    assert endpoint_id == "endpoint-1"
    assert endpoint_hostname == ""
    assert subtask == {
        "endpointId": "endpoint-1",
        "status": 3,
        "downloadURL": "https://example.com/memory-dump",
    }
    assert download_url == "https://example.com/memory-dump"


def test_extract_memory_dump_summary_ignores_non_processed_subtask_for_download_url():
    from GravityZone import _extract_memory_dump_summary

    task_output = {
        "subtasks": [
            {
                "endpointId": "endpoint-1",
                "status": 2,
                "downloadURL": "https://example.com/should-not-be-used",
            }
        ]
    }

    endpoint_id, endpoint_hostname, subtask, download_url = _extract_memory_dump_summary(task_output, "endpoint-1")
    assert endpoint_id == "endpoint-1"
    assert endpoint_hostname == ""
    assert subtask == {
        "endpointId": "endpoint-1",
        "status": 2,
        "downloadURL": "https://example.com/should-not-be-used",
    }
    assert download_url == ""


def test_extract_memory_dump_task_id_from_string_result():
    from GravityZone import _extract_memory_dump_task_id

    assert _extract_memory_dump_task_id("TASK_ID") == "TASK_ID"


def test_extract_memory_dump_task_id_raises_on_invalid_result():
    from GravityZone import _extract_memory_dump_task_id

    with pytest.raises(Exception, match="createMemoryDumpTask response is missing task ID"):
        _extract_memory_dump_task_id({})


def test_build_memory_dump_results_outputs_download_url_on_success():
    from GravityZone import _build_memory_dump_results

    task_output = {
        "status": 3,
        "subtasks": [
            {
                "endpointId": "endpoint-1",
                "endpointName": "host-1",
                "status": 3,
                "startDate": "2026-05-25T10:00:00",
                "endDate": "2026-05-25T10:01:00",
                "errorCode": "Success",
                "errorMessage": "Success",
                "downloadURL": "https://example.com/memory-dump",
            }
        ],
    }

    result = _build_memory_dump_results(task_output, "TASK_ID", "endpoint-1")

    assert result.outputs_prefix == "GravityZone.MemoryDump"
    assert result.outputs_key_field == "EndpointID"
    assert result.outputs == {
        "TaskID": "TASK_ID",
        "TaskType": "CreateMemoryDump",
        "Status": "Processed",
        "EndpointID": "endpoint-1",
        "Hostname": "host-1",
        "StartDate": "2026-05-25T10:00:00Z",
        "EndDate": "2026-05-25T10:01:00Z",
        "ErrorCode": "Success",
        "Error": "Success",
        "DownloadURL": "https://example.com/memory-dump",
    }


def test_build_memory_dump_results_omits_download_url_when_unavailable():
    from GravityZone import _build_memory_dump_results

    task_output = {
        "status": 1,
        "subtasks": [
            {
                "endpointId": "endpoint-1",
                "endpointName": "host-1",
                "status": 1,
                "startDate": "2026-05-25T10:00:00",
            }
        ],
    }

    result = _build_memory_dump_results(task_output, "TASK_ID", "endpoint-1")

    assert result.outputs == {
        "TaskID": "TASK_ID",
        "TaskType": "CreateMemoryDump",
        "Status": "Pending",
        "EndpointID": "endpoint-1",
        "Hostname": "host-1",
        "StartDate": "2026-05-25T10:00:00Z",
        "EndDate": "",
        "ErrorCode": "",
        "Error": "",
        "DownloadURL": "",
    }


def test_generate_processed_task_command_result_maps_memory_dump_task_type():
    from GravityZone import generate_processed_task_command_result

    task_output = {
        "type": 27,
        "subtasks": [
            {
                "endpointId": "endpoint-1",
                "endpointName": "host-1",
                "startDate": "2026-05-26T10:00:00",
                "endDate": "2026-05-26T10:01:00",
            }
        ],
    }

    result = generate_processed_task_command_result("parent-task-id", task_output, {})

    assert result.outputs_prefix == "GravityZone.Command.CreateMemoryDump"


@patch("GravityZone.demisto")
def test_gz_endpoint_isolate_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-isolate command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_endpoint_isolate_command, gz_poll_task_status_command

    mock_demisto.command.return_value = "gz-endpoint-isolate"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-isolate")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_isolate_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("gz-endpoint-isolate", command_response, polling_func=gz_poll_task_status_command, client=client)


@patch("GravityZone.demisto")
def test_gz_endpoint_deisolate_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-deisolate command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_endpoint_deisolate_command, gz_poll_task_status_command

    mock_demisto.command.return_value = "gz-endpoint-deisolate"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-deisolate")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_deisolate_command(client=client, args={"id": "ENDPOINT_ID"})

    # Assert command response
    assert_command_mocked_data("gz-endpoint-deisolate", command_response, polling_func=gz_poll_task_status_command, client=client)


@patch("GravityZone.demisto")
def test_gz_endpoint_kill_process_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-kill-process command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_kill_process_command,
        gz_poll_task_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-kill-process"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-kill-process")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_kill_process_command(
        client=client,
        args={
            "id": "ENDPOINT_ID",
            "pid": "5876",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-kill-process", command_response, polling_func=gz_poll_task_status_command, client=client
    )


@patch("GravityZone.demisto")
def test_gz_endpoint_run_command_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-run-command command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_run_command_command,
        gz_poll_investigation_activity_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-run-command"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-run-command")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_run_command_command(
        client=client,
        args={
            "id": "6942a43afe8d4e463ca5c197",
            "command": "ls -1",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-run-command", command_response, polling_func=gz_poll_investigation_activity_status_command, client=client
    )


@patch("GravityZone.demisto")
def test_gz_endpoint_get_process_tree_by_hash(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-get-process-tree-by-hash command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_get_process_tree_by_hash_command,
        gz_poll_live_search_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-get-process-tree-by-hash"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-get-process-tree-by-hash")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_get_process_tree_by_hash_command(
        client=client,
        args={
            "id": "ENDPOINT_ID",
            "process_hash": "PROCESS_HASH",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-get-process-tree-by-hash",
        command_response,
        polling_func=gz_poll_live_search_status_command,
        client=client,
    )


@patch("GravityZone.demisto")
def test_gz_endpoint_list_by_running_process_hash_command(mock_demisto, requests_mock):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-list-by-running-process-hash command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_list_by_running_process_hash_command,
        gz_poll_live_search_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-list-by-running-process-hash"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-list-by-running-process-hash")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_list_by_running_process_hash_command(
        client=client,
        args={
            "process_hash": "PROCESS_HASH",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-list-by-running-process-hash",
        command_response,
        polling_func=gz_poll_live_search_status_command,
        client=client,
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
        ({}, "gz-incident-list"),
        ({"endpoint_id": "ENDPOINT_ID"}, "gz-incident-list-2"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_incident_list_command(mock_demisto, requests_mock, args, api_mock_name):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-incident-list command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_incident_list_command

    mock_demisto.command.return_value = "gz-incident-list"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, api_mock_name)
    client = get_client()

    # Execute command
    command_response = gz_incident_list_command(client=client, args=args)

    # Assert command response
    assert_command_mocked_data(api_mock_name, command_response)


@pytest.mark.parametrize(
    "incident_id",
    [
        ("INCIDENT_ID_1"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_incident_get_edr_command(mock_demisto, requests_mock, incident_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-incident-get command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_incident_get_command

    mock_demisto.command.return_value = "gz-incident-get"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-incident-get-edr")
    client = get_client()

    # Execute command
    command_response = gz_incident_get_command(client=client, args={"id": incident_id})

    # Assert command response
    assert_command_mocked_data("gz-incident-get-edr", command_response)


@pytest.mark.parametrize(
    "incident_id",
    [
        ("INCIDENT_ID_1"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_incident_get_xdr_command(mock_demisto, requests_mock, incident_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-incident-get command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_incident_get_command

    mock_demisto.command.return_value = "gz-incident-get"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-incident-get-xdr")
    client = get_client()

    # Execute command
    command_response = gz_incident_get_command(client=client, args={"id": incident_id})

    # Assert command response
    assert_command_mocked_data("gz-incident-get-xdr", command_response)


@pytest.mark.parametrize(
    "incident_id, note",
    [
        ("INCIDENT_ID_1", "This is a test note from unit test."),
    ],
)
@patch("GravityZone.demisto")
def test_gz_incident_add_note_command(mock_demisto, requests_mock, incident_id, note):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-incident-add-note command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_incident_add_note_command

    mock_demisto.command.return_value = "gz-incident-add-note"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-incident-add-note")
    client = get_client()

    # Execute command
    command_response = gz_incident_add_note_command(
        client=client,
        args={
            "id": incident_id,
            "note": note,
        },
    )

    # Assert command response
    assert_command_mocked_data("gz-incident-add-note", command_response)


@pytest.mark.parametrize(
    "incident_id, status_param, api_mock_name",
    [
        ("INCIDENT_ID_1", "PENDING", "gz-incident-change-status-pending"),
        ("INCIDENT_ID_1", "ACTIVE", "gz-incident-change-status-active"),
        ("INCIDENT_ID_1", "DONE", "gz-incident-change-status-done"),
    ],
)
@patch("GravityZone.demisto")
def test_gz_incident_change_status_command(mock_demisto, requests_mock, incident_id, status_param, api_mock_name):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-incident-change-status command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import gz_incident_change_status_command

    mock_demisto.command.return_value = "gz-incident-change-status"
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, api_mock_name)
    client = get_client()

    # Execute command
    command_response = gz_incident_change_status_command(
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
    assert requests_mock.called


@pytest.mark.parametrize(
    "endpoint_id, mock_data_suffix",
    [("6942a43afe8d4e463ca5c197", ""), ("ENDPOINT_ID", "-failed")],
)
@patch("GravityZone.demisto")
def test_gz_endpoint_download_file_command(mock_demisto, mocker, requests_mock, endpoint_id, mock_data_suffix):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-download-file command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_download_file_command,
        gz_poll_investigation_activity_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-download-file"
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
    load_api_mocked_data(requests_mock, f"gz-endpoint-download-file{mock_data_suffix}")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_download_file_command(
        client=client,
        args={
            "id": endpoint_id,
            "remote_file": "/home/ENDPOINT_NAME/test.txt",
            "output_file": "downloaded_file.txt",
        },
    )

    # Assert command response
    assert_command_mocked_data(
        f"gz-endpoint-download-file{mock_data_suffix}",
        command_response,
        polling_func=gz_poll_investigation_activity_status_command,
        client=client,
    )


@pytest.mark.parametrize(
    "endpoint_id",
    [("6942a43afe8d4e463ca5c197")],
)
@patch("GravityZone.demisto")
def test_gz_endpoint_download_investigation_package_command(mock_demisto, mocker, requests_mock, endpoint_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-download-investigation-package command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_download_investigation_package_command,
        gz_poll_investigation_activity_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-download-investigation-package"
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
    load_api_mocked_data(requests_mock, "gz-endpoint-download-investigation-package")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_download_investigation_package_command(
        client=client,
        args={"id": endpoint_id, "output_file": "investigation_package.zip"},
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-download-investigation-package",
        command_response,
        polling_func=gz_poll_investigation_activity_status_command,
        client=client,
    )


@pytest.mark.parametrize(
    "endpoint_id",
    [("6942a43afe8d4e463ca5c197")],
)
@patch("GravityZone.demisto")
@patch("GravityZone.FileManagement.get_file")
def test_gz_endpoint_upload_file_command(mock_get_file, mock_demisto, requests_mock, endpoint_id):
    """
    Given
            All relevant arguments for the command that is executed
    When
            Calling gz-endpoint-upload-file command
    Then
            Make sure the outputs, outputs_prefix and outputs_key_field values are as expected.
    """

    # Prepare
    from GravityZone import (
        gz_endpoint_upload_file_command,
        gz_poll_task_status_command,
    )

    mock_demisto.command.return_value = "gz-endpoint-upload-file"
    mock_get_file.return_value = ("file_to_upload.txt", b"file_content")
    mock_demisto.params.return_value = {}
    load_api_mocked_data(requests_mock, "gz-endpoint-upload-file")
    client = get_client()

    # Execute command
    command_response = gz_endpoint_upload_file_command(
        client=client,
        args={"id": endpoint_id, "remote_location": "/home/ENDPOINT_NAME/", "entry_id": "abc"},
    )

    # Assert command response
    assert_command_mocked_data(
        "gz-endpoint-upload-file", command_response, polling_func=gz_poll_task_status_command, client=client
    )

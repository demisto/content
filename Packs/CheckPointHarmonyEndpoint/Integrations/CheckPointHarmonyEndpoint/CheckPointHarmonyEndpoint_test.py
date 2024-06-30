import json
import os
import unittest.mock
from typing import Any, Callable

import CommonServerPython
import pytest

import CheckPointHarmonyEndpoint

TEST_DATA = "test_data"
BASE_URL = "https://www.example.com/"
API_URL = CommonServerPython.urljoin(
    BASE_URL, "app/endpoint-web-mgmt/harmony/endpoint/api/v1"
)


def load_mock_response(file_name: str) -> dict[str, Any] | list[dict[str, Any]]:
    """Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        dict[str, Any]: Mock file content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path, mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def mock_client() -> CheckPointHarmonyEndpoint.Client:
    """
    Establish a mock connection to the client with a user name and password.

    Returns:
        Client: Mock connection to client.
    """
    return CheckPointHarmonyEndpoint.Client(
        base_url=API_URL,
        client_id="test",
        client_secret="test",
        verify_certificate=False,
        proxy=False,
    )


@pytest.mark.parametrize(
    "command_args, endpoint, response_file",
    [
        (
            {"job_id": "123"},
            "jobs/123",
            "job_status.json",
        ),
    ],
)
def test_job_status_get_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    command_args: dict[str, Any],
    endpoint: str,
    response_file: str,
):
    """
    Scenario:
    - Test retrieving job status.

    Given:
    - Arguments for retrieving job status.

    When:
    - Executing job_status_get_command function.

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    mock_response = load_mock_response(response_file)
    requests_mock.get(
        url=f"{API_URL}/{endpoint}",
        json=mock_response,
    )

    command_results = CheckPointHarmonyEndpoint.job_status_get_command(
        command_args, mock_client
    )

    assert command_results.raw_response == mock_response
    assert command_results.outputs == mock_response
    assert command_results.outputs_prefix == "HarmonyEP.Job"
    assert command_results.outputs_key_field == "id"


@pytest.mark.parametrize(
    "command_args, endpoint, response_file",
    [
        (
            {
                "filter": "com",
                "sort_field": "iocValue",
                "sort_direction": "ASC",
            },
            "ioc/get",
            "ioc_list.json",
        ),
    ],
)
def test_ioc_list_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    command_args: dict[str, Any],
    endpoint: str,
    response_file: str,
):
    """
    Scenario:
    - Test listing IOCs.

    Given:
    - Arguments for listing IOCs.

    When:
    - Executing ioc_list_command function.

    Then:
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    mock_response = load_mock_response(response_file)
    requests_mock.post(
        url=f"{API_URL}/{endpoint}",
        json=mock_response,
    )

    command_results = CheckPointHarmonyEndpoint.ioc_list_command(
        command_args, mock_client
    )
    mock_response["content"][0]["modifiedOn"] = (
        CheckPointHarmonyEndpoint.convert_unix_to_date_string(
            mock_response["content"][0]["modifiedOn"]
        )
    )

    assert command_results.raw_response == mock_response
    assert command_results.outputs == mock_response["content"]
    assert command_results.outputs_prefix == "HarmonyEP.IOC"
    assert command_results.outputs_key_field == "id"


@pytest.mark.parametrize(
    "command_args, response_file",
    [
        (
            {
                "type": "Domain",
                "value": "tal.com",
                "comment": "Tal Domain Test",
                "ioc_id": "1108",
            },
            "ioc_update.json",
        ),
    ],
)
def test_ioc_update_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    command_args: dict[str, Any],
    response_file: str,
):
    """
    Scenario:
    - Test updating an IOC.

    Given:
    - Arguments for updating an IOC.

    When:
    - Executing ioc_update_command function.

    Then:
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    """
    mock_response = load_mock_response(response_file)
    requests_mock.put(
        url=f"{API_URL}/ioc/edit",
        json=mock_response,
    )

    command_results = CheckPointHarmonyEndpoint.ioc_update_command(
        command_args, mock_client
    )

    assert command_results.raw_response == mock_response
    assert command_results.outputs == mock_response
    assert command_results.outputs_prefix == "HarmonyEP.IOC"
    assert command_results.outputs_key_field == "id"


def test_ioc_create_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
):
    """
    Scenario:
    - Test creating an IOC.

    Given:
    - Arguments for creating an IOC.

    When:
    - Executing ioc_create_command function.

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    requests_mock.post(
        url=f"{API_URL}/ioc/create",
        json="",
    )

    command_results = CheckPointHarmonyEndpoint.ioc_create_command(
        {"type": "Domain", "value": "example.com", "comment": "Suspicious domain"},
        mock_client,
    )

    assert command_results.readable_output == "IOC was created successfully."


@pytest.mark.parametrize(
    "command_args, endpoint, response_file, readable_output",
    [
        (
            {"ids": [1, 2, 3], "delete_all": False},
            "ioc/delete?ids=%5B1,%202,%203%5D",
            "ioc_delete.json",
            "IOCs [1, 2, 3] was deleted successfully.",
        ),
        (
            {"ids": None, "delete_all": True},
            "ioc/delete/all",
            "ioc_delete.json",
            "All IOCs were deleted successfully.",
        ),
    ],
)
def test_ioc_delete_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    command_args: dict[str, Any],
    endpoint: str,
    response_file: str,
    readable_output: str,
):
    """
    Scenario:
    - Test deleting an IOC.

    Given:
    - Arguments for deleting an IOC.

    When:
    - Executing ioc_delete_command function.

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    mock_response = load_mock_response(response_file)
    requests_mock.delete(
        url=f"{API_URL}/{endpoint}",
        json=mock_response,
    )

    command_results = CheckPointHarmonyEndpoint.ioc_delete_command(
        command_args, mock_client
    )

    assert command_results.readable_output == readable_output


def test_rule_assignments_get_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
):
    """
    Scenario:
    - Test getting rule assignments.

    Given:
    - Arguments for getting rule assignments.

    When:
    - Executing rule_assignments_get_command function.

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    mock_response = load_mock_response("rule_assignments.json")
    requests_mock.get(
        url=f"{API_URL}/policy/1/assignments",
        json=mock_response,
    )
    output = {"id": 1, "assignments": mock_response}
    command_results = CheckPointHarmonyEndpoint.rule_assignments_get_command(
        {"rule_id": 1}, mock_client
    )

    assert command_results.outputs_prefix == "HarmonyEP.Rule"
    assert command_results.outputs_key_field == "id"
    assert command_results.raw_response == mock_response
    assert command_results.outputs == output


def test_rule_assignments_add_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
):
    """
    Scenario:
    - Test adding rule assignments.

    Given:
    - Arguments for adding rule assignments.

    When:
    - Executing rule_assignments_add_command function.

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """

    requests_mock.put(
        url=f"{API_URL}/policy/1/assignments/add",
        json="",
    )

    command_results = CheckPointHarmonyEndpoint.rule_assignments_add_command(
        {"rule_id": 1, "entities_ids": ["3", "4"]}, mock_client
    )

    assert (
        command_results.readable_output
        == "Entities ['3', '4'] were assigned to rule 1 successfully."
    )


def test_rule_assignments_remove_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
):
    """
    Scenario:
    - Test removing rule assignments.

    Given:
    - Arguments for removing rule assignments.

    When:
    - Executing rule_assignments_remove_command function.

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """

    requests_mock.put(
        url=f"{API_URL}/policy/1/assignments/remove",
        json="",
    )

    command_results = CheckPointHarmonyEndpoint.rule_assignments_remove_command(
        {"rule_id": 1, "entities_ids": ["3", "4"]}, mock_client
    )

    assert (
        command_results.readable_output
        == "Entities ['3', '4'] were removed from rule 1 successfully."
    )


@pytest.mark.parametrize(
    "command_args, endpoint, response_file",
    [
        (
            {"limit": 2, "all_results": False},
            "policy/metadata",
            "rule_metadata_list.json",
        ),
        (
            {"rule_id": 1, "all_results": True},
            "policy/1/metadata",
            "rule_metadata_get.json",
        ),
    ],
)
def test_rule_metadata_list_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    command_args: dict[str, Any],
    endpoint: str,
    response_file: str,
):
    """
    Scenario:
    - Test the rule_metadata_list_command function.

    Given:
    - Arguments for the command.

    When:
    - Executing the rule_metadata_list_command function.

    Then:
    - Ensure that the CommandResults are as expected.
    """

    mock_response: dict[str, Any] | list[dict[str, Any]] = load_mock_response(
        response_file
    )
    requests_mock.get(
        url=f"{API_URL}/{endpoint}",
        json=mock_response,
    )
    command_results = CheckPointHarmonyEndpoint.rule_metadata_list_command(
        command_args, mock_client
    )
    mock_response = (
        mock_response[: command_args["limit"]]
        if "limit" in command_args
        else mock_response
    )

    assert command_results.raw_response == mock_response
    assert command_results.outputs == mock_response
    assert command_results.outputs_prefix == "HarmonyEP.Rule"
    assert command_results.outputs_key_field == "id"


@pytest.mark.parametrize(
    "args,command_name,integration_context,response_file,expected_integration_context,expected_poll_result",
    [
        # Mock success first run
        (
            {"job_id": "3"},
            "harmony-ep-push-operation-status-list",
            {},
            "push_operation_status_list.json",
            {"job_id": None, "remediation_operation_id": None},
            CommonServerPython.PollResult(
                response=CommonServerPython.CommandResults(
                    outputs=load_mock_response("push_operation_status_list.json"),
                    outputs_prefix="HarmonyEP.PushOperation",
                    outputs_key_field="job_id",
                    raw_response=load_mock_response("push_operation_status_list.json"),
                ),
                continue_to_poll=False,
                args_for_next_run=None,
            ),
        ),
        # Mock continue to poll
        (
            {"job_id": "3"},
            "harmony-ep-push-operation-status-list",
            {},
            "push_operation_status_in_progress.json",
            None,
            CommonServerPython.PollResult(
                response=CommonServerPython.CommandResults(
                    outputs=load_mock_response(
                        "push_operation_status_in_progress.json"
                    ),
                    outputs_prefix="HarmonyEP.Job",
                    outputs_key_field="id",
                    raw_response=load_mock_response(
                        "push_operation_status_in_progress.json"
                    ),
                ),
                continue_to_poll=True,
                args_for_next_run={"job_id": "3"},
            ),
        ),
        # Mock success second run
        (
            {"job_id": "3"},
            "harmony-ep-push-operation-status-list",
            {"job_id": "3"},
            "push_operation_status_list.json",
            {"job_id": None, "remediation_operation_id": None},
            CommonServerPython.PollResult(
                response=CommonServerPython.CommandResults(
                    outputs=load_mock_response("push_operation_status_list.json"),
                    outputs_prefix="HarmonyEP.PushOperation",
                    outputs_key_field="job_id",
                    raw_response=load_mock_response("push_operation_status_list.json"),
                ),
                continue_to_poll=False,
                args_for_next_run=None,
            ),
        ),
        # Mock success first run with push operation data
        (
            {"job_id": "3"},
            "harmony-ep-anti-malware-scan",
            {"job_id": "3", "remediation_operation_id": None},
            "push_operation_remediation_data.json",
            {"job_id": "new1", "remediation_operation_id": "222"},
            CommonServerPython.PollResult(
                response=CommonServerPython.CommandResults(
                    outputs=load_mock_response("push_operation_remediation_data.json"),
                    outputs_prefix="HarmonyEP.Job",
                    outputs_key_field="id",
                    raw_response=load_mock_response(
                        "push_operation_remediation_data.json"
                    ),
                ),
                continue_to_poll=True,
                args_for_next_run={"job_id": "3"},
            ),
        ),
        # Mock success second run with push operation data
        (
            {"job_id": "3"},
            "harmony-ep-anti-malware-scan",
            {"job_id": "3", "remediation_operation_id": "222"},
            "job_status.json",
            {"job_id": None, "remediation_operation_id": None},
            CommonServerPython.PollResult(
                response=CommonServerPython.CommandResults(
                    outputs=load_mock_response("job_status.json"),
                    outputs_prefix="HarmonyEP.AntiMalwareScan.PushOperation",
                    outputs_key_field="job_id",
                    raw_response=load_mock_response("job_status.json"),
                ),
                continue_to_poll=False,
                args_for_next_run=None,
            ),
        ),
    ],
)
def test_schedule_command(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    args: dict[str, Any],
    command_name: str,
    integration_context: dict[str, Any],
    response_file: str,
    expected_integration_context: dict[str, Any],
    expected_poll_result: CommonServerPython.PollResult,
):
    """Test the schedule_command function.

    Args:
        requests_mock (pytest_mock.plugin.MockerFixture): Mocked requests.
        mock_client (HarmonyEndpoint.Client): Mocked client.
        args (dict[str, Any]): The arguments to pass to the function.
        integration_context (dict[str, Any]): The integration context to patch.
        response_file (str): The file names for the mocked responses.
        expected_integration_context (dict[str, Any]): The expected integration context.
        expected_poll_result (CommonServerPython.PollResult): The expected poll result.
    """
    requests_mock.get(
        f"{API_URL}/jobs/3",
        json=load_mock_response(response_file),
    )

    if command_name == "harmony-ep-anti-malware-scan":
        requests_mock.post(
            f"{API_URL}/remediation/222/results/slim",
            json={"jobId": "new1"},
        )

    with (
        unittest.mock.patch(
            "CheckPointHarmonyEndpoint.get_integration_context",
            return_value=integration_context,
        ),
        unittest.mock.patch(
            "CheckPointHarmonyEndpoint.set_integration_context"
        ) as mock_set_integration_context,
    ):
        poll_result: CommonServerPython.PollResult = (
            CheckPointHarmonyEndpoint.schedule_command(
                client=mock_client,
                args=args,
                command_name=command_name,
            )
        )

        if expected_integration_context:
            mock_set_integration_context.assert_called_once_with(
                expected_integration_context
            )

    assert poll_result.continue_to_poll == expected_poll_result.continue_to_poll
    assert poll_result.args_for_next_run == expected_poll_result.args_for_next_run
    assert (
        poll_result.response.outputs_prefix
        == expected_poll_result.response.outputs_prefix
    )
    assert (
        poll_result.response.outputs_key_field
        == expected_poll_result.response.outputs_key_field
    )


@pytest.mark.parametrize(
    "command_name,request_method,request_function,command_args,endpoint",
    [
        (
            "harmony-ep-policy-rule-install",
            "POST",
            CheckPointHarmonyEndpoint.rule_policy_install_command,
            {"job_id": None},
            "policy/install",
        ),
        (
            "harmony-ep-policy-rule-modifications-get",
            "GET",
            CheckPointHarmonyEndpoint.rule_modifications_get_command,
            {"rule_id": "1994", "job_id": None},
            "policy/1994/modifications",
        ),
        (
            "harmony-ep-push-operation-status-list",
            "GET",
            CheckPointHarmonyEndpoint.push_operation_status_list_command,
            {"remediation_operation_id": "11081994", "job_id": None},
            "remediation/11081994/status",
        ),
        (
            "harmony-ep-push-operation-status-list",
            "GET",
            CheckPointHarmonyEndpoint.push_operation_status_list_command,
            {"all_results": True, "remediation_operation_id": None, "job_id": None},
            "remediation/status",
        ),
        (
            "harmony-ep-push-operation-get",
            "POST",
            CheckPointHarmonyEndpoint.push_operation_get_command,
            {
                "remediation_operation_id": "11081994",
                "filter_text": None,
                "job_id": None,
            },
            "remediation/11081994/results/slim",
        ),
        (
            "harmony-ep-push-operation-abort",
            "POST",
            CheckPointHarmonyEndpoint.push_operation_abort_command,
            {"remediation_operation_id": "11081994", "job_id": None},
            "remediation/11081994/abort",
        ),
        (
            "harmony-ep-anti-malware-scan",
            "POST",
            CheckPointHarmonyEndpoint.anti_malware_scan_command,
            {
                "comment": "test",
                "computer_ids": ["3"],
                "groups_ids_to_exclude": ["a"],
                "computers_ids_to_include": ["1"],
                "computers_ids_to_exclude": ["2"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/anti-malware/scan",
        ),
        (
            "harmony-ep-anti-malware-update",
            "POST",
            CheckPointHarmonyEndpoint.anti_malware_update_command,
            {
                "comment": "test",
                "computer_ids": ["3"],
                "groups_ids_to_exclude": ["a"],
                "computers_ids_to_include": ["1"],
                "computers_ids_to_exclude": ["2"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/anti-malware/update",
        ),
        (
            "harmony-ep-anti-malware-restore",
            "POST",
            CheckPointHarmonyEndpoint.anti_malware_restore_command,
            {
                "comment": "test",
                "computer_ids": ["3"],
                "groups_ids_to_exclude": ["a"],
                "computers_ids_to_include": ["1"],
                "computers_ids_to_exclude": ["2"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/anti-malware/restore",
        ),
        (
            "harmony-ep-forensics-indicator-analyze",
            "POST",
            CheckPointHarmonyEndpoint.indicator_analyze_command,
            {
                "indicator_type": "IP",
                "indicator_value": "1.1.1.1",
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/forensics/analyze-by-indicator/ip",
        ),
        (
            "harmony-ep-forensics-file-quarantine",
            "POST",
            CheckPointHarmonyEndpoint.file_quarantine_command,
            {
                "file_type": "PATH",
                "file_value": "file_name",
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/forensics/file/quarantine",
        ),
        (
            "harmony-ep-forensics-file-restore",
            "POST",
            CheckPointHarmonyEndpoint.file_restore_command,
            {
                "file_type": "PATH",
                "file_value": "file_name",
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/forensics/file/restore",
        ),
        (
            "harmony-ep-remediation-computer-isolate",
            "POST",
            CheckPointHarmonyEndpoint.remediation_computer_isolate_command,
            {
                "file_type": "PATH",
                "file_value": "file_name",
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/isolate",
        ),
        (
            "harmony-ep-remediation-computer-deisolate",
            "POST",
            CheckPointHarmonyEndpoint.remediation_computer_deisolate_command,
            {
                "file_type": "PATH",
                "file_value": "file_name",
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/de-isolate",
        ),
        (
            "harmony-ep-agent-computer-restart",
            "POST",
            CheckPointHarmonyEndpoint.computer_restart_command,
            {
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "force_apps_shutdown": False,
                "job_id": None,
            },
            "remediation/agent/reset-computer",
        ),
        (
            "harmony-ep-agent-computer-repair",
            "POST",
            CheckPointHarmonyEndpoint.computer_repair_command,
            {
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/repair-computer",
        ),
        (
            "harmony-ep-agent-computer-shutdown",
            "POST",
            CheckPointHarmonyEndpoint.computer_shutdown_command,
            {
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "force_apps_shutdown": False,
                "job_id": None,
            },
            "remediation/agent/shutdown-computer",
        ),
        (
            "harmony-ep-computer-list",
            "POST",
            CheckPointHarmonyEndpoint.computer_list_command,
            {
                "computer_ids": ["3"],
                "job_id": None,
            },
            "asset-management/computers/filtered",
        ),
        (
            "harmony-ep-agent-process-information-get",
            "POST",
            CheckPointHarmonyEndpoint.process_information_get_command,
            {
                "computer_ids": ["3"],
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/process/information",
        ),
        (
            "harmony-ep-agent-process-terminate",
            "POST",
            CheckPointHarmonyEndpoint.process_terminate_command,
            {
                "computer_ids": ["3"],
                "name": "test",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/process/terminate",
        ),
        (
            "harmony-ep-agent-registry-key-add",
            "POST",
            CheckPointHarmonyEndpoint.agent_registry_key_add_command,
            {
                "computer_ids": ["3"],
                "hive": "hive",
                "key": "key",
                "value_name": "value_name",
                "value_type": "STRING (REG_GZ)",
                "value_data": "value_data",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/registry/key/add",
        ),
        (
            "harmony-ep-agent-registry-key-delete",
            "POST",
            CheckPointHarmonyEndpoint.agent_registry_key_delete_command,
            {
                "computer_ids": ["3"],
                "hive": "hive",
                "key": "key",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/registry/key/delete",
        ),
        (
            "harmony-ep-agent-file-copy",
            "POST",
            CheckPointHarmonyEndpoint.agent_file_copy_command,
            {
                "computer_ids": ["3"],
                "destination_absolute_path": "destination_absolute_path",
                "source_absolute_path": "source_absolute_path",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/file/copy",
        ),
        (
            "harmony-ep-agent-file-move",
            "POST",
            CheckPointHarmonyEndpoint.agent_file_move_command,
            {
                "computer_ids": ["3"],
                "destination_absolute_path": "destination_absolute_path",
                "source_absolute_path": "source_absolute_path",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/file/move",
        ),
        (
            "harmony-ep-agent-file-delete",
            "POST",
            CheckPointHarmonyEndpoint.agent_file_delete_command,
            {
                "computer_ids": ["3"],
                "target_absolute_path": "target_absolute_path",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/file/delete",
        ),
        (
            "harmony-ep-agent-vpn-site-add",
            "POST",
            CheckPointHarmonyEndpoint.agent_vpn_site_add_command,
            {
                "computer_ids": ["3"],
                "remote_access_gateway_name": "remote_access_gateway_name",
                "fingerprint": "fingerprint",
                "host": "host",
                "authentication_method": "authentication_method",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/vpn/site/add",
        ),
        (
            "harmony-ep-agent-vpn-site-remove",
            "POST",
            CheckPointHarmonyEndpoint.agent_vpn_site_remove_command,
            {
                "computer_ids": ["3"],
                "display_name": "display_name",
                "inform_user": True,
                "allow_postpone": True,
                "job_id": None,
            },
            "remediation/agent/vpn/site/remove",
        ),
    ],
)
def test_all_schedule_commands(
    requests_mock,
    mock_client: CheckPointHarmonyEndpoint.Client,
    command_name: str,
    request_method: str,
    request_function: Callable,
    command_args: dict[str, Any],
    endpoint: str,
):
    """
    Scenario:
    - Test the process_terminate_command function.

    Given:
    - Arguments for the command.

    When:
    - Executing the process_terminate_command function.

    Then:
    - Ensure that the schedule_command is called with the appropriate arguments.
    """
    requests_mock.request(
        request_method,
        f"{API_URL}/{endpoint}",
        json={"jobId": "tg1108"},
    )

    with (
        unittest.mock.patch(
            "CheckPointHarmonyEndpoint.schedule_command"
        ) as mock_schedule_command,
        unittest.mock.patch("demistomock.command", return_value=command_name),
    ):
        request_function(command_args, mock_client)
        mock_schedule_command.assert_called_once_with(
            command_args, mock_client, command_name
        )


# test helper commands


@pytest.mark.parametrize(
    "page_size, page, limit", [(-1, 0, 10), (5, -1, 5), (5, 5, -1)]
)
def test_validate_pagination_arguments(page_size, page, limit):
    """
    Given:
     - invalid values of page_size, page and limit

    When:
     - executing validate_pagination_arguments function

    Then:
     - Ensure that ValueError is raised
    """

    with pytest.raises(ValueError):
        CheckPointHarmonyEndpoint.validate_pagination_arguments(
            page=page, page_size=page_size, limit=limit
        )


@pytest.mark.parametrize(
    "args,expected",
    [
        ({"limit": "10"}, (0, 10, "Showing page 1.\nCurrent page size: 10.")),
        (
            {"page": "2", "page_size": "5"},
            (1, 5, "Showing page 2.\nCurrent page size: 5."),
        ),
        (
            {"page": "3", "page_size": "5", "limit": "15"},
            (2, 5, "Showing page 3.\nCurrent page size: 5."),
        ),
    ],
)
def test_get_pagination_args(args: dict[str, str], expected):
    """Test get_pagination_args function.

    Args:
        args (dict[str, str]): Pagination arguments.
        expected (tuple): Updated pagination arguments and pagination message.
    """
    with unittest.mock.patch(
        "CommonServerPython.arg_to_number",
        side_effect=lambda x: int(x) if x is not None else None,
    ):
        with unittest.mock.patch(
            "CheckPointHarmonyEndpoint.validate_pagination_arguments"
        ) as mock_validate:
            assert CheckPointHarmonyEndpoint.get_pagination_args(args) == expected
            mock_validate.assert_called()


def test_validate_filter_arguments():
    """Test validate_filter_arguments function and ensure that ValueError is raised."""
    with pytest.raises(ValueError) as exc_info:
        CheckPointHarmonyEndpoint.validate_filter_arguments(
            column_name="invalid_name", filter_type="equals"
        )
    assert "'column_name' must be one of the followings" in str(exc_info.value)

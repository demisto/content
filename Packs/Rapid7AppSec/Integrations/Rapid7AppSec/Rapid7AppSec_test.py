import json
import os
from http import HTTPStatus
from typing import Callable
from urllib.parse import urljoin

import pytest
from CommonServerPython import *
from Rapid7AppSec import (ATTACK, DEFAULT_OUTPUT_KEY_FIELD,
                          INTEGRATION_COMMAND_PREFIX,
                          INTEGRATION_OUTPUT_PREFIX, SCAN, SCAN_ACTION,
                          VULNERABILITY, VULNERABILITY_COMMENT, Client,
                          OutputPrefix, ReadableOutputs, RequestAction,
                          UrlPrefix, generate_readable_output_message)

EXAMPLE_ID = "497f6eca-6276-4993-bfeb-53cbbbba6f08"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """Create a test client for App Sec.

    Returns:
        Client: App Sec Client.
    """
    return Client(
        base_url="https://xx.api.insight.rapid7.com",
        api_key="test",
        proxy=True,
        verify=False,
    )


@pytest.mark.parametrize(
    ("args", "command", "endpoint", "request_action", "excepted_output"),
    (
        (
            {"vulnerability_id": EXAMPLE_ID, "severity": "Safe", "status": "Unreviwed"},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-update",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}",
            RequestAction.PUT,
            generate_readable_output_message(
                object_type=ReadableOutputs.VULNERABILITY.value,
                object_id=EXAMPLE_ID,
                action=ReadableOutputs.UPDATED,
            ),
        ),
        (
            {"vulnerability_id": EXAMPLE_ID, "comment_content": "test"},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-create",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments",
            RequestAction.POST,
            generate_readable_output_message(
                object_type=ReadableOutputs.VULNERABILITY_COMMENT.value,
                action=ReadableOutputs.ADDED.value.format(EXAMPLE_ID),
            ),
        ),
        (
            {"vulnerability_id": EXAMPLE_ID, "comment_id": EXAMPLE_ID, "comment_content": "test"},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-update",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments/{EXAMPLE_ID}",
            RequestAction.PUT,
            generate_readable_output_message(
                object_type=ReadableOutputs.VULNERABILITY_COMMENT.value,
                action=ReadableOutputs.UPDATED,
                object_id=EXAMPLE_ID
            ),
        ),
        (
            {"vulnerability_id": EXAMPLE_ID, "comment_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-delete",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments/{EXAMPLE_ID}",
            RequestAction.DELETE,
            generate_readable_output_message(
                object_type=ReadableOutputs.VULNERABILITY_COMMENT.value,
                action=ReadableOutputs.DELETED,
                object_id=EXAMPLE_ID
            ),
        ),
        (
            {"scan_config_id": EXAMPLE_ID, "scan_type": " Regular"},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-submit",
            UrlPrefix.SCAN,
            RequestAction.POST,
            generate_readable_output_message(object_type=ReadableOutputs.SCAN,
                                             action=ReadableOutputs.SUBMITTED),
        ),
        (
            {"scan_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-delete",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}",
            RequestAction.DELETE,
            generate_readable_output_message(object_type=ReadableOutputs.SCAN,
                                             action=ReadableOutputs.DELETED,
                                             object_id=EXAMPLE_ID)
        ),
        (
            {"scan_id": EXAMPLE_ID, "action": "Cancel"},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN_ACTION}-submit",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/action",
            RequestAction.PUT,
            generate_readable_output_message(object_type=ReadableOutputs.SCAN,
                                             action=ReadableOutputs.CHANGED.value.format("Cancel"),
                                             object_id=EXAMPLE_ID)
        ),

    ),
)
def test_no_content_commands(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    command: str,
    excepted_output: str,
    endpoint: str,
    request_action: str,
):
    """
    Scenario: Test commands with action.
    Given:
     - User has provided correct parameters.
    When:
     - app-sec-vulnerability-update called.
     - app-sec-vulnerability-comment-create called.
     - app-sec-vulnerability-comment-update called.
     - app-sec-vulnerability-comment-delete called.
    Then:
     - Ensure that readable outputs is correct.
    """
    from Rapid7AppSec import (create_vulnerability_comment_command,
                              delete_scan_command,
                              delete_vulnerability_comment_command,
                              submit_scan_action_command, submit_scan_command,
                              update_vulnerability_command,
                              update_vulnerability_comment_command)
    commands: Dict[str, Callable] = {
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-update": update_vulnerability_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-create": create_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-update": update_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-delete": delete_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-submit": submit_scan_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-delete": delete_scan_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN_ACTION}-submit": submit_scan_action_command,

    }
    url = urljoin(mock_client._base_url, endpoint)
    match request_action:
        case RequestAction.POST:
            requests_mock.post(url=url)
        case RequestAction.PUT:
            requests_mock.put(url=url)
        case RequestAction.DELETE:
            requests_mock.delete(url=url)

    result = commands[command](mock_client, args)
    assert result.readable_output == excepted_output


@pytest.mark.parametrize(
    ("args", "command", "endpoint", "response", "output_prefix", "outputs_key_field"),
    (
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-list",
            UrlPrefix.VULNERABILITY,
            "vulnerability/list.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.VULNERABILITY}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}",
            "vulnerability/get.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.VULNERABILITY}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-history-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/history",
            "vulnerability/list_history.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.VULNERABILITY_HISTORY}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments",
            "vulnerability/list_comment.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.VULNERABILITY_COMMENT}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID, "comment_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments/{EXAMPLE_ID}",
            "vulnerability/get_comment.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.VULNERABILITY_COMMENT}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-list",
            f"{UrlPrefix.SCAN}",
            "scan/list_scan.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.SCAN}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"scan_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-list",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}",
            "scan/get_scan.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.SCAN}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"scan_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-engine-event-list",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/engine-events",
            "scan/list_engine_events.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ENGINE_EVENT}",
            "scan_id",
        ),
        (
            {"scan_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-platform-event-list",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/platform-events",
            "scan/list_platform_events.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.PLATFORM_EVENT}",
            "scan_id",
        ),
        (
            {"scan_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-execution-details-get",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/execution-details",
            "scan/get_execution_details.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.EXECUTION_DETAIL}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"scan_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN_ACTION}-get",
            f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/action",
            "scan/scan_action.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.SCAN}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),

    ),
)
def test_list_commands(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    command: str,
    endpoint: str,
    response: str,
    output_prefix: str,
    outputs_key_field: str,
):
    """
    Scenario: List and Get commands using list_handler command.
    Given:
     - User has provided correct parameters.
    When:
     - app-sec-vulnerability-list called.
     - app-sec-vulnerability-history-list called.
     - app-sec-vulnerability-comment-list called.

    Then:
     - Ensure that output prefix is correct.
     - Ensure that outputs key field is correct.
     - Ensure that outputs id is correct.
    """

    from Rapid7AppSec import (get_scan_action_command,
                              get_scan_execution_detail_command,
                              list_scan_command,
                              list_scan_engine_events_command,
                              list_scan_platform_events_command,
                              list_vulnerability_command,
                              list_vulnerability_comment_command,
                              list_vulnerability_history_command)
    commands: Dict[str, Callable] = {
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-list": list_vulnerability_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-history-list": list_vulnerability_history_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list": list_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-list": list_scan_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-engine-event-list": list_scan_engine_events_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-platform-event-list": list_scan_platform_events_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-execution-details-get": get_scan_execution_detail_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN_ACTION}-get": get_scan_action_command,
    }
    url = urljoin(
        mock_client._base_url,
        endpoint
    )
    json_response = load_mock_response(response)
    requests_mock.get(url=url, json=json_response)
    args = args | {"page": None, "page_size": None, "limit": 1}
    result = commands[command](mock_client, args)
    assert result.outputs_prefix == output_prefix
    assert result.outputs_key_field == outputs_key_field
    assert result.outputs[0][result.outputs_key_field] == EXAMPLE_ID
    assert result.raw_response == json_response

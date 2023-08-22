from Rapid7AppSec import Client, ReadableOutputs, UrlPrefix, OutputPrefix, RequestAction, DEFAULT_OUTPUT_KEY_FIELD
from Rapid7AppSec import generate_readable_output_message, generate_output_prefix
from CommonServerPython import *
import pytest
from http import HTTPStatus
from urllib.parse import urljoin
from typing import Callable
import os
import json
from Rapid7AppSec import INTEGRATION_COMMAND_PREFIX, VULNERABILITY, VULNERABILITY_COMMENT, ATTACK, SCAN, SCAN_ACTION


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
    from Rapid7AppSec import update_vulnerability_command
    from Rapid7AppSec import create_vulnerability_comment_command
    from Rapid7AppSec import update_vulnerability_comment_command
    from Rapid7AppSec import delete_vulnerability_comment_command
    commands: Dict[str, Callable] = {
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-update": update_vulnerability_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-create": create_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-update": update_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-delete": delete_vulnerability_comment_command,
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
            generate_output_prefix(OutputPrefix.VULNERABILITY),
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}",
            "vulnerability/get.json",
            generate_output_prefix(OutputPrefix.VULNERABILITY),
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-history-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/history",
            "vulnerability/list_history.json",
            generate_output_prefix(OutputPrefix.VULNERABILITY_HISTORY),
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments",
            "vulnerability/list_comment.json",
            generate_output_prefix(OutputPrefix.VULNERABILITY_COMMENT),
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"vulnerability_id": EXAMPLE_ID, "comment_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list",
            f"{UrlPrefix.VULNERABILITY}/{EXAMPLE_ID}/comments/{EXAMPLE_ID}",
            "vulnerability/get_comment.json",
            generate_output_prefix(OutputPrefix.VULNERABILITY_COMMENT),
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

    from Rapid7AppSec import list_vulnerability_command
    from Rapid7AppSec import list_vulnerability_history_command
    from Rapid7AppSec import list_vulnerability_comment_command
    commands: Dict[str, Callable] = {
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-list": list_vulnerability_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-history-list": list_vulnerability_history_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-list": list_vulnerability_comment_command,
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


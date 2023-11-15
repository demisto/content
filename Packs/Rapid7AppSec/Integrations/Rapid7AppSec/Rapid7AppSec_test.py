import http
import json
import os
from collections.abc import Callable
from urllib.parse import urljoin

import pytest
from CommonServerPython import *
from Rapid7AppSec import (API_LIMIT, ATTACK, DEFAULT_OUTPUT_KEY_FIELD,
                          INTEGRATION_COMMAND_PREFIX,
                          INTEGRATION_OUTPUT_PREFIX, SCAN, SCAN_ACTION,
                          VULNERABILITY, VULNERABILITY_COMMENT, Client,
                          OutputPrefix, ReadableOutputs, RequestAction,
                          UrlPrefix, generate_readable_output_message)

EXAMPLE_ID = "1111"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, encoding="utf-8") as mock_file:
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
            {"scan_config_id": EXAMPLE_ID, "scan_type": "Regular"},
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
     - Case 1: Update vulnerability severity and status.
     - Case 2: Create a comment to specific vulnerability.
     - Case 3: Update a comment to specific vulnerability.
     - Case 4: Delete a comment from specific vulnerability.
     - Case 5: Submit a scan.
     - Case 5: Delete a scan.
    When:
     - app-sec-vulnerability-update called.
     - app-sec-vulnerability-comment-create called.
     - app-sec-vulnerability-comment-update called.
     - app-sec-vulnerability-comment-delete called.
     - app-sec-scan-submit called.
     - app-sec-scan-delete called.
    Then:
     - Ensure that readable outputs is correct.
    """
    from Rapid7AppSec import (create_vulnerability_comment_command,
                              delete_scan_command,
                              delete_vulnerability_comment_command,
                              submit_scan_command,
                              update_vulnerability_command,
                              update_vulnerability_comment_command)
    commands: Dict[str, Callable] = {
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY}-update": update_vulnerability_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-create": create_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-update": update_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{VULNERABILITY_COMMENT}-delete": delete_vulnerability_comment_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-submit": submit_scan_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-delete": delete_scan_command,
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


def test_pooling_commands(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Test commands with action.
    Given:
     - User has provided correct parameters.
    When:
     - app-sec-scan-submit called.
    Then:
     - Ensure that readable outputs is correct.
    """
    from unittest.mock import patch

    from Rapid7AppSec import submit_scan_action_command

    excepted_output = generate_readable_output_message(object_type=ReadableOutputs.SCAN_ACTION,
                                                       action=ReadableOutputs.CHANGED.value.format("Resume"),
                                                       object_id=EXAMPLE_ID)

    url = urljoin(
        mock_client._base_url,
        f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/action"
    )
    requests_mock.get(url=url, status_code=http.HTTPStatus.NO_CONTENT)

    url = urljoin(
        mock_client._base_url,
        f"{UrlPrefix.SCAN}/{EXAMPLE_ID}/action"
    )
    requests_mock.put(url=url)

    with patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.5.0',
        'buildNumber': '12345'
    }):
        result = submit_scan_action_command(client=mock_client, args={"scan_id": EXAMPLE_ID, "action": "Resume"})
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
        (
            {"module_id": EXAMPLE_ID, "attack_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-get",
            f"{UrlPrefix.MODULE}/{EXAMPLE_ID}/attacks/{EXAMPLE_ID}",
            "vulnerability/get_attack.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ATTACK}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"module_id": EXAMPLE_ID, "attack_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-documentation-get",
            f"{UrlPrefix.MODULE}/{EXAMPLE_ID}/attacks/{EXAMPLE_ID}/documentation",
            "vulnerability/get_attack_documentation.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ATTACK_DOCUMENTATION}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-config-list",
            f"{UrlPrefix.SCAN_CONFIG}",
            "scan/list_scan_config.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.SCAN_CONFIG}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"scan_config_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-config-list",
            f"{UrlPrefix.SCAN_CONFIG}/{EXAMPLE_ID}",
            "scan/get_scan_config.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.SCAN_CONFIG}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-app-list",
            f"{UrlPrefix.APP}",
            "scan/list_app.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.APP}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"app_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-app-list",
            f"{UrlPrefix.APP}/{EXAMPLE_ID}",
            "scan/get_app_engine_group.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.APP}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-module-list",
            f"{UrlPrefix.MODULE}",
            "scan/list_modules.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.MODULE}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"module_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-module-list",
            f"{UrlPrefix.MODULE}/{EXAMPLE_ID}",
            "scan/list_modules.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.MODULE}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-template-list",
            f"{UrlPrefix.ATTACK_TEMPLATE}",
            "scan/list_attack_template.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ATTACK_TEMPLATE}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"attack_template_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-template-list",
            f"{UrlPrefix.ATTACK_TEMPLATE}/{EXAMPLE_ID}",
            "scan/get_attack_template.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ATTACK_TEMPLATE}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-engine-group-list",
            f"{UrlPrefix.ENGINE_GROUP}",
            "scan/list_engine_group.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ENGINE_GROUP}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"engine_group_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-engine-group-list",
            f"{UrlPrefix.ENGINE_GROUP}/{EXAMPLE_ID}",
            "scan/get_app_engine_group.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ENGINE_GROUP}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {},
            f"{INTEGRATION_COMMAND_PREFIX}-engine-list",
            f"{UrlPrefix.ENGINE}",
            "scan/list_engine.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ENGINE}",
            DEFAULT_OUTPUT_KEY_FIELD,
        ),
        (
            {"engine_id": EXAMPLE_ID},
            f"{INTEGRATION_COMMAND_PREFIX}-engine-list",
            f"{UrlPrefix.ENGINE}/{EXAMPLE_ID}",
            "scan/get_engine.json",
            f"{INTEGRATION_OUTPUT_PREFIX}.{OutputPrefix.ENGINE}",
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
     - Case 1: List vulnerabilities.
     - Case 2: List vulnerabilities with a specific vulnerability_id.
     - Case 3: List vulnerability history.
     - Case 4: List vulnerability comments.
     - Case 5: List vulnerability comment with a specific comment_id.
     - Case 6: List scans.
     - Case 7: List scan with specific scan_id.
     - Case 8: List scan engine events.
     - Case 9: List scan platform events.
     - Case 10: List scan execution details.
     - Case 11: Get scan action.
     - Case 12: Get attack.
     - Case 13: Get attack documentation.
     - Case 14: List scan configs.
     - Case 15: List scan config with a specific scan_config_id.
     - Case 16: List apps.
     - Case 17: List app with a specific app_id.
     - Case 18: List modules.
     - Case 19: List module with a specific module_id.
     - Case 20: List attack templates.
     - Case 21: List attack template with a specific attack template_id.
     - Case 22: List engine groups.
     - Case 23: List engine group with a specific engine_group_id.
     - Case 24: List engines.
     - Case 25: List engine with a specific engine_id.

    When:
     - app-sec-vulnerability-list called.
     - app-sec-vulnerability-history-list called.
     - app-sec-vulnerability-comment-list called.
     - app-sec-scan-list called.
     - app-sec-scan-engine-event-list.
     - app-sec-scan-platform-event-list.
     - app-sec-scan-execution-details-list.
     - app-sec-scan-action-get called.
     - app-sec-attack-get called.
     - app-sec-attack-documentation-get called.
     - app-sec-scan-config-list called.
     - app-sec-app-list called.
     - app-sec-module-list called.
     - app-sec-attack-template-list called.
     - app-sec-engine-list called.
     - app-sec-engine-group-list called.

    Then:
     - Ensure that output prefix is correct.
     - Ensure that outputs key field is correct.
     - Ensure that outputs id is correct.
     - Ensure that raw_response id is correct.
    """

    from Rapid7AppSec import (get_attack_command,
                              get_attack_documentation_command,
                              get_scan_action_command,
                              get_scan_execution_detail_command,
                              list_app_command, list_attack_template_command,
                              list_engine_command, list_engine_group_command,
                              list_module_command, list_scan_command,
                              list_scan_config_command,
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
        f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-get": get_attack_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-documentation-get": get_attack_documentation_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{SCAN}-config-list": list_scan_config_command,
        f"{INTEGRATION_COMMAND_PREFIX}-app-list": list_app_command,
        f"{INTEGRATION_COMMAND_PREFIX}-{ATTACK}-template-list": list_attack_template_command,
        f"{INTEGRATION_COMMAND_PREFIX}-engine-group-list": list_engine_group_command,
        f"{INTEGRATION_COMMAND_PREFIX}-engine-list": list_engine_command,
        f"{INTEGRATION_COMMAND_PREFIX}-module-list": list_module_command,
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


@pytest.mark.parametrize(
    ("args", "endpoints"),
    (
        (
            {"page": "21", "page_size": "50", "limit": "50"},
            [("vulnerabilities?index=20&size=50", "vulnerability/list.json")],
        ),
        (
            {"page": "41", "page_size": "50", "limit": "50"},
            [("vulnerabilities?index=40&size=50", "vulnerability/list.json")],
        ),
        (
            {"page": "61", "page_size": "50", "limit": "50"},
            [("vulnerabilities?index=60&size=50", "vulnerability/list.json")],
        ),
        (
            {"page": None, "page_size": None, "limit": "3000"},
            [
                ("vulnerabilities?size=1000", "vulnerability/list.json"),
                ("vulnerabilities?size=1000&page-token=string", "vulnerability/list_2.json"),
                ("vulnerabilities?size=1000&page-token=string2", "vulnerability/list_3.json"),
            ],
        ),
        (
            {"page": None, "page_size": None, "limit": "4000"},
            [
                ("vulnerabilities?size=1000", "vulnerability/list.json"),
                ("vulnerabilities?size=1000&page-token=string", "vulnerability/list_2.json"),
                ("vulnerabilities?size=1000&page-token=string2", "vulnerability/list_3.json"),
            ],
        ),
        (
            {"page": None, "page_size": None, "limit": "4020"},
            [
                ("vulnerabilities?size=1000", "vulnerability/list.json"),
                ("vulnerabilities?size=1000&page-token=string", "vulnerability/list_2.json"),
                ("vulnerabilities?size=1000&page-token=string2", "vulnerability/list_3.json"),
                ("vulnerabilities?size=20&page-token=string2", "vulnerability/list_3.json"),
            ],
        ),
    ),
)
def test_pagination(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    endpoints: list,
):
    """
    Scenario: Test pagination with page-token.
    Given:
     - User has provided correct parameters.
    When:
     - app-sec-vulnerability-list called.

    Then:
     - Ensure that output prefix is correct.
     - Ensure that outputs raw_response field is correct.
    """

    from Rapid7AppSec import list_vulnerability_command

    for endpoint, json_path in endpoints:
        json_response = load_mock_response(file_name=json_path)
        url = urljoin(
            mock_client._base_url,
            endpoint
        )
        requests_mock.get(url=url, json=json_response)

    result = list_vulnerability_command(mock_client, args)
    assert result.outputs_prefix == "Rapid7AppSec.Vulnerability"
    limit = arg_to_number(args.get("limit"))
    assert (isinstance(limit, int) and limit >= API_LIMIT) or (result.raw_response == json_response)

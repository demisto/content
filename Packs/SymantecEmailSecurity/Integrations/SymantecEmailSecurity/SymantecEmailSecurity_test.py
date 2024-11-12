import copy
import json
import os
import unittest.mock
from datetime import datetime
from typing import Any, Callable

import CommonServerPython
import pytest
import SymantecEmailSecurity

TEST_DATA = "test_data"
BASE_URL = "https://www.example.com"


def load_json_file(file_name: str) -> list[dict[str, Any]] | dict[str, Any]:
    """Load the content of a JSON file.

    Args:
        file_name (str): Name of the JSON file to read and load.
    Returns:
        list[dict[str, Any]] | dict[str, Any]: Loaded file's content.
    """
    file_path = os.path.join(TEST_DATA, file_name)

    with open(file_path) as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture()
def mock_client() -> SymantecEmailSecurity.Client:
    """Establish a mock connection to the API client.

    Returns:
        Client: Mock connection to client.
    """
    return SymantecEmailSecurity.Client(
        base_url=BASE_URL,
        username="test",
        password="test",
    )


@pytest.fixture()
def mock_quarantine_client() -> SymantecEmailSecurity.QuarantineClient:
    """Establish a mock connection to the API client.

    Returns:
        Client: Mock connection to client.
    """
    return SymantecEmailSecurity.QuarantineClient(
        base_url=BASE_URL,
        username="test",
        password="test",
    )


class MockClient:
    def __init__(self):
        self.calls = 0

    @SymantecEmailSecurity.pagination(items_key="items")
    def mock_api_call(self, start_index: int = 0, page_size: int = 2):
        """Mock API call that returns paginated results.

        Args:
            start_index (int, optional): The index to start fetching items from.
                Defaults to 0.
            page_size (int, optional): The number of items to return per page.
                Defaults to 2.

        Returns:
            dict[str, Any]: A dictionary containing the paginated items.
        """
        start_index = start_index or 0
        self.calls += 1
        data = [{"id": i} for i in range(start_index, start_index + page_size)]

        return {"items": data}


def test_pagination_manual() -> None:
    """
    Scenario:
    - Test manual pagination by calling the mock API for a specific page.

    Given:
    - A mock API function that simulates paginated results.

    When:
    - The mock API is called with `page=2` and `page_size=2`.

    Then:
    - Ensure that the correct items for the second page are returned.
    - Ensure that only one API call is made.
    """
    client = MockClient()
    response = client.mock_api_call(page=2, page_size=2)

    assert response["items"] == [{"id": 2}, {"id": 3}]
    assert client.calls == 1


def test_pagination_automatic() -> None:
    """
    Scenario:
    - Test automatic pagination by calling the mock API to retrieve multiple items.

    Given:
    - A mock API function that simulates paginated results.

    When:
    - The mock API is called with a `limit=4`.

    Then:
    - Ensure that the correct number of items (4) are returned.
    - Ensure that two API calls are made to fetch all items (as page size is 2).
    """
    SymantecEmailSecurity.DEFAULT_LIMIT = 3
    SymantecEmailSecurity.QUARANTINE_API_MAX_LIMIT = 2

    client = MockClient()
    response = client.mock_api_call(limit=4)

    assert response["items"] == [{"id": 0}, {"id": 1}, {"id": 2}, {"id": 3}]
    assert client.calls == 2


@SymantecEmailSecurity.validate_response
def mock_successful_api_call() -> dict[str, str]:
    """Mock API call that returns a successful response.

    Returns:
        dict[str, str]: A dictionary with a status of SUCCESS.
    """
    return {"status": "SUCCESS", "data": "Valid response"}


@SymantecEmailSecurity.validate_response
def mock_failed_api_call() -> dict[str, str]:
    """Mock API call that returns a failed response.

    Returns:
        dict[str, str]: A dictionary with a status of FAILURE.
    """
    return {"status": "FAILURE", "error": "Something went wrong"}


def test_validate_response_success() -> None:
    """
    Scenario:
    - Test the `validate_response` decorator for a successful response.

    Given:
    - A mock API function that returns a response with `status="SUCCESS"`.

    When:
    - The decorated function is called.

    Then:
    - Ensure that the function returns the original response as expected.
    """
    assert mock_successful_api_call() == {"status": "SUCCESS", "data": "Valid response"}


def test_validate_response_failure() -> None:
    """
    Scenario:
    - Test the `validate_response` decorator for a failed response.

    Given:
    - A mock API function that returns a response with `status="FAILURE"`.

    When:
    - The decorated function is called.

    Then:
    - Ensure that the function raises a `DemistoException` with the appropriate error message.
    """
    with pytest.raises(CommonServerPython.DemistoException):
        mock_failed_api_call()


@pytest.mark.parametrize(
    (
        "username,"
        "password,"
        "has_any_client_url,"
        "quarantine_username,"
        "quarantine_password,"
        "expect_client,"
        "expect_quarantine_client"
    ),
    [
        ("user", "pass", True, "user", "pass", True, True),  # Test creating both the clients
        ("user", "pass", True, None, None, True, False),  # Test creating only the regular client
        (None, None, False, "q_user", "q_pass", False, True),  # Test creating only the quarantine client
    ],
)
def test_determine_clients(
    username: str | None,
    password: str | None,
    has_any_client_url: bool,
    quarantine_username: str | None,
    quarantine_password: str | None,
    expect_client: bool,
    expect_quarantine_client: bool,
) -> None:
    """
    Scenario:
    - Test creating either the regular client or the quarantine client based on the input.

    Given:
    - Valid credentials and URL for either the regular client or the quarantine client.

    When:
    - `determine_clients` is called.

    Then:
    - Ensure that the appropriate client(s) are created or not, depending on the input.
    """
    command = "some-command"
    client, quarantine_client = SymantecEmailSecurity.determine_clients(
        command=command,
        username=username,
        password=password,
        command_to_url={command: "https://example.com"},
        has_any_client_url=has_any_client_url,
        quarantine_username=quarantine_username,
        quarantine_password=quarantine_password,
        url_quarantine="https://example.com/quarantine",
        verify_certificate=False,
        proxy=False,
    )

    if expect_client:
        assert client is not None
    else:
        assert client is None

    if expect_quarantine_client:
        assert quarantine_client is not None
    else:
        assert quarantine_client is None


@pytest.mark.parametrize(
    (
        "username,"
        "password,"
        "url_regular,"
        "quarantine_username,"
        "quarantine_password,"
        "url_quarantine,"
        "expected_message"
    ),
    [
        # Test for mismatched credentials (only username is provided)
        (
            "user",
            None,
            "https://example.com",
            None,
            None,
            "https://example.com/quarantine",
            "Both username and password must be present when adding credentials.",
        ),
        # Test for missing URL for the regular client
        (
            "user",
            "pass",
            None,
            None,
            None,
            "https://example.com/quarantine",
            "Missing URL for 'Credentials', please fill the correct URL according to the mapping in 'Help'.",
        ),
        # Test for missing quarantine URL
        (
            None,
            None,
            "https://example.com",
            "q_user",
            "q_pass",
            None,
            "Missing URL for 'Quarantine Credentials', please fill 'Server URL - Quarantine'.",
        ),
        # Test for no credentials provided.
        (
            None,
            None,
            None,
            None,
            None,
            None,
            "At least one of the credentials must be filled.",
        ),
    ],
)
def test_determine_clients_exceptions(
    username: str | None,
    password: str | None,
    url_regular: str | None,
    quarantine_username: str | None,
    quarantine_password: str | None,
    url_quarantine: str | None,
    expected_message: str,
) -> None:
    """
    Scenario:
    - Mismatched credentials, missing URL for the client, or missing URL for the quarantine client.

    Given:
    - Various invalid combinations of credentials and URLs.

    When:
    - `determine_clients` is called.

    Then:
    - Ensure that the appropriate `DemistoException` is raised with the correct message.
    """
    command = "some-command"
    command_to_url = {command: url_regular}

    with pytest.raises(CommonServerPython.DemistoException, match=expected_message):
        SymantecEmailSecurity.determine_clients(
            command=command,
            username=username,
            password=password,
            has_any_client_url=False,
            command_to_url=command_to_url,
            quarantine_username=quarantine_username,
            quarantine_password=quarantine_password,
            url_quarantine=url_quarantine,
            verify_certificate=False,
            proxy=False,
        )


@pytest.mark.parametrize(
    "input, expected",
    [
        ("2023-10-15T12:34:56.789123Z", "2023-10-15T12:34:56Z"),
        ("2023-10-15T12:34:56", "2023-10-15T12:34:56Z"),
        ("0", datetime(1970, 1, 1, 0, 0, 0).isoformat() + "Z"),
    ],
)
def test_convert_datetime_string(input: str, expected: str) -> None:
    """
    Scenario:
    - Test converting datetime strings to ISO 8601 format with microseconds set to zero.

    Given:
    - Various datetime strings with different formats and microseconds.

    When:
    - convert_datetime_string is called with these datetime strings.

    Then:
    - Ensure that the returned string is in the correct ISO 8601 format without microseconds and with 'Z' appended.
    - Ensure that microseconds are set to zero in the output.
    """
    assert SymantecEmailSecurity.convert_datetime_string(input) == expected


@pytest.mark.parametrize(
    "input, expected",
    [
        ("1970-01-01T00:00:00Z", "0"),
        ("2023-10-15T12:34:56", str(int(datetime(2023, 10, 15, 12, 34, 56).timestamp() * 1000))),
        ("0", "0"),  # This assumes "0" is treated as epoch time, Jan 1, 1970
        (None, None),
    ],
)
def test_convert_to_epoch_timestamp(input: str | None, expected: str | None) -> None:
    """
    Scenario:
    - Test converting datetime strings to epoch timestamps in milliseconds.

    Given:
    - Various datetime strings or None values.

    When:
    - convert_to_epoch_timestamp is called with these datetime strings.

    Then:
    - Ensure that the returned value is the correct epoch timestamp in milliseconds or None.
    """
    assert SymantecEmailSecurity.convert_to_epoch_timestamp(input) == expected


@pytest.mark.parametrize(
    "input, expected",
    [
        (None, None),
        (True, True),
        (False, False),
        ("true", True),
        ("false", False),
    ],
)
def test_arg_to_optional_bool(input: Any, expected: None | bool) -> None:
    """
    Scenario:
    - Test converting various inputs to optional boolean values.

    Given:
    - Various inputs of different types.

    When:
    - arg_to_optional_bool is called with these inputs.

    Then:
    - Ensure that the returned value is either None or the correct boolean representation.
    """
    assert SymantecEmailSecurity.arg_to_optional_bool(input) == expected


def test_list_ioc_command(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test retrieving a list of items through an HTTP request.

    Given:
    - limit.

    When:
    - ioc_list_command is called

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    mock_response = load_json_file("ioc_list_response.json")
    mock_table = load_json_file("ioc_list_table.json")

    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/download")

    requests_mock.get(url=endpoint, json=mock_response)

    command_results = SymantecEmailSecurity.list_ioc_command(mock_client, {"limit": 5})

    assert command_results.outputs_prefix == f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.IOC"
    assert command_results.outputs_key_field == "iocBlackListId"
    assert command_results.outputs == mock_response
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name="IOC(s)",
        t=mock_table,
        headers=[
            "ID",
            "Type",
            "Value",
            "Status",
            "Description",
            "Email Direction",
            "Remediation Action",
            "Expiry Date",
        ],
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    "args, iocs",
    [
        (
            {"action": "ioc", "entry_id": "000"},
            [
                {
                    "APIRowAction": "A",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "I",
                },
                {
                    "APIRowAction": "R",
                    "IocBlacklistId": "00000000-0000-0000-0000-000000000000",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "O",
                    "RemediationAction": "H",
                },
                {
                    "APIRowAction": "U",
                    "IocBlacklistId": "00000000-0000-0000-0000-000000000000",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "O",
                    "RemediationAction": "H",
                },
                {
                    "APIRowAction": "D",
                    "IocBlacklistId": "00000000-0000-0000-0000-000000000000",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "O",
                    "RemediationAction": "H",
                },
            ],
        ),
        (
            {"action": "merge", "entry_id": "000"},
            [
                {
                    "IocType": "url",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "I",
                }
            ],
        ),
        (
            {"action": "replace", "entry_id": "000"},
            [
                {
                    "IocType": "url",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "I",
                }
            ],
        ),
    ],
)
def test_action_ioc_command_success_multiple_ioc(
    requests_mock,
    mock_client: SymantecEmailSecurity.Client,
    args: dict[str, Any],
    iocs: list[dict[str, Any]],
) -> None:
    """
    Scenario:
    - Test build IOCs through all scenarios.

    Given:
    - An `entry_id` with an `action`.

    When:
    - ioc_action_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    read_data = json.dumps(iocs)
    mocked_open = unittest.mock.mock_open(read_data=read_data)

    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/upload")

    requests_mock.post(url=endpoint, json=[])

    with unittest.mock.patch("builtins.open", mocked_open):
        command_results = SymantecEmailSecurity.action_ioc_command(mock_client, args)

    assert command_results.readable_output == "## All IOC(s) were uploaded successfully."


@pytest.mark.parametrize(
    "args",
    [
        {
            "action": "merge",
            "ioc_type": "subject",
            "ioc_value": "Test",
            "description": "Test",
            "email_direction": "inbound",
            "remediation_action": "quarantine",
        },
        {
            "action": "replace",
            "ioc_type": "subject",
            "ioc_value": "Test",
            "description": "Test",
            "email_direction": "inbound",
            "remediation_action": "quarantine",
        },
        {
            "action": "add",
            "ioc_type": "subject",
            "ioc_value": "Test",
            "description": "Test",
            "email_direction": "inbound",
            "remediation_action": "quarantine",
        },
        {
            "action": "update",
            "ioc_id": "00000000-0000-0000-0000-000000000000",
            "ioc_type": "subject",
            "ioc_value": "Test",
            "description": "Test",
            "email_direction": "inbound",
            "remediation_action": "quarantine",
        },
        {
            "action": "delete",
            "ioc_id": "00000000-0000-0000-0000-000000000000",
            "ioc_type": "subject",
            "ioc_value": "Test",
            "description": "Test",
            "email_direction": "inbound",
            "remediation_action": "quarantine",
        },
        {
            "action": "renew",
            "ioc_id": "00000000-0000-0000-0000-000000000000",
            "ioc_type": "subject",
            "ioc_value": "Test",
            "description": "Test",
            "email_direction": "inbound",
            "remediation_action": "quarantine",
        },
    ],
)
def test_action_ioc_command_success_single_ioc(
    requests_mock,
    mock_client: SymantecEmailSecurity.Client,
    args: dict[str, Any],
) -> None:
    """
    Scenario:
    - Test build IOCs through all scenarios.

    Given:
    - All arguments except for `entry_id`.

    When:
    - ioc_action_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/upload")
    requests_mock.post(url=endpoint, json=[])

    command_results = SymantecEmailSecurity.action_ioc_command(mock_client, args)

    assert command_results.readable_output == "## All IOC(s) were uploaded successfully."


@pytest.mark.parametrize(
    "args, iocs, error_message",
    [
        (
            {"action": "ioc", "entry_id": "000"},
            [
                {
                    "APIRowAction": "A",
                    "IocBlacklistId": "00000000-0000-0000-0000-000000000000",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "I",
                },
            ],
            "IocBlacklistId should not be present for APIRowAction=A (Add).",
        ),
        (
            {"action": "ioc", "entry_id": "000"},
            [
                {
                    "APIRowAction": "R",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "O",
                    "RemediationAction": "H",
                },
            ],
            "IocBlacklistId must be present for APIRowAction=R.",
        ),
        (
            {"action": "ioc", "entry_id": "000"},
            [
                {
                    "IocBlacklistId": "00000000-0000-0000-0000-000000000000",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "O",
                    "RemediationAction": "H",
                },
            ],
            "APIRowAction must be present for action=ioc.",
        ),
        (
            {"action": "ioc", "entry_id": "000"},
            [
                {
                    "APIRowAction": "D",
                    "IocType": "subject",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "O",
                    "RemediationAction": "H",
                },
            ],
            "IocBlacklistId must be present for APIRowAction=D.",
        ),
        (
            {"action": "merge", "entry_id": "000"},
            [
                {
                    "IocBlacklistId": "00000000-0000-0000-0000-000000000000",
                    "IocType": "url",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "I",
                }
            ],
            "APIRowAction and IocBlacklistId should be omitted or blank for MERGE requests.",
        ),
        (
            {"action": "replace", "entry_id": "000"},
            [
                {
                    "APIRowAction": "A",
                    "IocType": "url",
                    "IocValue": "Test",
                    "Description": "Test",
                    "EmailDirection": "I",
                }
            ],
            "APIRowAction and IocBlacklistId should be omitted or blank for REPLACE requests.",
        ),
        (
            {"action": "add", "entry_id": "000"},
            [],
            "The field `entry_id` is only compatible with `action=merge/replace/ioc`.",
        ),
        (
            {"action": "delete", "entry_id": "000"},
            [],
            "The field `entry_id` is only compatible with `action=merge/replace/ioc`.",
        ),
        (
            {"action": "renew", "entry_id": "000"},
            [],
            "The field `entry_id` is only compatible with `action=merge/replace/ioc`.",
        ),
        (
            {"action": "update", "entry_id": "000"},
            [],
            "The field `entry_id` is only compatible with `action=merge/replace/ioc`.",
        ),
    ],
)
def test_action_ioc_command_error_multiple_ioc(
    requests_mock,
    mock_client: SymantecEmailSecurity.Client,
    args: dict[str, Any],
    iocs: list[dict[str, Any]],
    error_message: str,
) -> None:
    """
    Scenario:
    - Test exception handling when build IOCs from a dict.

    Given:
    - An `entry_id` with an `action`.

    When:
    - ioc_action_command

    Then:
    - Ensure that the error message is raised.
    """
    read_data = json.dumps(iocs)
    mocked_open = unittest.mock.mock_open(read_data=read_data)

    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/upload")

    requests_mock.post(url=endpoint, json=[])

    with unittest.mock.patch("builtins.open", mocked_open), pytest.raises(CommonServerPython.DemistoException) as e:
        SymantecEmailSecurity.action_ioc_command(mock_client, args)

    assert str(e.value) == error_message


@pytest.mark.parametrize(
    "args, error_message",
    [
        (
            {"action": "ioc"},
            "`action=ioc` is only compatible with `entry_id`.",
        ),
        (
            {
                "action": "merge",
                "ioc_id": "00000000-0000-0000-0000-000000000000",
                "ioc_type": "subject",
                "ioc_value": "Test",
                "description": "Test",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "APIRowAction and IocBlacklistId should be omitted or blank for MERGE requests.",
        ),
        (
            {
                "action": "merge",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "Fields IocType, IocValue, Description, and EmailDirection are mandatory.",
        ),
        (
            {
                "action": "replace",
                "ioc_id": "00000000-0000-0000-0000-000000000000",
                "ioc_type": "subject",
                "ioc_value": "Test",
                "description": "Test",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "APIRowAction and IocBlacklistId should be omitted or blank for REPLACE requests.",
        ),
        (
            {
                "action": "add",
                "ioc_id": "00000000-0000-0000-0000-000000000000",
                "ioc_type": "subject",
                "ioc_value": "Test",
                "description": "Test",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "IocBlacklistId should not be present for APIRowAction=A (Add).",
        ),
        (
            {
                "action": "update",
                "ioc_type": "subject",
                "ioc_value": "Test",
                "description": "Test",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "IocBlacklistId must be present for APIRowAction=U.",
        ),
        (
            {
                "action": "delete",
                "ioc_type": "subject",
                "ioc_value": "Test",
                "description": "Test",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "IocBlacklistId must be present for APIRowAction=D.",
        ),
        (
            {
                "action": "renew",
                "ioc_type": "subject",
                "ioc_value": "Test",
                "description": "Test",
                "email_direction": "inbound",
                "remediation_action": "quarantine",
            },
            "IocBlacklistId must be present for APIRowAction=R.",
        ),
    ],
)
def test_action_ioc_command_error_single_ioc(
    requests_mock,
    mock_client: SymantecEmailSecurity.Client,
    args: dict[str, Any],
    error_message: str,
) -> None:
    """
    Scenario:
    - Test build IOCs through all scenarios.

    Given:
    - All arguments except for `entry_id`.

    When:
    - ioc_action_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/upload")
    requests_mock.post(url=endpoint, json=[])

    with pytest.raises(CommonServerPython.DemistoException) as e:
        SymantecEmailSecurity.action_ioc_command(mock_client, args)

    assert str(e.value) == error_message


def test_action_ioc_command_failure_multiple_ioc(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test build IOCs through all scenarios.

    Given:
    - An `entry_id` with an `action`.

    When:
    - ioc_action_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    iocs = [
        {
            "APIRowAction": "A",
            "IocType": "subject",
            "IocValue": "Test",
            "Description": "Test",
            "EmailDirection": "I",
        }
    ]
    read_data = json.dumps(iocs)
    mocked_open = unittest.mock.mock_open(read_data=read_data)

    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/upload")
    response = [
        {
            "iocBlackListId": "000",
            "iocType": "subject",
            "iocValue": "Test",
            "failureReason": "Hello World!",
        },
        {
            "iocType": "subject",
            "iocValue": "Test",
            "failureReason": "Hello World!",
        },
    ]

    requests_mock.post(url=endpoint, json=response)

    args = {"action": "ioc", "entry_id": "000"}

    with unittest.mock.patch("builtins.open", mocked_open):
        command_results = SymantecEmailSecurity.action_ioc_command(mock_client, args)

    assert (
        command_results.readable_output
        == "## The following IOC(s) failed:\n- 000: Hello World!\n- subject-Test: Hello World!"
    )


def test_renew_ioc_command_success(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test renewing all IOCs in the API.

    Given:
    - Nothing.

    When:
    - ioc_renew_command is called

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/renewall")
    requests_mock.post(url=endpoint, json={}, headers={"x-status": "SUCCESS"})

    command_results = SymantecEmailSecurity.renew_ioc_command(mock_client, {})
    assert command_results.readable_output == "## All IOC(s) were renewed."


def test_renew_ioc_command_error(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test renewing all IOCs in the API.

    Given:
    - Nothing.

    When:
    - ioc_renew_command is called

    Then:
    - Ensure that an error is raised with the correct message.
    """
    endpoint = CommonServerPython.urljoin(BASE_URL, "domains/global/iocs/renewall")
    requests_mock.post(url=endpoint, json={}, headers={"x-status": "FAILURE"})

    with pytest.raises(CommonServerPython.DemistoException) as e:
        SymantecEmailSecurity.renew_ioc_command(mock_client, {})

    assert str(e.value) == "Failed to renew IOCs, reason: None."


def test_list_email_queue_command(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test retrieving a list of items through an HTTP request.

    Given:
    - limit.

    When:
    - email_queue_list is called

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    mock_response = load_json_file("email_queue_list_response.json")

    endpoint = CommonServerPython.urljoin(BASE_URL, "stats")

    requests_mock.get(url=endpoint, json=mock_response)

    command_results = SymantecEmailSecurity.list_email_queue_command(mock_client, {"limit": 5})

    expected_readable_output = (
        CommonServerPython.tableToMarkdown(
            name="Email Queue Statistic(s)",
            t=mock_response,
            headerTransform=CommonServerPython.string_to_table_header,
            headers=[
                "TotalMessagesInbound",
                "TotalMessagesOutbound",
                "MeanTimeInQueueInbound",
                "MeanTimeInQueueOutbound",
                "LongestTimeInInbound",
                "LongestTimeInOutbound",
            ],
        )
        + "\n"
        + CommonServerPython.tableToMarkdown(
            name="Domain Statistic(s)",
            t=mock_response["Domains"],
            headerTransform=CommonServerPython.string_to_table_header,
            headers=[
                "Name",
                "ReceiveQueueCountInbound",
                "ReceiveQueueCountOutbound",
                "DeliveryQueueCountInbound",
                "DeliveryQueueCountOutbound",
            ],
        )
    )

    assert command_results.outputs_prefix == f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.EmailQueue"
    assert command_results.outputs == mock_response
    assert command_results.readable_output == expected_readable_output
    assert command_results.raw_response == mock_response


def test_list_data_command(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test retrieving a list of items through an HTTP request.

    Given:
    - limit.

    When:
    - data_list_command is called

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    mock_response = load_json_file("data_list_response.json")
    mock_table = load_json_file("data_list_table.json")

    endpoint = CommonServerPython.urljoin(BASE_URL, "all")

    requests_mock.get(url=endpoint, json="Reset successfully")
    requests_mock.get(url=endpoint, json=mock_response)

    command_results = SymantecEmailSecurity.list_data_command(mock_client, {"limit": 5, "fetch_only_incidents": "true"})

    assert command_results.outputs_prefix == f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.Data"
    assert command_results.outputs == mock_response
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name="Email Data Feed(s)",
        t=mock_table,
        headers=[
            "Message Size",
            "Subject",
            "Envelope From",
            "Envelope To",
            "Sender IP",
            "Sender Mail Server",
            "File/URLs With Risk",
            "Incidents",
        ],
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "outputs_prefix,"
        "outputs_key,"
    ),
    [
        (
            SymantecEmailSecurity.list_quarantine_email_command,
            {},
            "v1/mails",
            "quarantine_email_list_response.json",
            "quarantine_email_list_table.json",
            "Quarantine Email(s)",
            f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.QuarantineEmail",
            "mail_list",
        ),
        (
            SymantecEmailSecurity.list_item_allow_block_command,
            {"access_control": SymantecEmailSecurity.AccessControl.WHITELIST.value},
            "v1/users/whitelist",
            "item_allow_block_list_response.json",
            "item_allow_block_list_table.json",
            "Allow List Item(s)",
            f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.Allow",
            "items",
        ),
        (
            SymantecEmailSecurity.list_item_allow_block_command,
            {"access_control": SymantecEmailSecurity.AccessControl.BLACKLIST.value},
            "v1/users/blacklist",
            "item_allow_block_list_response.json",
            "item_allow_block_list_table.json",
            "Block List Item(s)",
            f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.Block",
            "items",
        ),
    ],
)
def test_automatic_pagination_commands(
    requests_mock,
    mock_quarantine_client: SymantecEmailSecurity.QuarantineClient,
    list_command: Callable[[SymantecEmailSecurity.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    outputs_prefix: str,
    outputs_key: str,
) -> None:
    """
    Scenario:
    - Test retrieving a list of objects through making multiple HTTP requests.

    Given:
    - Command args and a `limit`.

    When:
    - quarantine_email_list_command
    - item_allow_block_list_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args["sort_order"] = "desc"
    args["limit"] = 5
    SymantecEmailSecurity.QUARANTINE_API_MAX_LIMIT = 2

    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    endpoint = CommonServerPython.urljoin(BASE_URL, endpoint_suffix)
    number_of_calls = args["limit"] // SymantecEmailSecurity.QUARANTINE_API_MAX_LIMIT

    for i in range(number_of_calls + 1):
        expected_output = mock_response[outputs_key][number_of_calls * i: number_of_calls * (i + 1)]

        if not expected_output:
            break

        current_mock_response = copy.copy(mock_response)
        current_mock_response[outputs_key] = expected_output

        start_index = i * SymantecEmailSecurity.QUARANTINE_API_MAX_LIMIT

        if i == 0:
            page_size = SymantecEmailSecurity.QUARANTINE_API_MAX_LIMIT
        else:
            page_size = len(expected_output)

        requests_mock.get(
            url=f"{endpoint}?sort_order=desc&{f'{start_index=}&' if i else ''}{page_size=}",
            json=current_mock_response,
        )

    command_results = list_command(mock_quarantine_client, args)

    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs == mock_response[outputs_key]
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=list(mock_table[0]),
    )
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    (
        "list_command,"
        "args,"
        "endpoint_suffix,"
        "response_file,"
        "table_file,"
        "readable_output_title,"
        "outputs_prefix,"
        "outputs_key,"
    ),
    [
        (
            SymantecEmailSecurity.list_quarantine_email_command,
            {},
            "v1/mails",
            "quarantine_email_list_response.json",
            "quarantine_email_list_table.json",
            "Quarantine Email(s)",
            f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.QuarantineEmail",
            "mail_list",
        ),
        (
            SymantecEmailSecurity.list_item_allow_block_command,
            {"access_control": SymantecEmailSecurity.AccessControl.WHITELIST.value},
            "v1/users/whitelist",
            "item_allow_block_list_response.json",
            "item_allow_block_list_table.json",
            "Allow List Item(s)",
            f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.Allow",
            "items",
        ),
        (
            SymantecEmailSecurity.list_item_allow_block_command,
            {"access_control": SymantecEmailSecurity.AccessControl.BLACKLIST.value},
            "v1/users/blacklist",
            "item_allow_block_list_response.json",
            "item_allow_block_list_table.json",
            "Block List Item(s)",
            f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.Block",
            "items",
        ),
    ],
)
def test_manual_pagination_commands(
    requests_mock,
    mock_quarantine_client: SymantecEmailSecurity.QuarantineClient,
    list_command: Callable[[SymantecEmailSecurity.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    response_file: str,
    table_file: str,
    readable_output_title: str,
    outputs_prefix: str,
    outputs_key: str,
) -> None:
    """
    Scenario:
    - Test retrieving a list of objects through making a paginated HTTP requests.

    Given:
    - Command args, `page` and `page_size`.

    When:
    - quarantine_email_list_command
    - item_allow_block_list_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args["page"] = 1
    args["page_size"] = 5

    mock_response = load_json_file(response_file)
    mock_table = load_json_file(table_file)

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json=mock_response,
    )

    command_results = list_command(mock_quarantine_client, args)

    assert command_results.outputs_prefix == outputs_prefix
    assert command_results.outputs_key_field == "id"
    assert command_results.outputs == mock_response[outputs_key]
    assert command_results.readable_output == CommonServerPython.tableToMarkdown(
        name=readable_output_title,
        t=mock_table,
        headers=list(mock_table[0]),
    )
    assert command_results.raw_response == mock_response


def test_preview_quarantine_email_command(
    requests_mock,
    mock_quarantine_client: SymantecEmailSecurity.QuarantineClient,
):
    """
    Scenario:
    - Test previewing a quarantine email.

    Given:
    - Command args, `message_id`.

    When:
    - preview_quarantine_email_command

    Then:
    - Ensure that the CommandResults outputs_prefix is correct.
    - Ensure that the CommandResults outputs_key_field is correct.
    - Ensure that the CommandResults outputs is correct.
    - Ensure that the CommandResults readable_output is correct.
    - Ensure that the CommandResults raw_response is correct.
    """
    args = {"message_id": "000"}

    mock_response = load_json_file("quarantine_email_preview_response.json")
    mock_table = load_json_file("quarantine_email_preview_table.json")

    requests_mock.get(
        url=CommonServerPython.urljoin(BASE_URL, "v1/mails/preview"),
        json=mock_response,
    )

    command_results = SymantecEmailSecurity.preview_quarantine_email_command(mock_quarantine_client, args)

    mock_response["details"]["message_id"] = args["message_id"]
    expected_outputs = mock_response["details"]
    expected_readable_output = (
        CommonServerPython.tableToMarkdown(
            name="Quarantine Email Preview",
            t=mock_table["headers"],
            headers=list(mock_table["headers"]),
        )
        + CommonServerPython.tableToMarkdown(
            name="Attachments",
            t=mock_table["attachments"],
            headers=list(mock_table["attachments"][0]),
        )
        + CommonServerPython.tableToMarkdown(
            name="Body Parts",
            t=mock_table["bodypart"],
        )
    )

    assert command_results.outputs_prefix == f"{SymantecEmailSecurity.INTEGRATION_PREFIX}.QuarantineEmailPreview"
    assert command_results.outputs_key_field == "message_id"
    assert command_results.outputs == expected_outputs
    assert command_results.readable_output == expected_readable_output
    assert command_results.raw_response == mock_response


@pytest.mark.parametrize(
    "command,args,endpoint_suffix,readable_output_title",
    [
        (
            SymantecEmailSecurity.release_quarantine_email_command,
            {"message_ids": "000,111", "recipient": "hello", "headers": "hello,world"},
            "v1/mails/release",
            "## Successfully released all messages.",
        ),
        (
            SymantecEmailSecurity.delete_quarantine_email_command,
            {"message_ids": "000,111"},
            "v1/mails/delete",
            "## Successfully deleted all messages.",
        ),
        (
            SymantecEmailSecurity.update_item_allow_block_list_command,
            {
                "access_control": SymantecEmailSecurity.AccessControl.BLACKLIST.value,
                "suduls_user": "Lior",
                "email_or_domain": "was",
                "description": "here",
            },
            "v1/users/blacklist",
            "## The items were successfully merged.",
        ),
        (
            SymantecEmailSecurity.delete_item_allow_block_list_command,
            {"access_control": SymantecEmailSecurity.AccessControl.WHITELIST.value, "item_id": "000"},
            "v1/users/whitelist",
            "## The items were successfully deleted.",
        ),
    ],
)
def test_general_action_commands(
    requests_mock,
    mock_quarantine_client: SymantecEmailSecurity.QuarantineClient,
    command: Callable[[SymantecEmailSecurity.Client, dict[str, Any]], CommonServerPython.CommandResults],
    args: dict[str, Any],
    endpoint_suffix: str,
    readable_output_title: str,
) -> None:
    """
    Scenario:
    - Test several general commands

    Given:
    - Command args.

    When:
    - release_quarantine_email_command
    - delete_quarantine_email_command
    - update_item_allow_block_list_command
    - delete_item_allow_block_list_command

    Then:
    - Ensure that the CommandResults readable_output is correct.
    """
    requests_mock.post(
        url=CommonServerPython.urljoin(BASE_URL, endpoint_suffix),
        json={"status": "SUCCESS"},
    )

    command_results = command(mock_quarantine_client, args)
    assert command_results.readable_output == readable_output_title


def test_fetch_incidents(requests_mock, mock_client: SymantecEmailSecurity.Client) -> None:
    """
    Scenario:
    - Test fetch incidents.

    Given:
    - Arguments for initializing a fetch.

    When:
    - fetch_incidents is called.

    Then:
    - Ensure that the incidents are correct.
    - Ensure that the next_run is correct.
    """
    mock_response = load_json_file("data_list_response.json")

    endpoint = CommonServerPython.urljoin(BASE_URL, "all")

    requests_mock.get(url=endpoint, json="Reset successfully")
    requests_mock.get(url=endpoint, json=mock_response)

    next_run, incidents = SymantecEmailSecurity.fetch_incidents(
        client=mock_client,
        last_run={},
        first_fetch_time="3 days",
        max_results=2,
        accepted_severities=[CommonServerPython.IncidentSeverity.LOW],
        feed_type="all",
        include_delivery=True,
    )

    expected_incidents = [
        {
            "name": " - Email Data Feeds - Malware - 000",
            "occurred": "1970-01-12T13:46:40.000Z",
            "severity": 1,
            "details": "unknown",
            "rawJSON": json.dumps(mock_response[0] | {"incident_type": "email_data_feed"}),
        }
    ]
    expected_next_run = {
        "email_data_feeds": {
            "last_fetch": "1000000000",
            "last_ids": [
                "000",
            ],
        }
    }

    assert incidents == expected_incidents
    assert next_run == expected_next_run


def test_fetch_incidents_quarantine(
    requests_mock,
    mock_quarantine_client: SymantecEmailSecurity.QuarantineClient,
) -> None:
    """
    Scenario:
    - Test fetch quarantine incidents.

    Given:
    - Arguments for initializing a fetch.

    When:
    - fetch_incidents is called.

    Then:
    - Ensure that the incidents are correct.
    - Ensure that the next_run is correct.
    """
    mock_response = load_json_file("quarantine_email_list_response.json")
    mock_response_preview = load_json_file("quarantine_email_preview_response.json")

    mock_response["mail_list"] = mock_response["mail_list"][:1]

    requests_mock.get(url=CommonServerPython.urljoin(BASE_URL, "v1/mails"), json=mock_response)
    requests_mock.get(url=CommonServerPython.urljoin(BASE_URL, "v1/mails/preview"), json=mock_response_preview)

    next_run, incidents = SymantecEmailSecurity.fetch_incidents_quarantine(
        client=mock_quarantine_client,
        last_run={},
        first_fetch_time="3 days",
        max_results=2,
    )

    item = mock_response["mail_list"][0] | mock_response_preview["details"] | {"incident_type": "email_quarantine"}

    expected_incidents = [
        {
            "name": " - Email Quarantine - CI - 000",
            "occurred": "2024-10-06T09:20:41.000Z",
            "severity": CommonServerPython.IncidentSeverity.UNKNOWN,
            "details": "Reason: CC",
            "rawJSON": json.dumps(item),
        }
    ]
    expected_next_run = {
        "email_quarantine": {
            "last_fetch": "1728206441148",
            "last_ids": [
                "000",
            ],
        }
    }

    assert incidents == expected_incidents
    assert next_run == expected_next_run

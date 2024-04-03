"""InsightIDR Integration for Cortex XSOAR - Unit Tests file"""

import json

import pytest
from CommonServerPython import *
from Rapid7_InsightIDR import Client, ConstantsV1, ConstantsV2

REGION = "us"


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """Create a test client for V1/V2.

    Args:
        version (str): Version (V1/V2).

    Returns:
        Client: Fortieweb VM Client.
    """
    return Client(
        base_url=f"https://{REGION}.api.insight.rapid7.com/",
        verify=False,
        headers={"Authentication": "apikey"},
        proxy=False,
        is_multi_customer=False,
    )


def util_load_json(path) -> dict:
    with open(path, encoding="utf-8") as file:
        return json.loads(file.read())


def util_load_file(path) -> str:
    with open(path, encoding="utf-8") as file:
        return file.read()


@pytest.mark.parametrize(
    ("api_version", "data_path", "constants", "outputs_key_field"),
    [
        ("V1", "list_investigations.json", ConstantsV1, "id"),
        ("V2", "list_investigations_v2.json", ConstantsV2, "rrn"),
    ],
)
def test_insight_idr_list_investigations(
    mock_client: Client, requests_mock, api_version, data_path, constants, outputs_key_field
) -> None:
    """
    Scenario: test list investigations
    Given:
     - User has provided valid credentials
    When:
     - insight_idr_list_investigations_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_list_investigations_command

    mock_response = util_load_json(f"test_data/{data_path}")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/idr/{api_version.lower()}/investigations",
        json=mock_response,
    )

    response = insight_idr_list_investigations_command(
        client=mock_client,
        args={
            "api_version": api_version,
            "index": 0,
            "page_size": 2,
            "limit": 50,
            "time_range": "1 day",
        },
        constants=constants,
    )

    outputs = []
    assert isinstance(response.raw_response, dict)
    for investigation in response.raw_response.get("data", []):
        outputs.append(investigation)

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == outputs_key_field
    assert response.outputs == outputs


@pytest.mark.parametrize(
    ("api_version", "data_path", "constants", "outputs_key_field", "endpoint", "outputs_prefix"),
    [
        (
            "V1",
            "get_investigation.json",
            ConstantsV1,
            "id",
            "idr/v1/investigations",
            "Rapid7InsightIDR.Investigation",
        ),
        (
            "V1",
            "empty_get_investigation.json",
            ConstantsV1,
            None,
            "idr/v1/investigations",
            None,
        ),
        (
            "V2",
            "get_investigation_v2.json",
            ConstantsV2,
            "rrn",
            "idr/v2/investigations/test",
            "Rapid7InsightIDR.Investigation",
        ),
    ],
)
def test_insight_idr_get_investigation(
    mock_client: Client,
    requests_mock,
    api_version,
    data_path,
    constants,
    outputs_key_field,
    endpoint,
    outputs_prefix,
) -> None:
    """
    Scenario: test get investigation
    Given:
     - User has provided valid credentials
    When:
     - insight_idr_get_investigation_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_get_investigation_command

    mock_response = util_load_json(f"test_data/{data_path}")
    requests_mock.get(f"https://{REGION}.api.insight.rapid7.com/{endpoint}", json=mock_response)

    response = insight_idr_get_investigation_command(
        client=mock_client,
        args={"api_version": api_version, "investigation_id": "test"},
        constants=constants,
    )

    assert response.outputs_prefix == outputs_prefix
    assert response.outputs_key_field == outputs_key_field
    assert response.outputs == response.raw_response


def test_close_investigation(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test close investigations
    Given:
     - User has provided valid credentials
     - User has provided valid times
    When:
     - insight_idr_close_investigations_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure the amount of ids that were closed
    """
    from Rapid7_InsightIDR import insight_idr_close_investigations_command

    mock_response = util_load_json("test_data/close_investigations_v2.json")
    requests_mock.post(
        f"https://{REGION}.api.insight.rapid7.com/idr/v2/investigations/bulk_close",
        json=mock_response,
    )

    args = {
        "start_time": "2018-06-06T16:56:42Z",
        "end_time": "2018-06-06T16:56:42Z",
        "source": "MANUAL",
        "disposition": "Undecided",
    }
    response = insight_idr_close_investigations_command(client=mock_client, args=args)
    assert isinstance(response.raw_response, dict)
    assert response.raw_response.get("num_closed", -1) == len(response.raw_response.get("ids", []))
    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == "id"


@pytest.mark.parametrize(
    ("api_version", "data_path", "constants", "outputs_key_field", "endpoint"),
    [
        ("V1", "assign_user.json", ConstantsV1, "id", "idr/v1/investigations/test/assignee"),
        (
            "V2",
            "get_investigation_v2.json",
            ConstantsV2,
            "rrn",
            "idr/v2/investigations/test/assignee",
        ),
    ],
)
def test_assign_user(
    mock_client: Client,
    requests_mock,
    api_version,
    data_path,
    constants,
    outputs_key_field,
    endpoint,
) -> None:
    """
    Scenario: test assign user to investigations
    Given:
     - User has provided valid credentials
     - User has provided valid email address
    When:
     - insight_idr_assign_user_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure email field is as expected
    """
    from Rapid7_InsightIDR import insight_idr_assign_user_command

    investigation_id = "test"
    email = "test@test.com"

    mock_response = util_load_json(f"test_data/{data_path}")
    requests_mock.put(
        f"https://{REGION}.api.insight.rapid7.com/{endpoint}",
        json=mock_response,
    )

    args = {
        "api_version": api_version,
        "investigation_id": investigation_id,
        "user_email_address": email,
    }
    response = insight_idr_assign_user_command(client=mock_client, args=args, constants=constants)
    assert isinstance(response.raw_response, list)
    if response.raw_response:
        for data in response.raw_response:
            for obj in data.get("data", []):
                assert obj.get("assignee", {}).get("email", "") == email

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == outputs_key_field


@pytest.mark.parametrize(
    ("api_version", "data_path", "constants", "outputs_key_field", "endpoint"),
    [
        ("V1", "set_status.json", ConstantsV1, "id", "idr/v1/investigations/test/status/OPEN"),
        (
            "V2",
            "get_investigation_v2.json",
            ConstantsV2,
            "rrn",
            "idr/v2/investigations/test/status/OPEN",
        ),
    ],
)
def test_set_status(
    mock_client: Client,
    requests_mock,
    api_version,
    data_path,
    constants,
    outputs_key_field,
    endpoint,
) -> None:
    """
    Scenario: test set status to investigations
    Given:
     - User has provided valid credentials
     - User has provided valid status
    When:
     - insight_idr_set_status_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure status field is as expected
    """
    from Rapid7_InsightIDR import insight_idr_set_status_command

    investigation_id = "test"
    status = "OPEN"

    mock_response = util_load_json(f"test_data/{data_path}")
    requests_mock.put(
        f"https://{REGION}.api.insight.rapid7.com/{endpoint}",
        json=mock_response,
    )

    args = {"api_version": api_version, "investigation_id": investigation_id, "status": status}
    response = insight_idr_set_status_command(client=mock_client, args=args, constants=constants)
    assert isinstance(response.raw_response, list)

    if response.raw_response:
        for data in response.raw_response:
            for obj in data.get("data", []):
                assert obj.get("status", "") == status

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == outputs_key_field


def test_insight_idr_add_threat_indicators(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test add indiactors to threat
    Given:
     - User has provided valid credentials
     - User has provided valid indicators
    When:
     - insight_idr_add_threat_indicators_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_add_threat_indicators_command

    mock_response = util_load_json("test_data/add_threat_indicators.json")
    requests_mock.post(
        f"https://{REGION}.api.insight.rapid7.com/idr/v1/customthreats/key/x/indicators/add",
        json=mock_response,
    )

    response = insight_idr_add_threat_indicators_command(mock_client, "x")

    outputs = []
    assert isinstance(response.raw_response, list)

    for threat in response.raw_response:
        outputs.append(threat.get("threat"))

    assert response.outputs_prefix == "Rapid7InsightIDR.Threat"
    assert response.outputs_key_field == "name"
    assert response.outputs == outputs


def test_insight_idr_replace_threat_indicators(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test replace indiactors to threat
    Given:
     - User has provided valid credentials
     - User has provided valid indicators
    When:
     - insight_idr_replace_threat_indicators_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_replace_threat_indicators_command

    mock_response = util_load_json("test_data/replace_threat_indicators.json")
    requests_mock.post(
        f"https://{REGION}.api.insight.rapid7.com/idr/v1/customthreats/key/x/indicators/replace",
        json=mock_response,
    )

    response = insight_idr_replace_threat_indicators_command(mock_client, "x")
    assert isinstance(response.raw_response, list)

    outputs = []
    for threat in response.raw_response:
        outputs.append(threat.get("threat"))

    assert response.outputs_prefix == "Rapid7InsightIDR.Threat"
    assert response.outputs_key_field == "name"
    assert response.outputs == outputs


def test_insight_idr_list_logs(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test list logs
    Given:
     - User has provided valid credentials
    When:
     - insight_idr_list_logs_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_list_logs_command

    mock_response = util_load_json("test_data/list_logs.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/log_search/management/logs", json=mock_response
    )

    response = insight_idr_list_logs_command(mock_client)

    outputs = []
    assert isinstance(response.raw_response, dict)
    for log in response.raw_response.get("logs", []):
        outputs.append(log)

    assert response.outputs_prefix == "Rapid7InsightIDR.Log"
    assert response.outputs_key_field == "id"
    assert response.outputs == outputs


def test_insight_idr_list_log_sets(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test list log sets
    Given:
     - User has provided valid credentials
    When:
     - insight_idr_list_log_sets_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_list_log_sets_command

    mock_response = util_load_json("test_data/list_log_sets.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/log_search/management/logsets", json=mock_response
    )

    response = insight_idr_list_log_sets_command(mock_client)
    assert isinstance(response.raw_response, dict)

    outputs = []
    for log in response.raw_response.get("logsets", []):
        outputs.append(log)

    assert response.outputs_prefix == "Rapid7InsightIDR.LogSet"
    assert response.outputs_key_field == "id"
    assert response.outputs == outputs


def test_insight_idr_download_logs(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test download logs
    Given:
     - User has provided valid credentials
     - User has provided valid logIDs
    When:
     - insight_idr_download_logs_command is called
    Then:
     - Ensure file type
    """
    from Rapid7_InsightIDR import insight_idr_download_logs_command

    mock_response = util_load_file("test_data/download_logs.txt")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/log_search/download/logs/x:y", text=mock_response
    )

    response = insight_idr_download_logs_command(mock_client, "x:y")

    assert (response.get("File", "")[-4:]) == ".log"


def test_insight_idr_query_log(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test query log
    Given:
     - User has provided valid credentials
     - User has provided valid logID
    When:
     - insight_idr_query_log_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_query_log_command

    mock_response = util_load_json("test_data/query_log_set.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/log_search/query/logs/x", json=mock_response
    )

    response = insight_idr_query_log_command(mock_client, "x", "", "", "")
    assert isinstance(response.raw_response, list)
    outputs = [event for result in response.raw_response for event in result.get("events", [])]

    assert response.outputs_prefix == "Rapid7InsightIDR.Event"
    assert response.outputs_key_field == "message"
    assert response.outputs == outputs
    assert len(outputs) == 1


def test_insight_idr_query_log_set(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test query log set
    Given:
     - User has provided valid credentials
     - User has provided valid logset ID
    When:
     - insight_idr_query_log_set_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output is as expected
    """
    from Rapid7_InsightIDR import insight_idr_query_log_set_command

    mock_response = util_load_json("test_data/query_log_set.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/log_search/query/logsets/x", json=mock_response
    )

    response = insight_idr_query_log_set_command(mock_client, "x", "", "", "")
    assert isinstance(response.raw_response, list)

    outputs = [event for result in response.raw_response for event in result.get("events", [])]

    assert response.outputs_prefix == "Rapid7InsightIDR.Event"
    assert response.outputs_key_field == "message"
    assert response.outputs == outputs
    assert len(outputs) == 1


@pytest.mark.parametrize(
    "end_point",
    [
        ("logsets"),
        ("logs"),
    ],
)
def test_insight_idr_query_log_with_pagination(
    mock_client: Client, requests_mock, end_point
) -> None:
    """
    Given:
        - User has provided logs_per_page argument
    When:
        - insight_idr_query_log_command or insight_idr_query_log_set_command is called
    Then:
        - Ensure pagination is working as expected
    """
    from Rapid7_InsightIDR import insight_idr_query_log_command, insight_idr_query_log_set_command

    commands = {"logsets": insight_idr_query_log_set_command, "logs": insight_idr_query_log_command}
    mock_response_callback = util_load_json("test_data/query_log_set_callback_with_pagination.json")
    mock_response_page_1 = util_load_json("test_data/query_log_set_page_1.json")
    mock_response_page_2 = util_load_json("test_data/query_log_set_page_2.json")
    mock_response_page_3 = util_load_json("test_data/query_log_set_page_3.json")

    base_url = f"https://{REGION}.api.insight.rapid7.com"

    requests_mock.get(f"{base_url}/log_search/query/{end_point}/x", json=mock_response_callback)
    requests_mock.get(
        f"{base_url}/query/logs/123?per_page=1&sequence_number=1", json=mock_response_page_1
    )
    requests_mock.get(
        f"{base_url}/query/logs/123?per_page=1&sequence_number=2", json=mock_response_page_2
    )
    requests_mock.get(
        f"{base_url}/query/logs/123?per_page=1&sequence_number=3", json=mock_response_page_3
    )

    response = commands[end_point](mock_client, "x", "", logs_per_page=1)
    assert isinstance(response.raw_response, list)

    outputs = [event for result in response.raw_response for event in result.get("events", [])]

    assert len(outputs) == 3
    assert response.outputs == outputs


@pytest.mark.parametrize(
    "end_point",
    [
        ("logsets"),
        ("logs"),
    ],
)
def test_insight_idr_query_log_with_callback(mocker, requests_mock, end_point) -> None:
    """
    Given:
        - User has provided valid logset ID or log key
    When:
        - insight_idr_query_log_command or insight_idr_query_log_set_command is called
            and callback is enabled
    Then:
        - Ensure callback is working as expected
    """
    from Rapid7_InsightIDR import (
        Client,
        insight_idr_query_log_command,
        insight_idr_query_log_set_command,
    )

    commands = {"logsets": insight_idr_query_log_set_command, "logs": insight_idr_query_log_command}
    mock_response_callback = util_load_json("test_data/query_log_set_callback.json")
    mock_response_callback_1 = util_load_json("test_data/query_log_set_callback_1.json")
    mock_response = util_load_json("test_data/query_log_set.json")

    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/log_search/query/{end_point}/x",
        json=mock_response_callback,
    )
    mocker.patch.object(
        Client, "query_log_callback", side_effect=[mock_response_callback_1, mock_response]
    )

    client = Client(
        base_url=f"https://{REGION}.api.insight.rapid7.com/",
        verify=False,
        headers={"Authentication": "apikey"},
        proxy=False,
        is_multi_customer=False,
    )
    response = commands[end_point](client, "x", "")
    assert isinstance(response.raw_response, list)
    outputs = [event for result in response.raw_response for event in result.get("events", [])]

    assert len(outputs) == 1
    assert response.outputs == outputs


def test_fetch_incidents(mock_client: Client, requests_mock) -> None:
    """
    Scenario: test fetch incidents
    Given:
     - User has provided valid credentials
     - User has provided valid last_run and first_time_fetch
     - User has provided valid max_fetch
    When:
     - insight_idr_query_log_set_command is called
    Then:
     - Ensure output is as expected
     - Ensure timestamp is as expected (+1 Miliseconds)
    """
    from Rapid7_InsightIDR import fetch_incidents

    mock_response = util_load_json("test_data/list_investigations.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/idr/v1/investigations", json=mock_response
    )

    last_fetch_timestamp = parse_date_range("1 day", to_timestamp=True)[0]
    last_run = {"last_fetch": last_fetch_timestamp}

    response = fetch_incidents(
        client=mock_client, max_fetch="1", last_run=last_run, first_fetch_time="1 day"
    )
    outputs = []
    for investigation in response[1]:
        outputs.append(investigation)

    assert last_fetch_timestamp + 1 == response[0]["last_fetch"]
    assert response[1] == [
        {
            "name": "Joe enabled account Joebob",
            "occurred": "2018-06-06T16:56:42.000Z",
            "rawJSON": outputs[0]["rawJSON"],
        },
        {
            "name": "Hello",
            "occurred": "2018-06-06T16:56:43.000Z",
            "rawJSON": outputs[1]["rawJSON"],
        },
    ]


def test_create_investigation(mock_client: Client, requests_mock) -> None:
    """
    Scenario: Test create investigation
    Given:
     - User has provided valid credentials
     - User has provided valid inputs
    When:
     - insight_idr_create_investigation_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure the outputs data
    """
    from Rapid7_InsightIDR import insight_idr_create_investigation_command

    mock_response = util_load_json("test_data/get_investigation_v2.json")
    requests_mock.post(
        f"https://{REGION}.api.insight.rapid7.com/idr/v2/investigations", json=mock_response
    )

    args = {
        "title": "test",
        "status": "CLOSED",
        "priority": "Unspecified",
        "disposition": "disposition",
    }
    response = insight_idr_create_investigation_command(client=mock_client, args=args)

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == "rrn"
    assert isinstance(response.outputs, dict)
    assert response.outputs.get("status") == "CLOSED"
    assert response.outputs.get("priority") == "UNSPECIFIED"


def test_update_investigation(mock_client: Client, requests_mock) -> None:
    """
    Scenario: Test update investigation
    Given:
     - User has provided valid credentials
     - User has provided valid inputs
    When:
     - insight_idr_update_investigation_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure the outputs data
    """
    from Rapid7_InsightIDR import insight_idr_update_investigation_command

    mock_response = util_load_json("test_data/get_investigation_v2.json")
    requests_mock.patch(
        f"https://{REGION}.api.insight.rapid7.com/idr/v2/investigations/test", json=mock_response
    )

    args = {
        "investigation_id": "test",
        "title": "test",
        "status": "Closed",
        "priority": "Unspecified",
        "disposition": "disposition",
    }
    response = insight_idr_update_investigation_command(client=mock_client, args=args)

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == "rrn"
    assert isinstance(response.outputs, dict)
    assert response.outputs.get("status") == "CLOSED"
    assert response.outputs.get("priority") == "UNSPECIFIED"


@pytest.mark.parametrize(
    ("args", "expected_len"),
    [
        ({"investigation_id": "test", "limit": "1", "all_results": "false"}, 1),
        ({"investigation_id": "test", "limit": "50", "all_results": "true"}, 4),
    ],
)
def test_insight_idr_get_investigation_alerts(
    requests_mock, mock_client: Client, args: dict[str, Any], expected_len: int
) -> None:
    """
    Scenario: Test get investigation alerts
    Given:
     - User has provided valid credentials
     - User has provided exist investigation ID
    When:
     - insight_idr_list_investigation_alerts_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
     - Ensure output length is as expected
    """
    from Rapid7_InsightIDR import insight_idr_list_investigation_alerts_command

    mock_response = util_load_json("test_data/get_investigation_alerts.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/idr/v2/investigations/test/alerts",
        json=mock_response,
    )

    response = insight_idr_list_investigation_alerts_command(
        client=mock_client,
        args=args,
    )

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == "rrn"
    assert isinstance(response.outputs, dict)
    alert_list = response.outputs["alert"]
    assert isinstance(alert_list, list)
    assert len(alert_list) == expected_len


def test_insight_idr_get_investigation_product_alerts(mock_client: Client, requests_mock) -> None:
    """
    Scenario: Test get investigation product alerts.
    Given:
     - User has provided valid credentials
     - User has provided exist investigation ID
    When:
     - insight_idr_list_investigation_product_alerts_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
    """
    from Rapid7_InsightIDR import insight_idr_list_investigation_product_alerts_command

    mock_response = util_load_json("test_data/get_investigation_product_alerts.json")
    requests_mock.get(
        f"https://{REGION}.api.insight.rapid7.com/idr/v2/investigations/test/rapid7-product-alerts",
        json=mock_response,
    )

    response = insight_idr_list_investigation_product_alerts_command(
        client=mock_client,
        args={"investigation_id": "test", "limit": "50", "all_results": "false"},
    )

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == "rrn"


@pytest.mark.parametrize(
    ("args", "endpoint", "data_path"),
    [
        ({"rrn": "test"}, "idr/v1/users/test", "get_user.json"),
        (
            {"index": "0", "page_size": "2", "limit": "50"},
            "idr/v1/users/_search",
            "search_users.json",
        ),
    ],
)
def test_insight_idr_list_user(
    requests_mock, mock_client: Client, args: dict[str, Any], endpoint: str, data_path: str
) -> None:
    """
    Scenario: Test list users
    Given:
     - User has provided valid credentials
    When:
     - insight_idr_list_users_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
    """
    from Rapid7_InsightIDR import insight_idr_list_users_command

    mock_response = util_load_json(f"test_data/{data_path}")
    requests_mock.get(f"https://{REGION}.api.insight.rapid7.com/{endpoint}", json=mock_response)
    requests_mock.post(f"https://{REGION}.api.insight.rapid7.com/{endpoint}", json=mock_response)

    response = insight_idr_list_users_command(
        client=mock_client,
        args=args,
    )

    assert response.outputs_prefix == "Rapid7InsightIDR.User"
    assert response.outputs_key_field == "rrn"


def test_insight_idr_search_investigation(mock_client: Client, requests_mock) -> None:
    """
    Scenario: Test search investigation
    Given:
     - User has provided valid credentials
    When:
     - insight_idr_search_investigation_command is called
    Then:
     - Ensure prefix is correct
     - Ensure key field is correct
    """
    from Rapid7_InsightIDR import insight_idr_search_investigation_command

    mock_response = util_load_json("test_data/search_investigation.json")
    requests_mock.post(
        f"https://{REGION}.api.insight.rapid7.com/idr/v2/investigations/_search", json=mock_response
    )

    response = insight_idr_search_investigation_command(
        client=mock_client,
        args={"index": "0", "page_size": "2", "limit": "50"},
    )

    assert response.outputs_prefix == "Rapid7InsightIDR.Investigation"
    assert response.outputs_key_field == "rrn"


def test_handle_sort():
    """
    Scenario: Test handle sort.
    Given:
     - User has provided correct input.
    When:
     - handle_sort is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import handle_sort

    result = handle_sort(args={"sort": "test,test2", "sort_direction": "asc"})
    assert len(result) == 2
    assert list(result[0].keys()) == ["field", "order"]
    assert result[0]["field"] == "test"
    assert result[0]["order"] == "ASC"


def test_handle_user_search():
    """
    Scenario: Test handle user search.
    Given:
     - User has provided wrong input (didn't insert search_operator).
    When:
     - handle_user_search is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import USER_SEARCH, handle_user_search

    with pytest.raises(ValueError) as error_info:
        handle_user_search(
            args={"first_name": "test,test2"},
            filter=USER_SEARCH,
        )

    assert str(object=error_info.value) == "Please insert search_operator in order to use filters."


def test_handle_investigation_search():
    """
    Scenario: Test handle investigation search.
    Given:
     - investigation has provided correct input.
    When:
     - handle_investigation_search is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import INVESTIGATION_SEARCH, handle_investigation_search

    result = handle_investigation_search(
        args={"priority": "test,test2", "actor_asset_hostname": "test,test2"},
        filter=INVESTIGATION_SEARCH,
    )
    assert len(result) == 4
    assert list(result[0].keys()) == ["field", "operator", "value"]
    assert result[0]["field"] == "actor_asset_hostname"
    assert result[0]["operator"] == "CONTAINS"
    assert result[3]["field"] == "priority"
    assert result[3]["operator"] == "EQUALS"
    assert result[0]["value"] == "test"


@pytest.mark.parametrize(
    ("text", "is_lower", "expected"),
    [
        ("aaa aa bb", True, "aaa_aa_bb"),
        ("A a Aa", True, "a_a_aa"),
        ("aaa aa", False, "AAA_AA"),
    ],
)
def test_to_snake_case(text, is_lower, expected):
    """
    Scenario: Test to_snake_case.
    Given:
     - User has provided correct input.
    When:
     - to_snake_case is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import to_snake_case

    result = to_snake_case(text=text, is_lower=is_lower)
    assert result == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("aaa aa bb", "AaaAaBb"),
        ("A a Aa", "AAAa"),
    ],
)
def test_to_camel_case(text, expected):
    """
    Scenario: Test to_camel_case.
    Given:
     - User has provided correct input.
    When:
     - to_camel_case is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import to_camel_case

    result = to_camel_case(text=text)
    assert result == expected


@pytest.mark.parametrize(
    ("text"),
    [
        ("2018-06-06T16:56:42Z"),
        ("2001-12-06T16:56:42Z"),
    ],
)
def test_raise_on_invalid_time(text):
    """
    Scenario: Test raise_on_invalid_time.
    Given:
     - User has provided correct input.
    When:
     - raise_on_invalid_time is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import raise_on_invalid_time

    result = raise_on_invalid_time(time_str=text)
    assert result


@pytest.mark.parametrize(
    ("text"),
    [
        ("2018-06-06T16:5611:42Z"),
    ],
)
def test_fail_raise_on_invalid_time(text):
    """
    Scenario: Test raise_on_invalid_time failed.
    Given:
     - User has provided wrong input.
    When:
     - raise_on_invalid_time is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import raise_on_invalid_time

    with pytest.raises(ValueError) as error_info:
        raise_on_invalid_time(time_str=text)
    assert f'"{text}" is not a valid date' in str(object=error_info.value)


@pytest.mark.parametrize(
    ("page_size", "limit"),
    [
        ("10", "20"),
        (None, "10"),
    ],
)
def test_get_pagination_size(page_size, limit):
    """
    Scenario: Test get_pagination_size.
    Given:
     - User has provided correct input.
    When:
     - get_pagination_size is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import get_pagination_size

    result = get_pagination_size(page_size=page_size, limit=limit)
    assert result == "10"


def test_generate_product_alerts_readable():
    """
    Scenario: Test generate_product_alerts_readable.
    Given:
     - User has provided correct input.
    When:
     - generate_product_alerts_readable is called
    Then:
     - Ensure return values correct.
    """
    from Rapid7_InsightIDR import generate_product_alerts_readable

    response = [
        {
            "insight_agent_details": [
                {
                    "agent_action_taken": "Block",
                    "alert_id": "972bef1b-72c9-48d2-9e33-ca9056cfe086",
                    "alert_type": "Endpoint Prevention",
                }
            ],
            "threat_command_details": {
                "alert_id": "620ba5123b2aff3303ed65f3",
                "alert_type": "Phishing",
                "applicable_close_reasons": ["ProblemSolved", "InformationalOnly", "Other"],
            },
            "type": "THREAT_COMMAND",
        },
    ]
    results = [
        {
            "agent_action_taken": "Block",
            "alert_id": "972bef1b-72c9-48d2-9e33-ca9056cfe086",
            "alert_type": "Endpoint Prevention",
            "name": "THREAT_COMMAND",
        },
        {
            "alert_id": "620ba5123b2aff3303ed65f3",
            "alert_type": "Phishing",
            "applicable_close_reasons": ["ProblemSolved", "InformationalOnly", "Other"],
            "name": "THREAT_COMMAND",
        },
    ]
    result = generate_product_alerts_readable(response=response)
    assert result == results

import json
import os
from http import HTTPStatus
from urllib.parse import urljoin
from datetime import datetime
from typing import Any
import pytest
from CommonServerPython import *
from DataBee import (
    Client,
    SearchConfiguration,
    SEARCH_CONFIGURATIONS,
    SearchTypes,
)


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
    """Create a test client for DataBee.

    Returns:
        Client: DataBee Client.
    """
    return Client(
        base_url="http://1.1.1.1/",
        username=None,
        password="test",
        verify=False,
        proxy=False,
    )


@pytest.mark.parametrize(
    ("args", "settings", "jsonpath", "query"),
    (
        (
            {"page": "0", "limit": 10, "query": "impact contains High"},
            SEARCH_CONFIGURATIONS[SearchTypes.DEVICE.value],
            "search_device.json",
            "impact+contains+High",
        ),
        (
            {"page": "0", "limit": 10, "hostname": "test"},
            SEARCH_CONFIGURATIONS[SearchTypes.DEVICE.value],
            "search_device.json",
            "hostname+contains+test",
        ),
        (
            {"page": "0", "limit": 10, "query": "test"},
            SEARCH_CONFIGURATIONS[SearchTypes.DEVICE.value],
            "search_device.json",
            "test",
        ),
        (
            {"page": "0", "limit": 10, "query": "test"},
            SEARCH_CONFIGURATIONS[SearchTypes.FINDING.value],
            "search_finding.json",
            "test",
        ),
    ),
)
def test_search_command(
    requests_mock,
    mock_client: Client,
    args: dict[str, Any],
    settings: SearchConfiguration,
    jsonpath: str,
    query: str,
):
    """
    Scenario: Search for DataBee tables.
    Given:
     - User has provided correct parameters.
    When:
     - databee-user-search
     - databee-device-search
     - databee-finding-search
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs type is list.
    """
    from DataBee import search_command

    json_response = load_mock_response(jsonpath)
    url = urljoin(
        mock_client._base_url,
        f"/search/{settings.type.value}?query={query}&offset=0&limit=10",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = search_command(mock_client, args, settings, [])
    assert result.outputs_prefix == f"DataBee.{settings.output_prefix}"
    assert result.outputs_key_field == "uid"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) <= 50 if result.outputs else True


def test_get_endpoint_command(
    requests_mock,
    mock_client: Client,
):
    """
    Scenario: Search endpoints.
    Given:
     - User has provided correct parameters.
    When:
     - endpint
    Then:
     - Ensure that output prefix correct.
     - Ensure that output key field correct.
     - Ensure that outputs type is list.
    """
    from DataBee import get_endpoint_command

    json_response = load_mock_response("search_device.json")
    url = urljoin(
        mock_client._base_url,
        "/search/device?query=ip+in+%281.2.3.4%29&offset=0",
    )
    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    result = get_endpoint_command(mock_client, {"ip": "1.2.3.4"})
    assert isinstance(result, list)
    assert len(result) == 2
    assert isinstance(result[0].indicator, Common.Endpoint)
    assert result[0].indicator.os == "Android"


def test_generate_command_results():
    """
    Scenario: Generate command results.
    Given:
     - User has provided correct parameters.
    When:
     - generate_command_results called.
    Then:
     - Ensure that the outputs prefix is correct.
     - Ensure that the outputs key field is correct.
    """
    from DataBee import generate_command_results

    result = generate_command_results(
        title="test",
        outputs_prefix="test",
        outputs_key_field="test",
        headers=[],
        outputs=[],
        raw_response=[],
        readable_outputs={},
    )

    assert result.outputs_prefix == "DataBee.test"
    assert result.outputs_key_field == "test"


def test_parse_response():
    """
    Scenario: Parse DataBee response to XSOAR outputs.
    Given:
     - User has provided correct parameters.
    When:
     - parse_response called.
    Then:
     - Ensure that the output key appears.
    """
    from DataBee import parse_response

    json_data = load_mock_response("search_device.json")
    result = parse_response(
        type=SearchTypes.DEVICE.value,
        data=json_data["results"],
        keys=SEARCH_CONFIGURATIONS[SearchTypes.DEVICE.value].output_keys,
        additional_context=[],
    )
    assert "name" in list(result[0].keys())


@pytest.mark.parametrize(
    ("operator", "key", "value", "expected"),
    (
        (
            None,
            "test",
            "test",
            "test contains test",
        ),
        (
            "Not In",
            "test",
            "test",
            "test notin (test)",
        ),
        (
            "In",
            "test",
            "test",
            "test in (test)",
        ),
        (
            "In",
            "test",
            "test,test2",
            "test in (test,test2)",
        ),
        (
            "between",
            "test",
            "test1,test2",
            "test between test1,test2",
        ),
        (
            "Not In",
            "test",
            "test1,test2",
            "test notin (test1,test2)",
        ),
        (
            "In",
            "test",
            None,
            None,
        ),
    ),
)
def test_create_query(
    operator: str,
    key: str,
    value: str,
    expected: str,
):
    """
    Scenario: Create DataBee query.
    Given:
     - User has provided correct parameters.
    When:
     - create_query called.
    Then:
     - Ensure that the result as expected.
    """
    from DataBee import create_query

    result = create_query(operator, key, value)
    assert result == expected


@pytest.mark.parametrize(
    ("search_type", "args", "expected"),
    (
        (
            SearchTypes.USER.value,
            {"query": "I'm using query"},
            "I'm using query",
        ),
        (
            SearchTypes.USER.value,
            {"start_time": "2024-03-26T11:03:18Z", "end_time": "2024-03-27T11:03:18Z"},
            "start_time between 03/26/2024 11:03,03/27/2024 11:03",
        ),
        (
            SearchTypes.USER.value,
            {
                "email_address": "test",
                "full_name": "test",
                "name": "test",
                "hostname": "test",
                "mac": "test",
                "ip": "test",
                "analytic_name": "test",
                "confidence": "test",
                "device_environment": "test",
                "device_risk_level": "test",
                "impact": "test",
                "risk_level": "test",
                "severity": "test",
            },
            "email_addr contains test and full_name contains test and name contains test",
        ),
        (
            SearchTypes.DEVICE.value,
            {
                "email_address": "test",
                "full_name": "test",
                "name": "test",
                "hostname": "test",
                "mac": "test",
                "ip": "test",
                "analytic_name": "test",
                "confidence": "test",
                "device_environment": "test",
                "device_risk_level": "test",
                "impact": "test",
                "risk_level": "test",
                "severity": "test",
            },
            "hostname contains test and mac contains test and name contains test and ip contains test",
        ),
        (
            SearchTypes.FINDING.value,
            {
                "email_address": "test",
                "full_name": "test",
                "name": "test",
                "hostname": "test",
                "mac": "test",
                "ip": "test",
                "analytic_name": "test",
                "confidence": "test",
                "device_environment": "test",
                "device_risk_level": "test",
                "impact": "test",
                "risk_level": "test",
                "severity": "test",
            },
            "analytic.name in (test) and confidence contains test and device.environment in (test) and device.risk_level "
            + "in (test) and impact contains test and risk_level contains test and severity contains test and "
            + "metadata.product.name in databee",
        ),
    ),
)
def test_build_full_query(
    search_type: SearchTypes,
    args: dict[str, Any],
    expected: str,
):
    """
    Scenario: Build full query.
    Given:
     - User has provided correct parameters.
    When:
     - build_full_query called.
    Then:
     - Ensure that the result as expected.
    """
    from DataBee import build_full_query

    result = build_full_query(search_type, args)
    assert result == expected


@pytest.mark.parametrize(
    ("page", "limit", "page_size", "excepted"),
    (
        ("1", "3", "5", (5, 5)),
        ("1", "3", None, (3, 0)),
        ("0", "3", "2", (2, 0)),
        ("1", "3", "2", (2, 2)),
    ),
)
def test_get_pagination_args(page: str, limit: str, page_size: str, excepted: tuple[int, int]):
    """
    Scenario: Get pagination args.
    Given:
     - User has provided correct parameters.
    When:
     - get_pagination_args called.
    Then:
     - Ensure that the result as expected.
    """
    from DataBee import get_pagination_args

    result = get_pagination_args(page=page, limit=limit, page_size=page_size)
    assert result == excepted


@pytest.mark.parametrize(
    ("params", "query"),
    (
        (
            {
                "first_fetch": "2023-03-19T06:06:08.488Z",
                "max_fetch": "2",
            },
            "?query=start_time+between+03%2F19%2F2023+06%3A06%2C01%2F01%2F2024+00%3A00+and+metadata.product.name+in+databee",
        ),
        (
            {
                "first_fetch": "2023-03-19T06:06:08.488Z",
                "max_fetch": "2",
                "severity": "high",
                "impact": "low",
            },
            "?query=start_time+between+03%2F19%2F2023+06%3A06%2C01%2F01%2F2024+00%3A00+and+metadata.product.name+in+databee+and"
            + "+severity+contains+high+and+impact+contains+low",
        ),
    ),
)
def test_fetch_incidents(
    requests_mock,
    mock_client: Client,
    params: dict[str, Any],
    query: str,
):
    """
    Scenario: Fetch incidents.
    Given:
     - User has provided correct parameters.
    When:
     - fetch_incidents called.
    Then:
     - Ensure the len of the incidents.
     - Ensure the new last run.
    """
    from DataBee import fetch_incidents

    json_response = load_mock_response("search_finding.json")
    url = urljoin(
        mock_client._base_url,
        f"/search/{SearchTypes.FINDING.value}{query}&offset=0&limit=2",
    )
    second_url = urljoin(
        mock_client._base_url,
        f"/search/{SearchTypes.FINDING.value}{query}&offset=2&limit=2",
    )
    second_json_response = load_mock_response("search_finding_empty.json")

    requests_mock.get(url=url, json=json_response, status_code=HTTPStatus.OK)
    requests_mock.get(second_url, json=second_json_response, status_code=HTTPStatus.OK)

    _, last_run = fetch_incidents(
        client=mock_client,
        args={},
        params=params,
        current_time=datetime(2024, 1, 1, 0, 0, 0),
    )

    assert last_run == {"time": "2024-01-01T00:00:00.000Z"}

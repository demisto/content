"""
Unit tests for Vectra Event Collector
"""

import pytest
from pytest_mock import MockerFixture
from VectraEventCollector import (
    VectraClient,
    is_eod,
    test_module,
    DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT,
    AUDIT_START_TIMESTAMP_FORMAT,
    DETECTION_FIRST_TIMESTAMP_FORMAT,
    get_detections_cmd,
    get_audits_cmd,
    get_events,
    fetch_events,
)
from typing import Dict, Any
import json
from datetime import datetime
from pathlib import Path
from CommonServerPython import *
from hypothesis import given, strategies as st

""" Constants """
BASE_URL = "mock://dev.vectra.ai"
PASSWORD = "9455w0rd"
client = VectraClient(url=BASE_URL, api_key=PASSWORD)


def load_json(path: Path):
    with open(path, mode="r", encoding="utf-8") as f:
        return json.load(f)


AUDITS: Dict[str, Any] = load_json(Path("./test_data/audits.json"))
DETECTIONS: Dict[str, Any] = load_json(Path("./test_data/search_detections.json"))
endpoints = load_json(Path("./test_data/endpoints.json"))
no_access_endpoints = load_json(Path("./test_data/endpoints_no_detection_audits.json"))

""" VectraClient Tests """


@pytest.mark.parametrize(
    "endpoints,expected",
    [
        ({"detections", f"{BASE_URL}/detections", "audits", f"{BASE_URL}/audits"}, True),
        ({"detections", f"{BASE_URL}/detections"}, False),
        ({"ep1", f"{BASE_URL}/ep1"}, False),
        ({}, False),
    ],
)
def test_auth(mocker: MockerFixture, endpoints: Dict[str, str], expected: bool):

    """
    Given:
        - A Vectra client.
    When:
        - Case A: The returned endpoints from the API root are the required ones.
        - Case B: The returned endpoints from the API root are missing 'audits'.
        - Case C: The returned endpoints from the API root are missing 'audits' and 'detections'.
        - Case D: The returned endpoints from the API root is empty.
    Then:
        - Case A: The authentication should succeed
        - Case B: The authentication should fail
        - Case C: The authentication should fail
        - Case D: The authentication should fail
    """

    mocker.patch.object(client, "get_endpoints", return_value=endpoints)
    endpoints = client.get_endpoints()

    assert all(ep in endpoints for ep in client.endpoints) == expected


@given(st.text())
def test_create_headers(token: str):

    """
    Given:
        - A Vectra client.
    When:
        - A token is supplied.
    Then:
        - Authentication headers match.
    """

    client = VectraClient("url.dev,", api_key=token)

    actual = client._create_headers()
    expected = {"Content-Type": "application/json", "Authorization": f"Token {token}"}

    assert "Content-Type" in actual.keys()
    assert "Authorization" in actual.keys()

    assert actual == expected


@pytest.mark.parametrize(
    "endpoints,expected",
    [(endpoints, "ok")],
)
def test_test_module(mocker: MockerFixture, endpoints: Dict[str, str], expected: str):
    """
    Given
            A dictionary of endpoints
    When
            Case A: Calling test-module with list of endpoints which include detections and audits
    Then
            Make sure that result succeeds or not.
    """

    mocker.patch.object(client, "_http_request", return_value=endpoints)
    actual = test_module(client)
    assert expected in actual


def test_test_module_exception(mocker: MockerFixture):
    # TODO docstring

    mocker.patch.object(
        client,
        "_http_request",
        side_effect=DemistoException(
            f"""User doesn't have access to endpoints {client.endpoints}, only to {','.join(list(no_access_endpoints.keys()))}.
                    Check with your Vectra account administrator."""
        ),
    )

    with pytest.raises(DemistoException) as e:
        test_module(client)

    assert "User doesn't have access to endpoints" in str(e.value)
    # assert


def test_get_detections(mocker: MockerFixture):
    """
    Test Vectra client `get_detections` method.
    """

    first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

    mocker.patch.object(client, "_http_request", return_value=DETECTIONS)
    response: Dict[str, Any] = client.get_detections(first_timestamp)

    assert isinstance(response, dict)
    assert not client.max_fetch < response.get("count")


def test_get_audits(mocker: MockerFixture):
    """
    Test Vectra client `get_audits` method.
    """

    start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

    mocker.patch.object(client, "_http_request", return_value=AUDITS)
    response: Dict[str, Any] = client.get_audits(start)

    assert isinstance(response, dict)
    assert not client.max_fetch < len(response.get("audits"))


""" Command Tests """


@pytest.mark.parametrize(
    "detections,audits",
    [(DETECTIONS, AUDITS), ({}, {}), (DETECTIONS, {}), ({}, AUDITS)],
)
class TestCommands:
    def test_get_detections_cmd(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Test `vectra-get-events` method detections part.
        """

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

        mocker.patch.object(client, "_http_request", return_value=DETECTIONS)
        cmd_res, detections = get_detections_cmd(client, first_timestamp)

        assert len(cmd_res.outputs) == len(detections)

    def test_get_audits_cmd(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Test `vectra-get-events` method audits part.
        """

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

        mocker.patch.object(client, "_http_request", return_value=AUDITS)
        cmd_res, audits = get_audits_cmd(client, first_timestamp)

        assert len(cmd_res.outputs) == len(audits)

    def test_get_events(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Test the `vectra-get-events` command.

        Given:
            - Detections and Audits raw responses.
        When:
            - Case A: Both detections and audits are returned.
            - Case B: Both detections and audits are empty.
            - Case C: Detections are returned, audits is empty.
            - Case D: Audts are returned, detections is empty.
        Then:
            - The `CommandResults::outputs` of detections are equal to the ones raw response.
            - The `CommandResults::outputs` of audits are equal to the ones raw response.
        """

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)

        detection_res, detections_actual, audits_res, audits_actual = get_events(
            client, datetime.now()
        )

        assert detection_res.outputs == detections_actual
        assert audits_res.outputs == audits_actual

    @pytest.mark.freeze_time("1970-01-01 00:00:00")
    def test_first_fetch(
        self, mocker: MockerFixture, freezer, detections: Dict[str, Any], audits: Dict[str, Any]
    ):

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)

        detections_actual, audits_actual, next_fetch = fetch_events(
            client, first_timestamp, start, is_first_fetch=True
        )

        if detections.get("results"):
            assert next_fetch.get("first_timestamp") == "2023-02-15T0217"

        if audits.get("audits"):
            next_fetch.get("start") == datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

    @pytest.mark.freeze_time("2023-03-01 00:00:00")
    def test_not_first_fetch_is_eod(
        self, mocker: MockerFixture, freezer, detections: Dict[str, Any], audits: Dict[str, Any]
    ):

        pass


""" Helper Functions Tests """


@pytest.mark.parametrize(
    "dt,expected",
    [
        (datetime(2023, 2, 22, 10, 55, 13), False),
        (datetime(2023, 2, 23, 00, 00, 13), False),
        (datetime(2023, 2, 23, 23, 59, 13), True),
    ],
)
def test_is_eod(dt: datetime, expected: bool):

    """
    Test the End-of-Day method.

    Given:
        - A `datetime`.
    When:
        - Case A: The time is 10:55.
        - Case B: The time is 00:00.
        - Case C: The time is 23:59.
    Then:
        - Case A: Method should return `False`.
        - Case B: Method should return `False`.
        - Case C: Method should return `True`.
    """

    assert is_eod(dt) == expected

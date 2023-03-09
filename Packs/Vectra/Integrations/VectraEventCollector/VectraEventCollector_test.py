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
    DETECTION_NEXT_RUN_KEY,
    AUDIT_NEXT_RUN_KEY,
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
from freezegun import freeze_time

""" Constants """
BASE_URL = "mock://dev.vectra.ai"
PASSWORD = "9455w0rd"
client = VectraClient(url=BASE_URL, api_key=PASSWORD)


def load_json(path: Path):
    with open(path, mode="r", encoding="utf-8") as f:
        return json.load(f)


AUDITS: Dict[str, Any] = load_json(Path("./test_data/audits.json"))
DETECTIONS: Dict[str, Any] = load_json(Path("./test_data/search_detections.json"))

""" VectraClient Tests """


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


def test_test_module(mocker: MockerFixture):
    """
    Given
    - A dictionary of endpoints
    When
    - Calling ``test-module``.
    Then
    - Make sure that result succeeds.
    """

    mocker.patch.object(client, "get_audits", return_value=AUDITS)
    mocker.patch.object(client, "get_detections", return_value=DETECTIONS)
    actual = test_module(client)
    assert "ok" in actual


def test_test_module_exception(mocker: MockerFixture):

    """
    Given
    - A dictionary of endpoints
    When
    - Calling ``test-module`` with an ``Exception`` side effect.
    Then
    - Make sure that result fails.
    """

    mocker.patch.object(
        client,
        "_http_request",
        side_effect=Exception("test module failed"),
    )

    with pytest.raises(Exception) as e:
        test_module(client)

    assert "test module failed" in str(e.value)


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

    @freeze_time("1970-01-01 00:00:00")
    def test_first_fetch(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):

        """
        Given:
            - Fetching for the first time.
        When:
            - Case A: Detections and Audits were fetched.
            - Case B: No Detections nor Audits were fetched.
            - Case C: Detections were fetched, Audits were not fetched.
            - Case D: Detections were not fetched, Audits were fetched.
        Then:
            - Case A: Detections next fetch will be set to now + 1 minute, audits next fetch will be set to today.
            - Case B: Detections next fetch will be set to last fetched detections, audits next fetch will be set to today.
            - Case C: Same as Case A.
            - Case D: Same as Case B.
        """

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)

        detections_actual, audits_actual, next_fetch = fetch_events(
            client, first_timestamp, start, is_first_fetch=True
        )

        if detections:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == (
                datetime.strptime(
                    detections_actual[0].get(DETECTION_NEXT_RUN_KEY),
                    DETECTION_FIRST_TIMESTAMP_FORMAT,
                )
                + timedelta(minutes=1)
            ).strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        else:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == datetime.now().strftime(
                DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
            )

        assert next_fetch.get(AUDIT_NEXT_RUN_KEY) == datetime.now().strftime(
            AUDIT_START_TIMESTAMP_FORMAT
        )

    @freeze_time("1970-01-01 23:59:00")
    def test_not_first_fetch_is_eod(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Given:
            - Not the first fetch.
            - Is the end of the day.
        When:
            - Case A: Detections and Audits were fetched.
            - Case B: No Detections nor Audits were fetched.
            - Case C: Detections were fetched, Audits were not fetched.
            - Case D: Detections were not fetched, Audits were fetched.
        Then:
            - Case A: Detections next fetch will be set to now + 1 minute, audits next fetch will be set to today.
            - Case B: Detections next fetch will be set to last fetched detections, audits next fetch will be set to today.
            - Case C: Same as Case A.
            - Case D: Same as Case B.
        """

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)

        detections_actual, audits_actual, next_fetch = fetch_events(
            client, first_timestamp, start, is_first_fetch=False
        )

        if audits:
            assert len(audits_actual) == len(audits.get("audits"))

        if detections:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == (
                datetime.strptime(
                    detections_actual[0].get(DETECTION_NEXT_RUN_KEY),
                    DETECTION_FIRST_TIMESTAMP_FORMAT,
                )
                + timedelta(minutes=1)
            ).strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        else:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == datetime.now().strftime(
                DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
            )

    @freeze_time("1970-01-01 00:00:01")
    def test_not_first_fetch_is_not_eod(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Given:
            - Not the first fetch.
            - Is not the end of the day.
        When:
            - Case A: Detections and Audits are there to be fetched.
            - Case B: No Detections nor Audits are there to be fetched.
            - Case C: Detections were fetched, Audits were not there to be fetched.
            - Case D: Detections were not there to be fetched, Audits are there to be fetched.
        Then:
            - All Cases: No audits are fetched.
            - Case A: Detections next fetch will be set to now + 1 minute.
            - Case B: Detections next fetch will be set to last fetched detection first_timestamp.
            - Case C: Same as Case A.
            - Case D: Same as Case B.
        """

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)

        detections_actual, audits_actual, next_fetch = fetch_events(
            client, first_timestamp, start, is_first_fetch=False
        )

        assert not audits_actual

        # if audits:
        #     assert len(audits_actual) == len(audits.get("audits"))

        if detections:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == (
                datetime.strptime(
                    detections_actual[0].get(DETECTION_NEXT_RUN_KEY),
                    DETECTION_FIRST_TIMESTAMP_FORMAT,
                )
                + timedelta(minutes=1)
            ).strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        else:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == datetime.now().strftime(
                DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
            )


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

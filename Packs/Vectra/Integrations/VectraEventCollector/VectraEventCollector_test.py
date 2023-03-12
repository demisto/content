"""
Unit tests for Vectra Event Collector
"""

import pytest
from pytest_mock import MockerFixture
from VectraEventCollector import (
    VectraClient,
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
    get_audits_to_send,
)
from typing import Dict, Any
import json
from datetime import datetime
from pathlib import Path
from CommonServerPython import *
from hypothesis import given, strategies as st
from freezegun import freeze_time
from pprint import pprint

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

        mocker.patch.object(client, "get_detections", return_value=detections)
        cmd_res = get_detections_cmd(client, first_timestamp)

        if detections:
            assert len(cmd_res.outputs) == len(detections.get("results"))
        else:
            assert "No detections found" in cmd_res.readable_output

    def test_get_audits_cmd(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Test `vectra-get-events` method audits part.
        """

        first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

        mocker.patch.object(client, "get_audits", return_value=audits)
        cmd_res = get_audits_cmd(client, first_timestamp)

        if audits:
            assert len(cmd_res.outputs) == len(audits.get("audits"))
        else:
            assert "No audits found" in cmd_res.readable_output

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

        detection_res, audits_res = get_events(client, datetime.now())

        assert detection_res.outputs == detections.get("results")
        assert audits_res.outputs == audits.get("audits")

    @freeze_time("1970-01-01 00:00:00")
    def test_first_fetch(
        self,
        mocker: MockerFixture,
        detections: Dict[str, Any],
        audits: Dict[str, Any],
    ):

        """
        Given:
            - Fetching for the first time, first_fetch set to default (3 days)
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

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)
        mocker.patch.object(demisto, "getLastRun", return_value={})

        detections_actual, audits_actual, next_fetch = fetch_events(client)

        if detections_actual:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == (
                datetime.strptime(
                    detections_actual[0].get(DETECTION_NEXT_RUN_KEY),
                    DETECTION_FIRST_TIMESTAMP_FORMAT,
                )
                + timedelta(minutes=1)
            ).strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)
        else:
            assert next_fetch.get(DETECTION_NEXT_RUN_KEY) == (
                datetime.now() + timedelta(days=-3)
            ).strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

        if audits_actual:
            assert next_fetch.get(AUDIT_NEXT_RUN_KEY) == AUDITS.get("audits")[-1].get(
                "vectra_timestamp"
            )
        else:
            assert next_fetch.get(AUDIT_NEXT_RUN_KEY) == "0"

    @freeze_time("2023-02-19 00:00:13")
    def test_not_first_fetch(
        self, mocker: MockerFixture, detections: Dict[str, Any], audits: Dict[str, Any]
    ):
        """
        Given:
            - Not the first fetch.
            - The frozen date is timestamp 1676764813, the 2nd audit from the list.
        When:
            - Case A: Detections and 3 Audits were fetched.
            - Case B: No Detections nor Audits were fetched.
            - Case C: Detections were fetched, Audits were not fetched.
            - Case D: Detections were not fetched, 3 Audits were fetched.
        Then:
            - Case A: Detections next fetch will be set to now + 1 minute, audits next fetch will to last audit timestamp.
            - Case B: Detections next fetch will be set to last fetched detections,
                        audits next fetch will be set to last audit timestamp.
            - Case C: Same as Case A.
            - Case D: Same as Case B.
        """

        mocker.patch.object(client, "get_detections", return_value=detections)
        mocker.patch.object(client, "get_audits", return_value=audits)
        mocker.patch.object(
            demisto,
            "getLastRun",
            return_value={
                DETECTION_NEXT_RUN_KEY: datetime.now().strftime(
                    DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT
                ),
                AUDIT_NEXT_RUN_KEY: str(datetime.now().timestamp()),
            },
        )

        detections_actual, audits_actual, next_fetch = fetch_events(client)

        if audits_actual:
            assert len(audits_actual) == 3
            assert next_fetch.get(AUDIT_NEXT_RUN_KEY) == AUDITS.get("audits")[-1].get(
                "vectra_timestamp"
            )

        if detections_actual:
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
    "audits",
    [(AUDITS.get("audits")), ([])],
)
def test_get_audits_to_send_first_fetch(audits: List[Dict[str, Any]]):
    """
    Given: audits returned from the endpoint.

    When:
        - Case A: 4 Audits returned.
        - Case B: No audits returned.

    Then:
        - Case A: 4 audits returned.
        - Case B: No audits returned.

    """

    actual = get_audits_to_send(audits, True, None)

    assert actual == audits


@pytest.mark.parametrize(
    "audits,prev_fetch_ts_str,expected",
    [
        (AUDITS.get("audits"), "0", AUDITS.get("audits")),
        (AUDITS.get("audits"), "1676764803", AUDITS.get("audits")[1:]),
        ([], "0", []),
        ([], "1676764803", []),
    ],
)
def test_get_audits_to_send_not_first_fetch(
    audits: List[Dict[str, Any]], prev_fetch_ts_str: str, expected: List[Dict[str, Any]]
):
    """
    Given: audits returned from the endpoint and it's not a first fetch.

    When:
        - Case A: 4 Audits returned, .
        - Case B: No audits returned.

    Then:
        - Case A: 4 audits returned.
        - Case B: No audits returned.

    """

    actual = get_audits_to_send(audits, False, prev_fetch_ts_str)

    assert actual == expected

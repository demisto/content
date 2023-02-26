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
    get_detections_cmd,
    get_audits_cmd,
)
from typing import Dict, Any
import json
from datetime import datetime
from pathlib import Path
from CommonServerPython import *

""" Constants """
BASE_URL = "mock://dev.vectra.ai"
PASSWORD = "9455w0rd"
client = VectraClient(url=BASE_URL, api_key=PASSWORD)


def load_json(path: Path):
    with open(path, mode="r", encoding="utf-8") as f:
        return json.load(f)


AUDITS = load_json(Path("./test_data/audits.json"))
DETECTIONS = load_json(Path("./test_data/search_detections.json"))
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


def test_create_headers():

    """
    Given:
        - A Vectra client.
    When:
        - A token is supplied.
    Then:
        - Authentication headers match.
    """

    actual = client._create_headers()
    expected = {"Content-Type": "application/json", "Authorization": f"Token {PASSWORD}"}

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


def test_test_module_exception(mocker):
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
    # TODO docstring

    first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

    mocker.patch.object(client, "_http_request", return_value=DETECTIONS)
    response: Dict[str, Any] = client.get_detections(first_timestamp)

    assert isinstance(response, dict)
    assert not client.max_fetch < response.get("count")


def test_get_audits(mocker: MockerFixture):
    # TODO docstring

    start = datetime.now().strftime(AUDIT_START_TIMESTAMP_FORMAT)

    mocker.patch.object(client, "_http_request", return_value=AUDITS)
    response: Dict[str, Any] = client.get_audits(start)

    assert isinstance(response, dict)
    assert not client.max_fetch < len(response.get("audits"))


""" Command Tests """


def test_get_detections_cmd(mocker: MockerFixture):
    # TODO docstring
    """ """

    first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

    mocker.patch.object(client, "_http_request", return_value=DETECTIONS)
    cmd_res, detections = get_detections_cmd(client, first_timestamp)

    assert len(cmd_res.outputs) == len(detections)


def test_get_audits_cmd(mocker: MockerFixture):
    # TODO docstring
    """ """

    first_timestamp = datetime.now().strftime(DETECTION_FIRST_TIMESTAMP_QUERY_START_FORMAT)

    mocker.patch.object(client, "_http_request", return_value=AUDITS)
    cmd_res, audits = get_audits_cmd(client, first_timestamp)

    assert len(cmd_res.outputs) == len(audits)


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

    # TODO docstring

    assert is_eod(dt) == expected

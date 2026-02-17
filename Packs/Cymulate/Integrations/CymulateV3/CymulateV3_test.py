from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from freezegun import freeze_time
from requests.exceptions import ChunkedEncodingError
from CommonServerPython import *
from CymulateV3 import (
    Client,
    fetch_incidents,
    test_module,
    FETCH_CATEGORY_THREAT_FEED_IOCS,
)


@pytest.fixture
def mock_client():
    """Create a Cymulate client with base URL and dummy token."""
    return Client(
        base_url="https://api.cymulate.com",
        token="dummy-token",
        verify=False,
        proxy=False,
    )


@pytest.fixture
def mock_demisto(monkeypatch):
    """Mock all demisto functions needed for fetch_incidents."""
    monkeypatch.setattr("CymulateV3.demisto.getLastRun", dict)
    monkeypatch.setattr("CymulateV3.demisto.debug", lambda _: None)
    monkeypatch.setattr("CymulateV3.demisto.error", lambda _: None)


# ========================================================================
# test_module tests
# ========================================================================


@freeze_time("2025-11-06T12:00:00Z")
def test_test_module_success(requests_mock, mock_client):
    """Test test_module returns 'ok' on success."""
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={"data": []},
        status_code=200,
    )
    result = test_module(mock_client)
    assert result == "ok"


@freeze_time("2025-11-06T12:00:00Z")
def test_test_module_401_error(requests_mock, mock_client):
    """Test test_module returns auth error on 401."""
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        status_code=401,
    )
    result = test_module(mock_client)
    assert "Authorization Error" in result


# ========================================================================
# fetch_incidents tests
# ========================================================================


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_happy_path(requests_mock, mock_client, mock_demisto):
    """Test fetch with assessments containing Not Prevented findings."""
    # Mock list_assessments
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={
            "data": [
                {
                    "id": "assessment-1",
                    "name": "Web Gateway Test",
                    "createdAt": "2025-11-06T10:00:00.000Z",
                    "status": "completed",
                },
            ],
            "nextCursor": None,
        },
    )

    # Mock get_assessment_findings
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/assessment-1/findings",
        json={
            "findings": [
                {
                    "_id": "finding-1",
                    "findingName": "SQL Injection",
                    "status": "Not Prevented",
                    "date": "2025-11-06T10:05:00.000Z",
                    "tags": [],
                },
                {
                    "_id": "finding-2",
                    "findingName": "XSS Attack",
                    "status": "Prevented",
                    "date": "2025-11-06T10:06:00.000Z",
                    "tags": [],
                },
                {
                    "_id": "finding-3",
                    "findingName": "File Upload",
                    "status": "Not Prevented",
                    "date": "2025-11-06T10:07:00.000Z",
                    "tags": [],
                },
            ],
            "nextCursor": None,
        },
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
    )

    # Only "Not Prevented" findings should create incidents
    assert len(incidents) == 2
    assert "SQL Injection" in incidents[0]["name"]
    assert "File Upload" in incidents[1]["name"]

    # last_run should have the assessment date
    assert last_run["last_assessment_date"] is not None
    assert "2025-11-06" in last_run["last_assessment_date"]


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_empty_assessments(requests_mock, mock_client, mock_demisto):
    """Test fetch with no assessments returns empty."""
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={"data": [], "nextCursor": None},
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
    )

    assert len(incidents) == 0
    assert last_run["last_assessment_date"] is None


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_threat_feed_filter(requests_mock, mock_client, mock_demisto):
    """Test fetch_category=threat_feed_iocs only returns tagged findings."""
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={
            "data": [
                {
                    "id": "assessment-1",
                    "name": "Threat Feed Test",
                    "createdAt": "2025-11-06T10:00:00.000Z",
                    "status": "completed",
                },
            ],
            "nextCursor": None,
        },
    )

    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/assessment-1/findings",
        json={
            "findings": [
                {
                    "_id": "finding-1",
                    "findingName": "IOC Finding",
                    "status": "Not Prevented",
                    "date": "2025-11-06T10:05:00.000Z",
                    "tags": ["Threat Feed IOC"],
                },
                {
                    "_id": "finding-2",
                    "findingName": "Regular Finding",
                    "status": "Not Prevented",
                    "date": "2025-11-06T10:06:00.000Z",
                    "tags": [],
                },
            ],
            "nextCursor": None,
        },
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
        fetch_category=FETCH_CATEGORY_THREAT_FEED_IOCS,
    )

    assert len(incidents) == 1
    assert "IOC Finding" in incidents[0]["name"]


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_dedup_via_assessment_date(requests_mock, mock_client, monkeypatch):
    """Test deduplication: assessments older than last_assessment_date are skipped."""
    monkeypatch.setattr(
        "CymulateV3.demisto.getLastRun",
        lambda: {"last_assessment_date": "2025-11-06T10:00:00.000000Z"},
    )
    monkeypatch.setattr("CymulateV3.demisto.debug", lambda _: None)
    monkeypatch.setattr("CymulateV3.demisto.error", lambda _: None)

    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={
            "data": [
                {
                    "id": "old-assessment",
                    "name": "Old Assessment",
                    "createdAt": "2025-11-06T09:00:00.000Z",
                    "status": "completed",
                },
                {
                    "id": "new-assessment",
                    "name": "New Assessment",
                    "createdAt": "2025-11-06T11:00:00.000Z",
                    "status": "completed",
                },
            ],
            "nextCursor": None,
        },
    )

    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/new-assessment/findings",
        json={
            "findings": [
                {
                    "_id": "new-finding",
                    "findingName": "New Finding",
                    "status": "Not Prevented",
                    "date": "2025-11-06T11:05:00.000Z",
                    "tags": [],
                },
            ],
            "nextCursor": None,
        },
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
    )

    # Only new assessment's findings should be returned
    assert len(incidents) == 1
    assert "New Finding" in incidents[0]["name"]
    assert "2025-11-06T11:00:00" in last_run["last_assessment_date"]


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_transient_error_assessments(mock_client, mock_demisto, monkeypatch):
    """Test ChunkedEncodingError during assessment fetch raises DemistoException."""
    monkeypatch.setattr(
        mock_client,
        "list_assessments",
        MagicMock(side_effect=ChunkedEncodingError("Connection broken: IncompleteRead")),
    )

    first_fetch = datetime(2025, 11, 1, tzinfo=timezone.utc)

    with pytest.raises(DemistoException, match="Error fetching assessments"):
        fetch_incidents(
            client=mock_client,
            first_fetch=first_fetch,
            max_fetch=10,
        )


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_transient_error_with_partial_data(mock_client, mock_demisto, monkeypatch):
    """Test transient error after collecting some assessments still returns partial results."""
    call_count = 0

    def mock_list_assessments(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {
                "data": [
                    {
                        "id": "assessment-1",
                        "name": "Test",
                        "createdAt": "2025-11-06T10:00:00.000Z",
                        "status": "completed",
                    },
                ],
                "nextCursor": "cursor-2",
            }
        raise ChunkedEncodingError("Connection broken")

    monkeypatch.setattr(mock_client, "list_assessments", mock_list_assessments)
    monkeypatch.setattr(
        mock_client,
        "get_assessment_findings",
        MagicMock(
            return_value={
                "findings": [
                    {
                        "_id": "f1",
                        "findingName": "Finding",
                        "status": "Not Prevented",
                        "date": "2025-11-06T10:05:00.000Z",
                        "tags": [],
                    },
                ],
                "nextCursor": None,
            }
        ),
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
    )

    assert len(incidents) == 1


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_pagination_assessments(requests_mock, mock_client, mock_demisto):
    """Test pagination of assessments (multi-page)."""
    # Page 1
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        [
            {
                "json": {
                    "data": [
                        {
                            "id": "assessment-1",
                            "name": "Assessment 1",
                            "createdAt": "2025-11-06T09:00:00.000Z",
                            "status": "completed",
                        },
                    ],
                    "nextCursor": "cursor-page2",
                },
            },
            {
                "json": {
                    "data": [
                        {
                            "id": "assessment-2",
                            "name": "Assessment 2",
                            "createdAt": "2025-11-06T10:00:00.000Z",
                            "status": "completed",
                        },
                    ],
                    "nextCursor": None,
                },
            },
        ],
    )

    # Findings for assessment-1
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/assessment-1/findings",
        json={
            "findings": [
                {
                    "_id": "f1",
                    "findingName": "Finding 1",
                    "status": "Not Prevented",
                    "date": "2025-11-06T09:05:00.000Z",
                    "tags": [],
                },
            ],
            "nextCursor": None,
        },
    )

    # Findings for assessment-2
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/assessment-2/findings",
        json={
            "findings": [
                {
                    "_id": "f2",
                    "findingName": "Finding 2",
                    "status": "Not Prevented",
                    "date": "2025-11-06T10:05:00.000Z",
                    "tags": [],
                },
            ],
            "nextCursor": None,
        },
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
    )

    assert len(incidents) == 2


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_max_fetch_cap(requests_mock, mock_client, mock_demisto):
    """Test that max_fetch limits the number of incidents returned."""
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={
            "data": [
                {
                    "id": "assessment-1",
                    "name": "Assessment 1",
                    "createdAt": "2025-11-06T10:00:00.000Z",
                    "status": "completed",
                },
            ],
            "nextCursor": None,
        },
    )

    findings = [
        {
            "_id": f"finding-{i}",
            "findingName": f"Finding {i}",
            "status": "Not Prevented",
            "date": f"2025-11-06T10:{i:02d}:00.000Z",
            "tags": [],
        }
        for i in range(10)
    ]

    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/assessment-1/findings",
        json={"findings": findings, "nextCursor": None},
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=3,
    )

    assert len(incidents) == 3


@freeze_time("2025-11-06T12:00:00Z")
def test_fetch_incidents_findings_pagination(requests_mock, mock_client, mock_demisto):
    """Test pagination of findings within an assessment."""
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched",
        json={
            "data": [
                {
                    "id": "assessment-1",
                    "name": "Assessment 1",
                    "createdAt": "2025-11-06T10:00:00.000Z",
                    "status": "completed",
                },
            ],
            "nextCursor": None,
        },
    )

    # Page 1 of findings
    requests_mock.get(
        "https://api.cymulate.com/v2/assessments/launched/assessment-1/findings",
        [
            {
                "json": {
                    "findings": [
                        {
                            "_id": "f1",
                            "findingName": "Finding 1",
                            "status": "Not Prevented",
                            "date": "2025-11-06T10:05:00.000Z",
                            "tags": [],
                        },
                    ],
                    "nextCursor": "cursor-findings-page2",
                },
            },
            {
                "json": {
                    "findings": [
                        {
                            "_id": "f2",
                            "findingName": "Finding 2",
                            "status": "Not Prevented",
                            "date": "2025-11-06T10:06:00.000Z",
                            "tags": [],
                        },
                    ],
                    "nextCursor": None,
                },
            },
        ],
    )

    first_fetch = datetime(2025, 11, 5, 12, 0, tzinfo=timezone.utc)
    incidents, last_run = fetch_incidents(
        client=mock_client,
        first_fetch=first_fetch,
        max_fetch=200,
    )

    assert len(incidents) == 2
    assert "Finding 1" in incidents[0]["name"]
    assert "Finding 2" in incidents[1]["name"]

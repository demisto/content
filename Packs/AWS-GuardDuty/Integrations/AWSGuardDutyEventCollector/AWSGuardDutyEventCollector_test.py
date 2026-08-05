from contextlib import nullcontext as does_not_raise
from datetime import datetime, timedelta
from unittest.mock import call

import demistomock as demisto
import pytest
from AWSGuardDutyEventCollector import _event_updated_at, _normalize_last_ids_entry, get_events
from test_data.finding_for_test import FINDING, FINDING_OUTPUT, MOST_GENERAL_FINDING, MOST_GENERAL_FINDING_STR

LIST_DETECTORS_RESPONSE = {"DetectorIds": ["detector_id1"]}

LIST_DETECTORS_RESPONSE_NONE_NEXT_TOKEN = {"DetectorIds": ["detector_id1"], "NextToken": None}

LIST_FINDING_IDS_RESPONSE = {"FindingIds": ["finding_id1"]}

LIST_FINDING_IDS_RESPONSE_NONE_NEXT_TOKEN = {"FindingIds": ["finding_id1"], "NextToken": None}

FINDINGS = {"Findings": [FINDING]}


def get_expected_list_finding_args(
    detector_id: str, updated_at_ts: int, gd_severity: int, max_results: int | None, next_token: str | None
):
    """Return arguments as expected in the AWSClient session list_finding function."""
    list_finding_args = {
        "DetectorId": detector_id,
        "FindingCriteria": {"Criterion": {"updatedAt": {"Gte": updated_at_ts}, "severity": {"Gte": gd_severity}}},
        "SortCriteria": {"AttributeName": "updatedAt", "OrderBy": "ASC"},
        "MaxResults": max_results,
    }
    if next_token:
        list_finding_args.update({"NextToken": next_token})
    return list_finding_args


def update_finding_id(finding, new_id, updated_at=None):
    """Update finding with new id and updatedAt fields."""
    finding["Id"] = new_id
    if updated_at:
        finding["UpdatedAt"] = updated_at
    return finding


class MockedBoto3Client:
    """Mocked AWSClient session for easier expectation settings."""

    def list_detectors(self, **kwargs):
        pass

    def list_findings(self, **kwargs):
        pass

    def get_findings(self, **kwargs):
        pass


def create_mocked_client(mocker, list_detectors_res, list_finding_ids_res, get_findings_res):
    """Create mocked AWSClient session and set the side effects for all relevant functions."""
    mocked_client = MockedBoto3Client()
    list_detectors_mock = mocker.patch.object(MockedBoto3Client, "list_detectors", side_effect=list_detectors_res)
    list_findings_mock = mocker.patch.object(MockedBoto3Client, "list_findings", side_effect=list_finding_ids_res)
    get_findings_mock = mocker.patch.object(MockedBoto3Client, "get_findings", side_effect=get_findings_res)
    return mocked_client, list_detectors_mock, list_findings_mock, get_findings_mock


def test_test_module(mocker):
    """
    Given:
        AWSClient session
        list_detectors, list_finding_ids, get_finding_ids valid responses

    When:
        Running test-module command

    Then:
        assert no exception is being raised.
        assert api calls are called exactly once.
    """
    mocked_client, list_detectors_mock, list_findings_mock, get_findings_mock = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[LIST_DETECTORS_RESPONSE],
        list_finding_ids_res=[LIST_FINDING_IDS_RESPONSE],
        get_findings_res=[FINDINGS],
    )

    with does_not_raise():
        get_events(
            aws_client=mocked_client,
            collect_from={},
            collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
            last_ids={},
            severity="Low",
            limit=1,
            detectors_num=1,
        )

    assert list_detectors_mock.is_called_once()
    assert list_findings_mock.is_called_once()
    assert get_findings_mock.is_called_once()


@pytest.mark.parametrize(
    "limit, severity, list_detectors_res, list_finding_ids_res, findings_res, "
    "list_detectors_calls, list_findings_calls, get_findings_calls, expected_events",
    [
        pytest.param(
            1,
            "Low",
            [LIST_DETECTORS_RESPONSE],
            [LIST_FINDING_IDS_RESPONSE],
            [FINDINGS],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=1, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1"])],
            [FINDING_OUTPUT],
            id="simple, no next tokens, low severity",
        ),
        pytest.param(
            10,
            "Low",
            [{"DetectorIds": ["detector_id1"], "NextToken": "next"}, {"DetectorIds": ["detector_id2"]}],
            [{"FindingIds": ["finding_id1"]}, {"FindingIds": ["finding_id2"]}],
            [
                {"Findings": [update_finding_id(FINDING.copy(), "finding_id1")]},
                {"Findings": [update_finding_id(FINDING.copy(), "finding_id2")]},
            ],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                ),
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id2", updated_at_ts=1661681559000, gd_severity=1, max_results=9, next_token=None
                    )
                ),
            ],
            [
                call(DetectorId="detector_id1", FindingIds=["finding_id1"]),
                call(DetectorId="detector_id2", FindingIds=["finding_id2"]),
            ],
            [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"), update_finding_id(FINDING_OUTPUT.copy(), "finding_id2")],
            id="2 detectors",
        ),
        pytest.param(
            10,
            "Low",
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id1"], "NextToken": "next"}, {"FindingIds": ["finding_id2"]}],
            [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1"), update_finding_id(FINDING.copy(), "finding_id2")]}],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                ),
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=9, next_token="next"
                    )
                ),
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1", "finding_id2"])],
            [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"), update_finding_id(FINDING_OUTPUT.copy(), "finding_id2")],
            id="1 detector, paginated findings",
        ),
        pytest.param(
            10,
            "Low",
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id1", "finding_id2"]}],
            [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1"), update_finding_id(FINDING.copy(), "finding_id2")]}],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1", "finding_id2"])],
            [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"), update_finding_id(FINDING_OUTPUT.copy(), "finding_id2")],
            id="1 detector, 2 findings",
        ),
        pytest.param(
            10,
            "Low",
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id1"]}],
            [{"Findings": [update_finding_id(MOST_GENERAL_FINDING.copy(), "finding_id1")]}],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1"])],
            [update_finding_id(MOST_GENERAL_FINDING_STR.copy(), "finding_id1")],
            id="check datetime to str conversion in all fields",
        ),
        pytest.param(
            1,
            "Medium",
            [LIST_DETECTORS_RESPONSE],
            [LIST_FINDING_IDS_RESPONSE],
            [FINDINGS],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=4, max_results=1, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1"])],
            [FINDING_OUTPUT],
            id="simple, no next tokens, medium severity",
        ),
        pytest.param(
            1,
            "High",
            [LIST_DETECTORS_RESPONSE],
            [LIST_FINDING_IDS_RESPONSE],
            [FINDINGS],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=7, max_results=1, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1"])],
            [FINDING_OUTPUT],
            id="simple, no next tokens, high severity",
        ),
    ],
)
def test_get_events_command(
    mocker,
    limit,
    severity,
    list_detectors_res,
    list_finding_ids_res,
    findings_res,
    list_detectors_calls,
    list_findings_calls,
    get_findings_calls,
    expected_events,
):
    """
    Given:
        AWSClient session
        get_events input parameters (limit, severity, collect_from_default)
        list_detectors, list_finding_ids, get_finding_ids various responses

    When:
        Running get-events command

    Then:
        assert events are returned as expected.
        assert api calls are called as expected.
    """
    mocked_client, list_detectors_mock, list_findings_mock, get_findings_mock = create_mocked_client(
        mocker=mocker,
        list_detectors_res=list_detectors_res,
        list_finding_ids_res=list_finding_ids_res,
        get_findings_res=findings_res,
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={},
        collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
        last_ids={},
        severity=severity,
        limit=limit,
    )

    list_detectors_mock.assert_has_calls(list_detectors_calls)
    list_findings_mock.assert_has_calls(list_findings_calls)
    get_findings_mock.assert_has_calls(get_findings_calls)
    assert events == expected_events


@pytest.mark.parametrize(
    "list_detectors_res, list_finding_ids_res, findings_res, "
    "list_detectors_calls, list_findings_calls, get_findings_calls, expected_events",
    [
        pytest.param(
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id1", "finding_id2", "finding_id3", "finding_id4", "finding_id5"]}],
            [
                {
                    "Findings": [
                        update_finding_id(FINDING.copy(), "finding_id1"),
                        update_finding_id(FINDING.copy(), "finding_id2"),
                    ]
                },
                {
                    "Findings": [
                        update_finding_id(FINDING.copy(), "finding_id3"),
                        update_finding_id(FINDING.copy(), "finding_id4"),
                    ]
                },
                {"Findings": [update_finding_id(FINDING.copy(), "finding_id5")]},
            ],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                )
            ],
            [
                call(DetectorId="detector_id1", FindingIds=["finding_id1", "finding_id2"]),
                call(DetectorId="detector_id1", FindingIds=["finding_id3", "finding_id4"]),
                call(DetectorId="detector_id1", FindingIds=["finding_id5"]),
            ],
            [
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"),
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id2"),
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id3"),
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id4"),
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id5"),
            ],
            id="1 detector, 5 findings, 2 is request limit",
        )
    ],
)
def test_get_events_with_chunked_finding_ids(
    mocker,
    list_detectors_res,
    list_finding_ids_res,
    findings_res,
    list_detectors_calls,
    list_findings_calls,
    get_findings_calls,
    expected_events,
):
    """
    Given:
        AWSClient session
        get_events input parameters (limit, severity, collect_from_default)
        list_finding_ids response with 5 findings
        max_ids_per_req is set to 2

    When:
        Running get_events function

    Then:
        assert events are returned as expected.
        assert api calls are called as expected and findings are paginated.
    """
    mocked_client, list_detectors_mock, list_findings_mock, get_findings_mock = create_mocked_client(
        mocker=mocker,
        list_detectors_res=list_detectors_res,
        list_finding_ids_res=list_finding_ids_res,
        get_findings_res=findings_res,
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={},
        collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
        last_ids={},
        severity="Low",
        limit=10,
        max_ids_per_req=2,
    )

    list_detectors_mock.assert_has_calls(list_detectors_calls)
    list_findings_mock.assert_has_calls(list_findings_calls)
    get_findings_mock.assert_has_calls(get_findings_calls)
    assert events == expected_events


@pytest.mark.parametrize(
    "list_detectors_res, list_finding_ids_res, findings_res",
    [
        pytest.param(
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id1"]}],
            [{"Findings": [update_finding_id(MOST_GENERAL_FINDING.copy(), "finding_id1")]}],
            id="datetime to str conversion in all available fields",
        )
    ],
)
def test_get_events_returns_datetime_as_str(mocker, list_detectors_res, list_finding_ids_res, findings_res):
    """
    Given:
        AWSClient session
        get_events input parameters
        findings response with datetime fields in the most general way.

    When:
        Running get_events function

    Then:
        assert events are returned as expected, with strings in all the date fields.
    """
    mocked_client, list_detectors_mock, list_findings_mock, get_findings_mock = create_mocked_client(
        mocker=mocker,
        list_detectors_res=list_detectors_res,
        list_finding_ids_res=list_finding_ids_res,
        get_findings_res=findings_res,
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={},
        collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
        last_ids={},
        severity="Low",
        limit=10,
    )

    assert len(events) == 1

    event_resource = events[0].get("Resource", {})
    event_service = events[0].get("Service", {})
    assert type(event_resource.get("EksClusterDetails", {}).get("CreatedAt")) is str
    assert type(event_resource.get("EcsClusterDetails", {}).get("TaskDetails", {}).get("TaskCreatedAt")) is str
    assert type(event_resource.get("EcsClusterDetails", {}).get("TaskDetails", {}).get("StartedAt")) is str
    assert type(event_service.get("EbsVolumeScanDetails", {}).get("ScanStartedAt")) is str
    assert type(event_service.get("EbsVolumeScanDetails", {}).get("ScanCompletedAt")) is str


@pytest.mark.parametrize(
    "collect_from, last_ids, list_detectors_res, list_finding_ids_res, findings_res, "
    "list_detectors_calls, list_findings_calls, get_findings_calls, expected_events, "
    "expected_new_collect_from, expected_new_last_ids",
    [
        pytest.param(
            {"detector_id1": "2022-08-28T10:12:39.923854"},
            {"detector_id1": "finding_id0"},
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id1"]}],
            [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1", updated_at="2022-09-28T10:12:39.923854")]}],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id1"])],
            [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1", updated_at="2022-09-28T10:12:39.923854")],
            {"detector_id1": "2022-09-28T10:12:39.923854"},
            # XSUP-67097: last_ids is now stored as list[str] of all ids sharing
            # the cursor's UpdatedAt second, not just one id.
            {"detector_id1": ["finding_id1"]},
            id="1 detector, 1 new finding",
        ),
        pytest.param(
            {"detector_id1": "2022-08-28T10:12:39.923854"},
            {"detector_id1": "finding_id0"},
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id0", "finding_id1"]}],
            # XSUP-72455: both ids are fetched so the collector can inspect each finding's
            # UpdatedAt. finding_id0 still shares the cursor second (already ingested) and is
            # deduped after the fetch; finding_id1 is new and is ingested.
            [
                {
                    "Findings": [
                        update_finding_id(FINDING.copy(), "finding_id0", updated_at="2022-08-28T10:12:39.923854"),
                        update_finding_id(FINDING.copy(), "finding_id1", updated_at="2022-09-28T10:12:39.923854"),
                    ]
                }
            ],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                )
            ],
            [call(DetectorId="detector_id1", FindingIds=["finding_id0", "finding_id1"])],
            [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1", updated_at="2022-09-28T10:12:39.923854")],
            {"detector_id1": "2022-09-28T10:12:39.923854"},
            {"detector_id1": ["finding_id1"]},
            id="1 detector, 1 new finding, 1 old finding",
        ),
        pytest.param(
            {"detector_id1": "2022-08-28T10:12:39.923854"},
            {"detector_id1": "finding_id0"},
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": []}],
            [],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                )
            ],
            [],
            [],
            {"detector_id1": "2022-08-28T10:12:39.923854"},
            {"detector_id1": "finding_id0"},
            id="1 detector, no findings",
        ),
        pytest.param(
            {"detector_id1": "2022-08-28T10:12:39.923854"},
            {"detector_id1": "finding_id0"},
            [{"DetectorIds": ["detector_id1", "detector_id2"]}],
            [{"FindingIds": ["finding_id1"]}, {"FindingIds": ["finding_id2"]}],
            [
                {"Findings": [update_finding_id(FINDING.copy(), "finding_id1", updated_at="2022-09-28T10:12:39.923854")]},
                {"Findings": [update_finding_id(FINDING.copy(), "finding_id2", updated_at="2022-07-29T10:12:39.923854")]},
            ],
            [call(MaxResults=50)],
            [
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id1", updated_at_ts=1661681559000, gd_severity=1, max_results=10, next_token=None
                    )
                ),
                call(
                    **get_expected_list_finding_args(
                        detector_id="detector_id2", updated_at_ts=1659003099000, gd_severity=1, max_results=9, next_token=None
                    )
                ),
            ],
            [
                call(DetectorId="detector_id1", FindingIds=["finding_id1"]),
                call(DetectorId="detector_id2", FindingIds=["finding_id2"]),
            ],
            [
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id1", updated_at="2022-09-28T10:12:39.923854"),
                update_finding_id(FINDING_OUTPUT.copy(), "finding_id2", updated_at="2022-07-29T10:12:39.923854"),
            ],
            {"detector_id1": "2022-09-28T10:12:39.923854", "detector_id2": "2022-07-29T10:12:39.923854"},
            {"detector_id1": ["finding_id1"], "detector_id2": ["finding_id2"]},
            id="1 old detector, 1 new detector, 1 new finding each",
        ),
    ],
)
def test_fetch_events(
    mocker,
    collect_from,
    last_ids,
    list_detectors_res,
    list_finding_ids_res,
    findings_res,
    list_detectors_calls,
    list_findings_calls,
    get_findings_calls,
    expected_events,
    expected_new_collect_from,
    expected_new_last_ids,
):
    """
    Given:
        AWSClient session
        get_events various input parameters (collect_from, last_ids)
        list_detectors, list_finding_ids, get_finding_ids various responses.

    When:
        Running get_events as part of fetch-events command.

    Then:
        assert events are returned as expected.
        assert api calls are called as expected.
        assert new_collect_from and new_last_ids are returned as expected.
    """
    mocked_client, list_detectors_mock, list_findings_mock, get_findings_mock = create_mocked_client(
        mocker=mocker,
        list_detectors_res=list_detectors_res,
        list_finding_ids_res=list_finding_ids_res,
        get_findings_res=findings_res,
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from=collect_from,
        collect_from_default=datetime(2022, 7, 28, 10, 11, 39, 923854),
        last_ids=last_ids,
        severity="Low",
        limit=10,
    )

    list_detectors_mock.assert_has_calls(list_detectors_calls)
    list_findings_mock.assert_has_calls(list_findings_calls)
    get_findings_mock.assert_has_calls(get_findings_calls)
    assert events == expected_events
    assert new_collect_from == expected_new_collect_from
    assert new_last_ids == expected_new_last_ids


def test_fetch_events_single_recent_old_finding_stays_pinned(mocker):
    """
    Given:
        One detector whose cursor sits at a RECENT second, and the only finding
        returned is the already-ingested one sharing that cursor second (no
        NextToken). Extracted from the former parametrized "1 detector, 1 old
        finding" case; the boundary is recent so it is within
        STALE_BOUNDARY_MARGIN.

    When:
        get_events runs.

    Then:
        The already-seen finding is deduped (no events), and because the boundary
        is still current the cursor stays pinned with last_ids preserved. (A stale
        boundary would instead advance via the XSUP-71079 freeze-breaker.)

    Reference:
        AWSGuardDutyEventCollector.get_events — same-second dedup pins a current
        boundary; the stale-boundary advance is time-gated.
    """
    cursor = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")

    mocked_client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["detector_id1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_id0"]}],
        get_findings_res=[{"Findings": [update_finding_id(FINDING.copy(), "finding_id0", updated_at=cursor)]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={"detector_id1": cursor},
        collect_from_default=datetime(2022, 7, 28, 10, 11, 39, 923854),
        last_ids={"detector_id1": "finding_id0"},
        severity="Low",
        limit=10,
    )

    assert events == []
    # Current boundary: cursor pinned and the already-seen id preserved.
    assert new_collect_from == {"detector_id1": cursor}
    assert new_last_ids == {"detector_id1": ["finding_id0"]}


# ---------------------------------------------------------------------------
# Regression test for XSUP-67097 / XSUP-67552 — same-second sibling-loss bug.
#
# Scenario: three findings (A, B, C) all share the same UpdatedAt timestamp.
#   Run 1: AWS pagination returns [A, B] (limit=2 cuts off page 2).
#          Cursor stored: last_ids[detector] = "B", collect_from = T.
#   Run 2: Filter is updatedAt: {Gte: T} (inclusive), so AWS returns the same
#          set again. AWS does NOT guarantee a stable order across calls when
#          findings share an UpdatedAt second, so it returns [A, C, B].
#          The dedup at AWSGuardDutyEventCollector.py:130-135 finds B, slices
#          AFTER B's index → result is []. Finding C is permanently dropped.
#
# Expected (after fix): A, B fetched in run 1; C fetched in run 2.
# Actual (with bug):    A, B fetched in run 1; C is LOST.
# ---------------------------------------------------------------------------


def test_same_second_sibling_loss_xsup_67097(mocker):
    """
    Given:
        Three findings (A, B, C) on a single detector, all sharing the same
        UpdatedAt second. Pagination splits them across two fetch cycles.

    When:
        Run 1 fetches with limit=2 and stores last_ids[det] = "B".
        Run 2's mocked AWS returns the same findings in a different valid
        intra-second order ([A, C, B]) — permitted by AWS GuardDuty since
        sort is stable only on updatedAt, not on id.

    Then:
        After both runs, all three findings should be ingested exactly once.
        With the current single-id dedup in get_events(), finding C is lost
        on run 2 (the dedup slices AFTER B's index, dropping C).

    Reference:
        AWSGuardDutyEventCollector.py:130-135 (single-id dedup slice)
        AWSGuardDutyEventCollector.py:158     (single-id storage)
    """
    same_second_ts = "2026-04-10T01:35:09.000000"
    finding_a = update_finding_id(FINDING.copy(), "finding_A", updated_at=same_second_ts)
    finding_b = update_finding_id(FINDING.copy(), "finding_B", updated_at=same_second_ts)
    finding_c = update_finding_id(FINDING.copy(), "finding_C", updated_at=same_second_ts)

    # ------------------------------------------------------------------ Run 1
    # AWS returns [A, B] only (limit=2 stops the loop before page 2 of [C]).
    run1_client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_A", "finding_B"]}],
        get_findings_res=[{"Findings": [finding_a, finding_b]}],
    )

    events_run1, last_ids_after_run1, collect_from_after_run1 = get_events(
        aws_client=run1_client,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids={},
        severity="Low",
        limit=2,
    )

    run1_ids = sorted(e["Id"] for e in events_run1)
    assert run1_ids == ["finding_A", "finding_B"], f"Sanity check failed: run 1 should ingest A and B, got {run1_ids}"
    # Cursor state after run 1: with the XSUP-67097 fix, last_ids stores ALL ids
    # whose UpdatedAt equals the cursor (the same-second siblings), not just one.
    # Both A and B share the cursor second so both must be remembered.
    assert last_ids_after_run1 == {"det1": ["finding_A", "finding_B"]}
    assert collect_from_after_run1 == {"det1": same_second_ts}

    # ------------------------------------------------------------------ Run 2
    # AWS re-queries with Gte: T (inclusive). It returns the same three
    # findings, but in a DIFFERENT intra-second order: [A, C, B].
    # This is valid AWS behavior — sort key is updatedAt only, ties are
    # not guaranteed stable across calls. The dedup in get_events() will
    # find B at index 2 and slice AFTER it, producing []. C is dropped.
    mocker.resetall()
    run2_client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_A", "finding_C", "finding_B"]}],
        # get_findings is only invoked if there are surviving ids after dedup.
        # The bug means there will be none, so this side-effect is never hit.
        # If a fix is applied, it WILL be hit with FindingIds=["finding_C"].
        get_findings_res=[{"Findings": [finding_c]}],
    )

    events_run2, _, _ = get_events(
        aws_client=run2_client,
        collect_from=collect_from_after_run1,
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids=last_ids_after_run1,
        severity="Low",
        limit=10,
    )

    # ------------------------------------------------------------ Assertion
    # Combined across both runs, every finding (A, B, C) must appear exactly
    # once. Today's code drops C — this assertion fails as proof of the bug.
    all_ingested_ids = sorted(e["Id"] for e in (events_run1 + events_run2))
    assert all_ingested_ids == ["finding_A", "finding_B", "finding_C"], (
        f"XSUP-67097 same-second sibling loss: expected all three findings "
        f"to be ingested across the two fetch cycles, but got {all_ingested_ids}. "
        f"Finding 'finding_C' was silently dropped because the dedup at "
        f"AWSGuardDutyEventCollector.py:135 slices after the single stored "
        f"last_id, losing any same-second siblings that AWS returned in a "
        f"position before that last_id on the next page."
    )


def test_legacy_last_ids_str_shape_still_works(mocker):
    """
    Given:
        A last_ids dict using the legacy str shape (single id per detector),
        as written by integration versions prior to 1.3.67.

    When:
        get_events runs with that legacy state and AWS returns the stored id
        again (because Gte is inclusive on updatedAt).

    Then:
        The legacy id is treated as already-seen and dropped from the new
        ingestion. State is migrated forward — the new run writes the
        list-shaped value going forward.

    Reference:
        AWSGuardDutyEventCollector._normalize_last_ids_entry — accepts
        str | list | tuple | set, preserving compatibility with stored
        state from older versions.
    """
    same_second_ts = "2026-04-10T01:35:09.000000"
    # Only finding_new is constructed because the dedup drops finding_old before
    # it ever reaches get_findings — there's no need to materialize the old one.
    finding_new = update_finding_id(FINDING.copy(), "finding_new", updated_at=same_second_ts)

    # Legacy single-string last_ids shape, as written by versions <1.3.67.
    legacy_last_ids: dict = {"det1": "finding_old"}
    legacy_collect_from = {"det1": same_second_ts}

    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        # AWS returns both findings; old one must be deduped via legacy str.
        list_finding_ids_res=[{"FindingIds": ["finding_old", "finding_new"]}],
        get_findings_res=[{"Findings": [finding_new]}],
    )

    events, new_last_ids, _ = get_events(
        aws_client=client,
        collect_from=legacy_collect_from,
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids=legacy_last_ids,
        severity="Low",
        limit=10,
    )

    # Only the new finding ingests; the legacy id is recognized and dropped.
    assert [e["Id"] for e in events] == ["finding_new"]
    # State is migrated forward to the list shape. Both old and new share the
    # cursor second, so both are remembered for the NEXT run's dedup.
    assert new_last_ids == {"det1": ["finding_new", "finding_old"]}


# ---------------------------------------------------------------------------
# Regression test for XSUP-71079 — mid-second cursor truncation.
#
# Scenario: a fetch is truncated by `limit` in the MIDDLE of a second that has
# more siblings than were fetched. The cursor must NOT advance into that
# partially-consumed second, otherwise the un-fetched siblings (which fall on
# the same inclusive `Gte` boundary) are skipped on the next run.
# ---------------------------------------------------------------------------


def test_mid_second_truncation_does_not_advance_cursor_xsup_71079(mocker):
    """
    Given:
        Two seconds of findings on a single detector:
          - second T1 = "...:08.000000" with finding_1 (fully drained)
          - second T2 = "...:09.000000" with finding_2 (only one of several
            siblings fetched before `limit` truncated the page; next_token is
            still set, signalling more findings remain).

    When:
        get_events runs with limit=2 and AWS returns a pending NextToken,
        indicating the fetch was truncated before T2 was fully drained.

    Then:
        The cursor (collect_from) is rolled back to T1 (the last fully-drained
        second), and the persisted last_ids contains T1's id so the next run
        re-queries from T1 (inclusive) and re-reads T2 in full without skipping
        any of its siblings.

    Reference:
        AWSGuardDutyEventCollector.get_events — truncated_by_limit rollback.
    """
    t1 = "2026-04-10T01:35:08.000000"
    t2 = "2026-04-10T01:35:09.000000"
    finding_1 = update_finding_id(FINDING.copy(), "finding_1", updated_at=t1)
    finding_2 = update_finding_id(FINDING.copy(), "finding_2", updated_at=t2)

    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        # NextToken is set => the loop exits due to `limit`, not exhaustion.
        list_finding_ids_res=[{"FindingIds": ["finding_1", "finding_2"], "NextToken": "more"}],
        get_findings_res=[{"Findings": [finding_1, finding_2]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids={},
        severity="Low",
        limit=2,
    )

    # Both fetched findings are still returned to XSIAM (no data dropped this run).
    assert sorted(e["Id"] for e in events) == ["finding_1", "finding_2"]
    # The cursor is rolled back to the last FULLY-drained second (T1), NOT T2,
    # so T2's un-fetched siblings are re-queried next run.
    assert new_collect_from == {"det1": t1}
    # last_ids reflects T1's siblings so finding_1 is not re-ingested next run.
    assert new_last_ids == {"det1": ["finding_1"]}


def test_exclude_archived_adds_criterion_xsup_71079(mocker):
    """
    Given:
        exclude_archived=True is passed to get_events.

    When:
        get_events builds the list_findings FindingCriteria.

    Then:
        The criterion includes service.archived == "false" so archived /
        suppressed findings are not fetched. When exclude_archived is False
        (default) the criterion does NOT include the archived filter.

    Reference:
        AWSGuardDutyEventCollector._build_finding_criterion — XSUP-71079 #2.
    """
    finding = update_finding_id(FINDING.copy(), "finding_1", updated_at="2026-04-10T01:35:09.000000")

    # exclude_archived=True
    client, _, list_findings_mock, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_1"]}],
        get_findings_res=[{"Findings": [finding]}],
    )
    get_events(
        aws_client=client,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids={},
        severity="Low",
        limit=10,
        exclude_archived=True,
    )
    criterion = list_findings_mock.call_args.kwargs["FindingCriteria"]["Criterion"]
    assert criterion.get("service.archived") == {"Eq": ["false"]}

    # exclude_archived=False (default) — no archived filter.
    mocker.resetall()
    client2, _, list_findings_mock2, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_1"]}],
        get_findings_res=[{"Findings": [finding]}],
    )
    get_events(
        aws_client=client2,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids={},
        severity="Low",
        limit=10,
        exclude_archived=False,
    )
    criterion2 = list_findings_mock2.call_args.kwargs["FindingCriteria"]["Criterion"]
    assert "service.archived" not in criterion2


# ---------------------------------------------------------------------------
# Regression test for XSUP-72455 — a recurring finding that is RE-UPDATED after
# being stored in last_ids must not be suppressed forever.
#
# Scenario: finding_X is ingested at cursor second T1 and stored in last_ids.
# Later GuardDuty aggregates a new occurrence into the same finding, moving its
# UpdatedAt to a strictly-later second T2. AWS returns it again (Gte is
# inclusive). The old ID-only dedup dropped it because its id was in last_ids,
# producing an empty result — which also prevented the cursor from advancing,
# pinning the fetch behind that finding indefinitely.
# ---------------------------------------------------------------------------


def test_reupdated_finding_is_not_suppressed_xsup_72455(mocker):
    """
    Given:
        finding_X was ingested on a previous run at cursor second T1 and is
        stored in last_ids[det1]. On the next run GuardDuty returns finding_X
        again, but its UpdatedAt has advanced to a strictly-later second T2
        (a real new occurrence aggregated into the long-lived finding).

    When:
        get_events runs with collect_from=T1 and last_ids={det1: [finding_X]}.

    Then:
        finding_X must be ingested (the update is a legitimate new event) and
        the cursor must advance to T2. The old ID-only dedup dropped it and
        left the cursor pinned at T1 with zero events — this test fails on the
        buggy code and passes once dedup is scoped to the cursor second.

    Reference:
        AWSGuardDutyEventCollector.get_events — dedup must only drop findings
        whose UpdatedAt equals the stored cursor second, never later updates.
    """
    t1 = "2026-07-03T15:48:55.563000"
    t2 = "2026-07-04T08:04:55.843000"
    # Same finding id as what is already stored in last_ids, but re-updated to T2.
    reupdated = update_finding_id(FINDING.copy(), "finding_X", updated_at=t2)

    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        # AWS returns the already-seen id again because Gte(T1) is inclusive and
        # the finding's UpdatedAt (T2) is >= T1.
        list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
        get_findings_res=[{"Findings": [reupdated]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t1},
        collect_from_default=datetime(2026, 7, 3, 7, 0, 0),
        last_ids={"det1": ["finding_X"]},
        severity="Low",
        limit=10,
    )

    # The re-updated finding is a legitimate new event and must be ingested.
    assert [e["Id"] for e in events] == ["finding_X"], (
        "XSUP-72455: a finding whose UpdatedAt advanced past the stored cursor "
        "second was dropped by ID-only dedup, so no events were ingested."
    )
    # The cursor must advance to the finding's new second (T2), not stay pinned at T1.
    assert new_collect_from == {"det1": t2}, (
        "XSUP-72455: cursor stayed pinned at the old second because the "
        "re-updated finding was suppressed, blocking all forward progress."
    )
    # last_ids now reflects the new cursor second (T2), holding finding_X so a
    # same-second re-query does not re-ingest it.
    assert new_last_ids == {"det1": ["finding_X"]}


def test_same_id_same_second_still_deduped_xsup_72455(mocker):
    """
    Given:
        finding_X is stored in last_ids at cursor second T1 and GuardDuty
        returns it again with the SAME UpdatedAt (T1) — the inclusive-Gte
        re-read of an already-ingested finding, not a new update.

    When:
        get_events runs with collect_from=T1 and last_ids={det1: [finding_X]}.

    Then:
        finding_X must be deduped (not re-ingested) and the cursor stays at T1.
        This guards that the XSUP-72455 fix does not regress the original
        same-second dedup (XSUP-67097) behavior.

    Reference:
        AWSGuardDutyEventCollector.get_events — same-second re-reads are still deduped.
    """
    # A RECENT cursor second: the re-read is deduped and the cursor stays pinned
    # (a real later same-second update could still arrive). Using a fixed past
    # second would trip the XSUP-71079 stale-boundary advance instead.
    t1 = datetime.utcnow().replace(microsecond=563000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    same_second_again = update_finding_id(FINDING.copy(), "finding_X", updated_at=t1)

    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
        get_findings_res=[{"Findings": [same_second_again]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t1},
        collect_from_default=datetime(2026, 7, 3, 7, 0, 0),
        last_ids={"det1": ["finding_X"]},
        severity="Low",
        limit=10,
    )

    # Already ingested at T1 with the same UpdatedAt — must not be re-ingested.
    assert events == []
    # Cursor unchanged; finding_X remembered for the next same-second re-query.
    assert new_collect_from == {"det1": t1}
    assert new_last_ids == {"det1": ["finding_X"]}


# ---------------------------------------------------------------------------
# _normalize_last_ids_entry — bad-path coercion.
#
# The helper must never propagate a malformed cache entry into the fetch loop.
# Unexpected value types (dict, int, etc.) fall back to an empty set() and a
# log line is emitted so operators can see a bad cache entry was ignored.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_value", [{"unexpected": "dict"}, 42])
def test_normalize_last_ids_entry_bad_path_returns_empty_set_and_logs(mocker, bad_value):
    """
    Given:
        A stored last_ids entry of an unexpected type (a dict and an int).

    When:
        _normalize_last_ids_entry is asked to coerce it into a set of ids.

    Then:
        The result is an empty set() (a single bad cache entry never blocks a
        fetch), and a log line is emitted noting the unexpected type so the
        silent fallback is observable.

    Reference:
        AWSGuardDutyEventCollector._normalize_last_ids_entry — bad-path branch.
    """
    # The helper logs via demisto's logging channel on the bad path. Patch it so
    # we can assert the fallback was recorded rather than silently swallowed.
    log_mock = mocker.patch.object(demisto, "debug")

    result = _normalize_last_ids_entry(bad_value)

    assert result == set()
    assert isinstance(result, set)
    # A log line must be emitted so the ignored bad cache entry is observable.
    assert log_mock.called, "Expected a log line to be emitted for the unexpected last_ids value type."
    logged_message = log_mock.call_args.args[0]
    assert type(bad_value).__name__ in logged_message


# ---------------------------------------------------------------------------
# Multi-detector truncation — detectors advance their cursors independently.
#
# detector_A is truncated by `limit` mid-boundary (rolls its cursor back to the
# last fully-drained second) while detector_B drains fully (advances normally).
# Each detector's new_collect_from and new_last_ids must be computed in
# isolation — one detector's truncation must not affect the other's cursor.
# ---------------------------------------------------------------------------


def test_multi_detector_truncation_advances_cursors_independently(mocker):
    """
    Given:
        Two detectors whose fetches end differently:
          - detector_A returns findings across two seconds (A_t1 fully drained,
            A_t2 partial) and the finding-ids loop exits with a pending
            NextToken because it hit `limit` mid-boundary at A_t2.
          - detector_B returns a single finding on one second and NO pending
            NextToken => fully drained, advancing its cursor normally.

    When:
        get_events processes both detectors in the same run (the finding-ids
        loop shares one `limit` budget, so det_A must reach the limit on its
        own page for its truncation to be attributable to the limit while
        det_B still has budget to drain).

    Then:
        detector_A's cursor rolls back to its last fully-drained second (A_t1)
        and its last_ids holds only A_t1's sibling, while detector_B advances
        normally to its finding's second with its own last_ids. Each detector's
        new_collect_from and new_last_ids are computed independently — det_A's
        rollback does not touch det_B's forward advance.

    Reference:
        AWSGuardDutyEventCollector.get_events — per-detector cursor bookkeeping
        (XSUP-71079 truncation rollback applied per detector).
    """
    a_t1 = "2026-04-10T01:35:08.000000"
    a_t2 = "2026-04-10T01:35:09.000000"
    b_t1 = "2026-04-10T02:00:00.000000"

    finding_a1 = update_finding_id(FINDING.copy(), "finding_A1", updated_at=a_t1)
    finding_a2 = update_finding_id(FINDING.copy(), "finding_A2", updated_at=a_t2)
    finding_b1 = update_finding_id(FINDING.copy(), "finding_B1", updated_at=b_t1)

    # limit=3: det_A returns 3 finding ids on one page (reaching the limit so its
    # loop exits by limit) but one id is a duplicate, so it ingests only 2 events
    # (A1, A2) and leaves budget for det_B to drain its single finding.
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det_A", "det_B"]}],
        list_finding_ids_res=[
            # det_A: 3 ids fill the limit => loop exits by limit; NextToken still
            # pending => truncated mid-boundary at the partial second A_t2.
            {"FindingIds": ["finding_A1", "finding_A2", "finding_A2"], "NextToken": "more"},
            # det_B: no NextToken => fully drained.
            {"FindingIds": ["finding_B1"]},
        ],
        get_findings_res=[
            {"Findings": [finding_a1, finding_a2]},
            {"Findings": [finding_b1]},
        ],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 0, 0),
        last_ids={},
        severity="Low",
        limit=3,
    )

    # All distinct fetched findings are still returned this run (nothing dropped).
    assert sorted(e["Id"] for e in events) == ["finding_A1", "finding_A2", "finding_B1"]

    # detector_A: truncated mid-boundary => cursor rolls back to the last
    # fully-drained second (A_t1), NOT the partial A_t2. last_ids holds A_t1's
    # sibling so it is not re-ingested next run.
    assert new_collect_from["det_A"] == a_t1
    assert new_last_ids["det_A"] == ["finding_A1"]

    # detector_B: fully drained => cursor advances normally to its finding's
    # second with its own independent last_ids.
    assert new_collect_from["det_B"] == b_t1
    assert new_last_ids["det_B"] == ["finding_B1"]


# ---------------------------------------------------------------------------
# Single-boundary-cannot-drain — an entire truncated page shares one UpdatedAt.
#
# When every fetched finding falls on the SAME second and the page is truncated
# by `limit` (NextToken set), there is no earlier second to roll back to. The
# cursor must stay pinned on that second and seen_ids must accumulate every id
# on it, so the next run makes progress via same-second dedup rather than
# skipping the un-fetched siblings.
# ---------------------------------------------------------------------------


def test_single_boundary_cannot_drain_keeps_cursor_and_accumulates_seen_ids(mocker):
    """
    Given:
        A single detector whose truncated page (NextToken set) contains two
        findings that all share ONE UpdatedAt second — there is no earlier,
        fully-drained second to roll the cursor back to.

    When:
        get_events runs and the loop exits due to limit with a pending token.

    Then:
        The cursor stays put on that single second and last_ids (seen_ids)
        accumulates every id observed on that second, so the next run dedups
        them and ingests the remaining siblings instead of skipping them.

    Reference:
        AWSGuardDutyEventCollector.get_events — single-second truncation branch
        (fully_drained is empty; keep cursor and accumulate seen ids).
    """
    ts = "2026-04-10T01:35:09.000000"
    finding_1 = update_finding_id(FINDING.copy(), "finding_1", updated_at=ts)
    finding_2 = update_finding_id(FINDING.copy(), "finding_2", updated_at=ts)

    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        # NextToken set => truncated by limit; every finding shares the same second.
        list_finding_ids_res=[{"FindingIds": ["finding_1", "finding_2"], "NextToken": "more"}],
        get_findings_res=[{"Findings": [finding_1, finding_2]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 35, 0),
        last_ids={},
        severity="Low",
        limit=2,
    )

    # Both fetched findings are returned this run.
    assert sorted(e["Id"] for e in events) == ["finding_1", "finding_2"]
    # No earlier second to roll back to => the cursor stays on the single second.
    assert new_collect_from == {"det1": ts}
    # seen_ids accumulates EVERY id on the pinned second so the next run dedups
    # them and can make forward progress via same-second dedup.
    assert new_last_ids == {"det1": ["finding_1", "finding_2"]}


# ---------------------------------------------------------------------------
# Cursor-pin regression guard — a finding re-updated at the SAME boundary every
# run must not freeze the fetch forever. Ingestion must resume when a
# later-boundary update finally arrives.
# ---------------------------------------------------------------------------


def test_same_boundary_reupdate_does_not_freeze_fetch_forever(mocker):
    """
    Given:
        finding_X keeps being re-returned at the SAME cursor second T1 across
        several runs (an already-ingested finding re-read by the inclusive Gte
        query). The cursor stays pinned at T1 during those runs — that is
        correct, because nothing new has actually happened.

    When:
        On a later run GuardDuty finally moves finding_X's UpdatedAt to a
        strictly-later second T2 (a genuine new occurrence).

    Then:
        Ingestion resumes: finding_X is ingested and the cursor advances to T2.
        This proves the same-boundary pinning is a bounded, correct pause — not
        a permanent freeze — and guards against a regression where a
        perpetually same-second finding would block the fetch indefinitely.

    Reference:
        AWSGuardDutyEventCollector.get_events — dedup is scoped to the cursor
        second, so a later-boundary update always resumes forward progress.
    """
    # T1 is a RECENT second so the same-second re-reads stay pinned (not tripped by
    # the XSUP-71079 stale-boundary advance). T2 is a strictly-later second.
    now = datetime.utcnow()
    t1 = now.replace(microsecond=563000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    t2 = (now + timedelta(seconds=17)).replace(microsecond=843000).strftime("%Y-%m-%dT%H:%M:%S.%f")

    # ---- Runs that keep re-reading finding_X at the SAME second T1 ----------
    for run_number in range(3):
        same_second_again = update_finding_id(FINDING.copy(), "finding_X", updated_at=t1)
        mocker.resetall()
        client, _, _, _ = create_mocked_client(
            mocker=mocker,
            list_detectors_res=[{"DetectorIds": ["det1"]}],
            list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
            get_findings_res=[{"Findings": [same_second_again]}],
        )
        events, new_last_ids, new_collect_from = get_events(
            aws_client=client,
            collect_from={"det1": t1},
            collect_from_default=datetime(2026, 7, 3, 7, 0, 0),
            last_ids={"det1": ["finding_X"]},
            severity="Low",
            limit=10,
        )
        # Nothing new happened this run: no re-ingestion, cursor pinned at T1.
        assert events == [], f"run {run_number}: same-second re-read must not re-ingest finding_X"
        assert new_collect_from == {"det1": t1}, f"run {run_number}: cursor must stay pinned while only T1 re-reads arrive"
        assert new_last_ids == {"det1": ["finding_X"]}

    # ---- Later run: a genuine later-boundary update finally arrives ---------
    reupdated = update_finding_id(FINDING.copy(), "finding_X", updated_at=t2)
    mocker.resetall()
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
        get_findings_res=[{"Findings": [reupdated]}],
    )
    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t1},
        collect_from_default=datetime(2026, 7, 3, 7, 0, 0),
        last_ids={"det1": ["finding_X"]},
        severity="Low",
        limit=10,
    )

    # Ingestion resumes the moment a later-boundary update arrives — the pin was
    # a bounded pause, never a permanent freeze.
    assert [e["Id"] for e in events] == ["finding_X"], (
        "Cursor-pin regression: a finding re-updated to a later boundary must "
        "resume ingestion, but nothing was ingested (fetch frozen)."
    )
    assert new_collect_from == {"det1": t2}, "Cursor must advance to the later boundary once a real update arrives."
    assert new_last_ids == {"det1": ["finding_X"]}


# ---------------------------------------------------------------------------
# _time / timestamp mapping — every emitted event must expose a field XSIAM can
# map to _time. XSIAM derives _time from the finding's UpdatedAt, which the
# fetch cursor is also built from, so every event must carry a string UpdatedAt.
# ---------------------------------------------------------------------------


def test_emitted_events_expose_updated_at_for_time_mapping(mocker):
    """
    Given:
        A detector returning findings with distinct UpdatedAt timestamps.

    When:
        get_events fetches and normalizes them for emission to XSIAM.

    Then:
        Every emitted event exposes an UpdatedAt field (the source XSIAM maps to
        _time), it is a string (datetime fields are stringified before emission
        so JSON serialization succeeds), and it matches the value the fetch
        cursor is derived from via _event_updated_at.

    Reference:
        AWSGuardDutyEventCollector.convert_events_with_datetime_to_str and
        _event_updated_at — the cursor/_time source field.
    """
    ts_1 = "2026-04-10T01:35:08.000000"
    ts_2 = "2026-04-10T01:35:09.000000"
    finding_1 = update_finding_id(FINDING.copy(), "finding_1", updated_at=ts_1)
    finding_2 = update_finding_id(FINDING.copy(), "finding_2", updated_at=ts_2)

    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_1", "finding_2"]}],
        get_findings_res=[{"Findings": [finding_1, finding_2]}],
    )

    events, _, _ = get_events(
        aws_client=client,
        collect_from={},
        collect_from_default=datetime(2026, 4, 10, 1, 0, 0),
        last_ids={},
        severity="Low",
        limit=10,
    )

    assert len(events) == 2
    for event in events:
        # XSIAM maps _time from UpdatedAt — it must be present on every event.
        assert "UpdatedAt" in event, "Every emitted event must expose UpdatedAt for XSIAM _time mapping."
        # Stringified before emission so setLastRun / send_events_to_xsiam can serialize it.
        assert isinstance(event["UpdatedAt"], str)
        # The _time source must equal the field the fetch cursor is derived from.
        assert _event_updated_at(event) == event["UpdatedAt"]

    # Each event's _time source is the expected, distinct UpdatedAt value.
    assert sorted(_event_updated_at(e) for e in events) == [ts_1, ts_2]


# ---------------------------------------------------------------------------
# Regression test for XSUP-73410 — sub-second (millisecond) cursor churn.
#
# Production GuardDuty findings carry MILLISECOND-precision UpdatedAt values
# (e.g. "...:23.311Z", "...:23.936Z"). Several findings routinely share the
# same whole SECOND while differing in their milliseconds. The fetch cursor is
# meant to be a per-second boundary (see XSUP-67097 / 71079 / 72455), and every
# finding sharing the cursor's second must be remembered so the inclusive Gte
# re-query can dedup them.
#
# Two defects combined to re-ingest the whole second on every run (observed in
# live telemetry: the same (Id, UpdatedAt) pair ingested up to 1440x/day):
#   1. The cursor was set from detector_events[-1] (LIST order), not the max
#      timestamp. AWS get_findings does NOT preserve the requested id order, so
#      the cursor oscillated between the earliest/latest ms of the same second.
#   2. The remembered sibling set was scoped to the EXACT-microsecond cursor
#      value, so only the one finding at that precise ms was remembered — the
#      other same-second siblings were forgotten and re-ingested next run.
#
# This test reproduces the loop: three findings in one second at different ms,
# returned by get_findings in a NON-sorted order, run across two fetch cycles
# with the state round-tripped as a list (as setLastRun would persist it).
# ---------------------------------------------------------------------------


def test_millisecond_siblings_not_reingested_xsup_73410(mocker):
    """
    Given:
        Three findings (A, B, C) on one detector, all sharing the same whole
        SECOND 13:18:23 but with different MILLISECONDS (.311 / .627 / .936).
        get_findings returns them in a NON-sorted order — valid AWS behavior,
        since get_findings does not preserve FindingIds order.

    When:
        Run 1 fetches from before the second and ingests all three.
        Run 2 re-queries with the persisted cursor (state round-tripped as a
        list, as setLastRun serializes it). The inclusive Gte re-returns the
        same three findings, again in a non-sorted order.

    Then:
        Run 1 ingests A, B, C exactly once.
        Run 2 ingests NOTHING — all three are recognized as the same
        already-seen same-second findings and deduped.
        The persisted cursor is deterministic (the max, .936) and stable across
        runs (no oscillation), and last_ids remembers ALL three siblings.

        With the pre-fix code, run 2 re-ingests all three and the cursor
        oscillates within the second, so these assertions fail — proving the
        millisecond-churn re-ingestion bug.

    Reference:
        AWSGuardDutyEventCollector.get_events — cursor advance + same-second
        sibling dedup must operate at whole-second resolution.
    """
    # Use a RECENT whole-second (within STALE_BOUNDARY_MARGIN of now) so the
    # fully-deduped re-query in run 2 correctly stays pinned rather than tripping
    # the stale-boundary freeze-breaker. A real later same-second update could
    # still arrive at a current second, so pinning is the correct behavior here.
    base_second = datetime.utcnow().replace(microsecond=0)
    ts_a = base_second.replace(microsecond=311000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    ts_b = base_second.replace(microsecond=627000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    ts_c = base_second.replace(microsecond=936000).strftime("%Y-%m-%dT%H:%M:%S.%f")

    def make_findings():
        # Fresh copies each run so mutations never leak between cycles.
        finding_a = update_finding_id(FINDING.copy(), "finding_A", updated_at=ts_a)
        finding_b = update_finding_id(FINDING.copy(), "finding_B", updated_at=ts_b)
        finding_c = update_finding_id(FINDING.copy(), "finding_C", updated_at=ts_c)
        return finding_a, finding_b, finding_c

    # ------------------------------------------------------------------ Run 1
    fa1, fb1, fc1 = make_findings()
    run1_client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_A", "finding_B", "finding_C"]}],
        # get_findings returns them in a DIFFERENT order than requested.
        get_findings_res=[{"Findings": [fc1, fa1, fb1]}],
    )

    events_run1, last_ids_after_run1, collect_from_after_run1 = get_events(
        aws_client=run1_client,
        collect_from={},
        collect_from_default=datetime(2026, 8, 1, 13, 18, 0),
        last_ids={},
        severity="Low",
        limit=10,
    )

    assert sorted(e["Id"] for e in events_run1) == [
        "finding_A",
        "finding_B",
        "finding_C",
    ], "Sanity: run 1 must ingest all three same-second findings."
    # The cursor must be the MAX timestamp of the second — deterministic, not
    # whichever finding happened to be last in get_findings order.
    assert collect_from_after_run1 == {
        "det1": ts_c
    }, f"Cursor must advance to the max same-second timestamp, got {collect_from_after_run1}."
    # Every finding sharing the cursor second must be remembered for dedup.
    assert last_ids_after_run1 == {
        "det1": ["finding_A", "finding_B", "finding_C"]
    }, f"All same-second siblings must be remembered, got {last_ids_after_run1}."

    # ------------------------------------------------------------------ Run 2
    # The inclusive Gte re-query returns the same three findings again, in yet
    # another order. State is round-tripped as a list (setLastRun serialization).
    mocker.resetall()
    fa2, fb2, fc2 = make_findings()
    run2_client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_A", "finding_B", "finding_C"]}],
        get_findings_res=[{"Findings": [fb2, fc2, fa2]}],
    )

    events_run2, last_ids_after_run2, collect_from_after_run2 = get_events(
        aws_client=run2_client,
        collect_from=collect_from_after_run1,
        collect_from_default=datetime(2026, 8, 1, 13, 18, 0),
        last_ids=last_ids_after_run1,
        severity="Low",
        limit=10,
    )

    # ------------------------------------------------------------ Assertion
    # Nothing new happened — the same second's findings must NOT be re-ingested.
    assert events_run2 == [], (
        f"XSUP-73410 millisecond re-ingest: the same same-second findings were "
        f"re-ingested on run 2, got {[e['Id'] for e in events_run2]}. The inclusive "
        f"Gte re-query returns them and they must all be deduped as already-seen."
    )
    # The cursor must be STABLE — no oscillation within the second across runs.
    assert collect_from_after_run2 == {"det1": ts_c}, (
        f"Cursor must remain stable at the max same-second timestamp across runs, "
        f"got {collect_from_after_run2} (oscillation indicates the churn bug)."
    )
    assert last_ids_after_run2 == {"det1": ["finding_A", "finding_B", "finding_C"]}


# ---------------------------------------------------------------------------
# Regression test for XSUP-71079 (continued) — the FULLY-DEDUPED STALE BOUNDARY
# dead-end (observed live on the BAY ap-southeast-7 detector).
#
# The cursor is second-resolution and the updatedAt query is inclusive (Gte).
# On a quiet detector the fetch can reach a state where the ONLY finding at/after
# the cursor second is one already in last_ids. Every cycle then:
#   1. list_findings returns just that one already-seen id (nothing newer),
#   2. dedup drops it as a same-second sibling -> 0 events,
#   3. the cursor only advances when events are ingested -> it never moves.
# The fetch is wedged forever, even though the boundary second is long in the
# past. Live evidence: the cursor sat frozen at a single second for 9+ hours,
# re-querying one finding, ingesting nothing.
#
# The fix is time-gated: when a fetch is NOT truncated by limit (AWS returned
# everything at/after the cursor) and everything deduped away, AND the boundary
# second is safely in the PAST relative to collect_from_default (so no new
# same-second finding can still arrive), advance the cursor one second past the
# boundary and drop the stale seen_ids. A RECENT boundary must still stay pinned
# (that bounded pause is required by test_same_boundary_reupdate_...).
# ---------------------------------------------------------------------------


def test_stale_fully_deduped_boundary_advances_cursor_xsup_71079(mocker):
    """
    Given:
        A quiet detector whose cursor sits at a second T0 that is well in the
        PAST (hours before collect_from_default/"now"). The only finding the
        inclusive Gte query returns is finding_X, which is already in last_ids
        (an already-ingested same-second finding). The fetch is NOT truncated by
        limit — AWS returned everything at/after T0 and there is nothing newer.

    When:
        get_events runs this cycle.

    Then:
        Nothing is ingested (finding_X is correctly deduped), but because the
        boundary second is stale and fully drained, the cursor MUST advance one
        second past T0 so the next run queries strictly after the dead boundary,
        and the stale seen_ids for that detector MUST be cleared. This breaks the
        perpetual freeze.

        With the pre-fix code the elif-finding_ids branch leaves the cursor and
        seen_ids unchanged, so the cursor stays frozen at T0 forever — these
        assertions fail, proving the dead-end.

    Reference:
        AWSGuardDutyEventCollector.get_events — the fully-deduped-boundary
        advance guard (time-gated so a recent boundary still pins).
    """
    # A fixed past boundary is stale against real wall-clock now — no mocking needed.
    # collect_from_default is the first_fetch lookback FLOOR and is intentionally
    # unrelated to the boundary; the guard must not depend on it.
    collect_from_default_floor = datetime(2020, 1, 1, 0, 0, 0)
    t0 = "2020-01-01T08:19:28.960000"  # years in the past — clearly stale
    t0_plus_1s = "2020-01-01T08:19:29"  # cursor must step to the next second

    stale_only = update_finding_id(FINDING.copy(), "finding_X", updated_at=t0)
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        # Only the already-seen boundary finding is returned; NO NextToken -> not
        # truncated by limit, so AWS has nothing newer at/after T0.
        list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
        get_findings_res=[{"Findings": [stale_only]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t0},
        collect_from_default=collect_from_default_floor,
        last_ids={"det1": ["finding_X"]},
        severity="Low",
        limit=10,
    )

    # Nothing new happened this cycle — the one boundary finding is deduped.
    assert events == [], "The already-seen boundary finding must not be re-ingested."
    # The wedge must break: the cursor steps one whole second past the stale
    # boundary so the next inclusive Gte query starts strictly after it.
    assert new_collect_from == {"det1": t0_plus_1s}, (
        f"Stale fully-deduped boundary must advance the cursor past T0, got "
        f"{new_collect_from} (unchanged == the XSUP-71079 permanent freeze)."
    )
    # The stale seen_ids belonged to the dead boundary second; the new second has
    # no known siblings, so they must be cleared.
    assert new_last_ids == {"det1": []}, f"Seen ids for the abandoned boundary second must be cleared, got {new_last_ids}."


def test_recent_fully_deduped_boundary_stays_pinned_xsup_71079(mocker):
    """
    Given:
        The same fully-deduped single-finding situation as the stale-boundary
        test, but the cursor second is RECENT — only moments before
        collect_from_default/"now". A genuine later-same-second update could
        still arrive, so the cursor must not jump past it yet.

    When:
        get_events runs this cycle.

    Then:
        Nothing is ingested and the cursor stays PINNED at the boundary second
        with its seen_ids preserved (the bounded, correct pause). This guards the
        time-gate: the freeze-breaking advance must fire ONLY for stale
        boundaries, never for a still-current second.

    Reference:
        AWSGuardDutyEventCollector.get_events — the fully-deduped-boundary
        advance is time-gated; a recent boundary keeps the existing pin behavior.
    """
    # Boundary is only a few seconds before real wall-clock now — still current,
    # so it falls inside STALE_BOUNDARY_MARGIN and must stay pinned. No mocking.
    now = datetime.utcnow()
    t_recent = (now - timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%S.%f")

    recent_only = update_finding_id(FINDING.copy(), "finding_X", updated_at=t_recent)
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
        get_findings_res=[{"Findings": [recent_only]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t_recent},
        collect_from_default=now,
        last_ids={"det1": ["finding_X"]},
        severity="Low",
        limit=10,
    )

    assert events == [], "The already-seen finding must not be re-ingested."
    # Recent boundary: keep the bounded pause so a later same-second update is
    # still catchable — cursor and seen_ids unchanged.
    assert new_collect_from == {"det1": t_recent}, f"A recent fully-deduped boundary must stay pinned, got {new_collect_from}."
    assert new_last_ids == {
        "det1": ["finding_X"]
    }, f"Seen ids for a still-current boundary must be preserved, got {new_last_ids}."


def test_stale_boundary_with_a_genuinely_new_finding_ingests_and_does_not_skip_xsup_71079(mocker):
    """
    Given:
        A stale cursor second T0. This cycle the inclusive Gte query returns the
        already-seen boundary finding (finding_old, in last_ids at T0) AND a
        genuinely new finding (finding_new) whose UpdatedAt is a strictly-later
        second T1 — a real occurrence that must be ingested.

    When:
        get_events runs.

    Then:
        finding_new is ingested (it is NOT deduped — its second is past the
        cursor) and the cursor advances to T1 via the NORMAL ingest path. The
        stale-boundary freeze-breaker must NOT fire here (there are events), and
        crucially nothing is skipped: a real update at a stale boundary is never
        lost by the freeze-breaking logic.

    Reference:
        AWSGuardDutyEventCollector.get_events — the stale-boundary advance lives
        in the elif-finding_ids (zero-events) branch only; any real ingestion
        takes the normal path and is unaffected.
    """
    t0 = "2020-01-01T08:19:28.960000"  # stale boundary (already seen)
    t1 = "2020-01-01T08:19:45.100000"  # a genuinely newer second

    finding_old = update_finding_id(FINDING.copy(), "finding_old", updated_at=t0)
    finding_new = update_finding_id(FINDING.copy(), "finding_new", updated_at=t1)
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_old", "finding_new"]}],
        get_findings_res=[{"Findings": [finding_old, finding_new]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t0},
        collect_from_default=datetime(2020, 1, 1, 0, 0, 0),
        last_ids={"det1": ["finding_old"]},
        severity="Low",
        limit=10,
    )

    # The genuinely new finding must be ingested (the old boundary one is deduped).
    assert [e["Id"] for e in events] == [
        "finding_new"
    ], f"A real new finding at a stale boundary must be ingested, got {[e['Id'] for e in events]}."
    # Cursor advances to the new finding's second via the normal ingest path —
    # NOT via the freeze-breaker (+1s), proving the guard did not fire.
    assert new_collect_from == {"det1": t1}, f"Cursor must advance to the ingested finding's timestamp, got {new_collect_from}."
    assert new_last_ids == {
        "det1": ["finding_new"]
    }, f"Only the new cursor-second sibling should be remembered, got {new_last_ids}."


def test_truncated_stale_fully_deduped_boundary_does_not_advance_xsup_71079(mocker):
    """
    Given:
        A stale cursor second T0 whose only returned finding is already-seen (so
        it dedups to zero events), BUT the finding-id listing was TRUNCATED by
        limit — list_findings returned a NextToken, meaning AWS still has
        un-fetched findings that may sit at this same boundary second.

    When:
        get_events runs.

    Then:
        The cursor must NOT advance and seen_ids must be preserved. Even though
        the boundary is stale, advancing past a limit-truncated second could skip
        the un-fetched findings still sitting there. The freeze-breaker is gated
        on `not truncated_by_limit` precisely to prevent that data loss.

    Reference:
        AWSGuardDutyEventCollector.get_events — the stale-boundary advance
        requires a fully-drained (non-truncated) page.
    """
    t0 = "2020-01-01T08:19:28.960000"  # stale boundary

    stale_seen = update_finding_id(FINDING.copy(), "finding_X", updated_at=t0)
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        # NextToken present => the id-listing loop stops on limit with more to
        # fetch, so truncated_by_limit is True.
        list_finding_ids_res=[{"FindingIds": ["finding_X"], "NextToken": "more"}],
        get_findings_res=[{"Findings": [stale_seen]}],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det1": t0},
        collect_from_default=datetime(2020, 1, 1, 0, 0, 0),
        last_ids={"det1": ["finding_X"]},
        severity="Low",
        limit=1,  # force the listing loop to stop with the NextToken still pending
    )

    assert events == [], "Nothing new should be ingested."
    # Truncated page => must NOT advance past the boundary (un-fetched siblings
    # may still be there); cursor and seen_ids stay put.
    assert new_collect_from == {
        "det1": t0
    }, f"A limit-truncated stale boundary must NOT advance the cursor, got {new_collect_from}."
    assert new_last_ids == {
        "det1": ["finding_X"]
    }, f"Seen ids must be preserved when the boundary page was truncated, got {new_last_ids}."


def test_stale_wedged_detector_advances_without_affecting_healthy_detector_xsup_71079(mocker):
    """
    Given:
        Two detectors on one instance:
          - det_stuck: wedged at a stale fully-deduped boundary (only its
            already-seen finding is returned).
          - det_ok: healthy, returning a brand-new finding to ingest.

    When:
        get_events runs over both detectors in one cycle.

    Then:
        det_stuck's cursor is unwedged (advances one second past its stale
        boundary, seen_ids cleared) while det_ok ingests its new finding and
        advances normally. The freeze-breaker is per-detector and must not
        disturb a healthy detector processed in the same run.

    Reference:
        AWSGuardDutyEventCollector.get_events — per-detector cursor/seen-ids
        handling; the stale-boundary advance is scoped to the affected detector.
    """
    t_stale = "2020-01-01T08:19:28.960000"
    t_stale_plus_1s = "2020-01-01T08:19:29"
    t_new = "2020-01-01T17:59:10.500000"  # healthy detector's new finding (ingested via normal path)

    stuck_seen = update_finding_id(FINDING.copy(), "finding_stuck", updated_at=t_stale)
    ok_new = update_finding_id(FINDING.copy(), "finding_ok", updated_at=t_new)

    # Detectors are processed in listing order: det_stuck first, then det_ok.
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det_stuck", "det_ok"]}],
        list_finding_ids_res=[
            {"FindingIds": ["finding_stuck"]},  # det_stuck listing
            {"FindingIds": ["finding_ok"]},  # det_ok listing
        ],
        get_findings_res=[
            {"Findings": [stuck_seen]},  # det_stuck get_findings
            {"Findings": [ok_new]},  # det_ok get_findings
        ],
    )

    events, new_last_ids, new_collect_from = get_events(
        aws_client=client,
        collect_from={"det_stuck": t_stale},  # det_ok has no prior cursor
        collect_from_default=datetime(2020, 1, 1, 0, 0, 0),
        last_ids={"det_stuck": ["finding_stuck"]},
        severity="Low",
        limit=10,
    )

    # Only the healthy detector's new finding is ingested.
    assert [e["Id"] for e in events] == [
        "finding_ok"
    ], f"Healthy detector's new finding must be ingested, got {[e['Id'] for e in events]}."
    # Stuck detector unwedged; healthy detector advanced normally to its finding.
    assert new_collect_from == {"det_stuck": t_stale_plus_1s, "det_ok": t_new}, (
        f"Stuck detector must advance past its stale boundary and healthy detector "
        f"must advance to its ingested finding, got {new_collect_from}."
    )
    # Stuck detector's stale seen_ids cleared; healthy detector remembers its sibling.
    assert new_last_ids == {"det_stuck": [], "det_ok": ["finding_ok"]}, f"Per-detector seen ids incorrect, got {new_last_ids}."


def test_z_suffixed_stale_cursor_is_comparable_to_wallclock_now_xsup_71079(mocker):
    """
    Given:
        The cursor is a real GuardDuty timestamp string in UTC "Z" form
        (e.g. "2020-01-01T08:19:28.960Z"), matching what GuardDuty emits, and the
        only finding returned is already-seen (fully deduped, not truncated).

    When:
        get_events evaluates the stale-boundary guard, which compares the parsed
        cursor second against datetime.utcnow().

    Then:
        The comparison must not raise (parse_date_string yields a NAIVE UTC
        datetime for "Z" input, and utcnow() is also naive UTC), and the stale
        boundary must advance normally. This pins the naive-UTC assumption so a
        future change to timestamp parsing can't silently break the comparison
        (e.g. by introducing an offset-aware datetime, which would raise
        "can't compare offset-naive and offset-aware datetimes").

    Reference:
        AWSGuardDutyEventCollector.get_events — staleness compares the parsed
        cursor second to naive-UTC now.
    """
    t0_z = "2020-01-01T08:19:28.960Z"  # real GuardDuty UTC "Z" form, years past
    t0_plus_1s = "2020-01-01T08:19:29"

    stale_only = update_finding_id(FINDING.copy(), "finding_X", updated_at=t0_z)
    client, _, _, _ = create_mocked_client(
        mocker=mocker,
        list_detectors_res=[{"DetectorIds": ["det1"]}],
        list_finding_ids_res=[{"FindingIds": ["finding_X"]}],
        get_findings_res=[{"Findings": [stale_only]}],
    )

    with does_not_raise():
        events, new_last_ids, new_collect_from = get_events(
            aws_client=client,
            collect_from={"det1": t0_z},
            collect_from_default=datetime(2020, 1, 1, 0, 0, 0),
            last_ids={"det1": ["finding_X"]},
            severity="Low",
            limit=10,
        )

    assert events == [], "The already-seen boundary finding must not be re-ingested."
    assert new_collect_from == {"det1": t0_plus_1s}, (
        f"A Z-suffixed stale boundary must compare cleanly to naive-UTC now and advance, " f"got {new_collect_from}."
    )
    assert new_last_ids == {"det1": []}, f"Seen ids for the abandoned boundary second must be cleared, got {new_last_ids}."

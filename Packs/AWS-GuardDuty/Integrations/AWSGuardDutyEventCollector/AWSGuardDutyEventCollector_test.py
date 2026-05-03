from contextlib import nullcontext as does_not_raise
from datetime import datetime
from unittest.mock import call

import pytest
from AWSGuardDutyEventCollector import get_events
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
            {"detector_id1": ["finding_id1"]},
            id="1 detector, 1 new finding, 1 old finding",
        ),
        pytest.param(
            {"detector_id1": "2022-08-28T10:12:39.923854"},
            {"detector_id1": "finding_id0"},
            [{"DetectorIds": ["detector_id1"]}],
            [{"FindingIds": ["finding_id0"]}],
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
            id="1 detector, 1 old finding",
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
    assert run1_ids == ["finding_A", "finding_B"], (
        f"Sanity check failed: run 1 should ingest A and B, got {run1_ids}"
    )
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

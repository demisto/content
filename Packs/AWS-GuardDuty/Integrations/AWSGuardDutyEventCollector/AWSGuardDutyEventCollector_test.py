import pytest
from contextlib import nullcontext as does_not_raise
from datetime import datetime
from unittest.mock import call

from AWSGuardDutyEventCollector import get_events
from test_data.finding_for_test import FINDING, FINDING_OUTPUT, MOST_GENERAL_FINDING, MOST_GENERAL_FINDING_STR


LIST_DETECTORS_RESPONSE = {
    "DetectorIds": ["detector_id1"]
}

LIST_DETECTORS_RESPONSE_NONE_NEXT_TOKEN = {
    "DetectorIds": ["detector_id1"],
    "NextToken": None
}

LIST_FINDING_IDS_RESPONSE = {
    "FindingIds": ["finding_id1"]
}

LIST_FINDING_IDS_RESPONSE_NONE_NEXT_TOKEN = {
    "FindingIds": ["finding_id1"],
    "NextToken": None
}

FINDINGS = {
    "Findings": [FINDING]
}


def get_expected_list_finding_args(detector_id: str, updated_at_ts: int, gd_severity: int, max_results: int | None,
                                   next_token: str | None):
    """Return arguments as expected in the AWSClient session list_finding function."""
    list_finding_args = {
        'DetectorId': detector_id,
        'FindingCriteria': {
            'Criterion': {
                'updatedAt': {'Gte': updated_at_ts},
                'severity': {'Gte': gd_severity}
            }
        },
        'SortCriteria': {
            'AttributeName': 'updatedAt',
            'OrderBy': 'ASC'
        },
        'MaxResults': max_results
    }
    if next_token:
        list_finding_args.update({'NextToken': next_token})
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
    list_detectors_mock = mocker.patch.object(MockedBoto3Client, 'list_detectors', side_effect=list_detectors_res)
    list_findings_mock = mocker.patch.object(MockedBoto3Client, 'list_findings', side_effect=list_finding_ids_res)
    get_findings_mock = mocker.patch.object(MockedBoto3Client, 'get_findings', side_effect=get_findings_res)
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
        get_findings_res=[FINDINGS])

    with does_not_raise():
        get_events(aws_client=mocked_client,
                   collect_from={},
                   collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
                   last_ids={},
                   severity='Low',
                   limit=1,
                   detectors_num=1)

    assert list_detectors_mock.is_called_once()
    assert list_findings_mock.is_called_once()
    assert get_findings_mock.is_called_once()


@pytest.mark.parametrize('limit, severity, list_detectors_res, list_finding_ids_res, findings_res, '
                         'list_detectors_calls, list_findings_calls, get_findings_calls, expected_events',
                         [pytest.param(1, 'Low', [LIST_DETECTORS_RESPONSE], [LIST_FINDING_IDS_RESPONSE], [FINDINGS],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=1,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1'])],
                                       [FINDING_OUTPUT],
                                       id='simple, no next tokens, low severity'),
                          pytest.param(10, 'Low', [{"DetectorIds": ["detector_id1"], "NextToken": "next"},
                                                   {"DetectorIds": ["detector_id2"]}],
                                       [{"FindingIds": ["finding_id1"]}, {"FindingIds": ["finding_id2"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1")]},
                                        {"Findings": [update_finding_id(FINDING.copy(), "finding_id2")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None)),
                                        call(**get_expected_list_finding_args(detector_id='detector_id2',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=9,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1']),
                                        call(DetectorId='detector_id2', FindingIds=['finding_id2'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id2")],
                                       id='2 detectors'),
                          pytest.param(10, 'Low', [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id1"], "NextToken": "next"},
                                        {"FindingIds": ["finding_id2"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1"),
                                                      update_finding_id(FINDING.copy(), "finding_id2")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None)),
                                        call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=9,
                                                                              next_token='next'))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1', 'finding_id2'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id2")],
                                       id='1 detector, paginated findings'),
                          pytest.param(10, 'Low', [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id1", "finding_id2"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1"),
                                                      update_finding_id(FINDING.copy(), "finding_id2")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1', 'finding_id2'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id2")],
                                       id='1 detector, 2 findings'),
                          pytest.param(10, 'Low', [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id1"]}],
                                       [{"Findings": [update_finding_id(MOST_GENERAL_FINDING.copy(), "finding_id1")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1'])],
                                       [update_finding_id(MOST_GENERAL_FINDING_STR.copy(), "finding_id1")],
                                       id='check datetime to str conversion in all fields'),
                          pytest.param(1, 'Medium', [LIST_DETECTORS_RESPONSE], [LIST_FINDING_IDS_RESPONSE], [FINDINGS],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=4,
                                                                              max_results=1,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1'])],
                                       [FINDING_OUTPUT],
                                       id='simple, no next tokens, medium severity'),
                          pytest.param(1, 'High', [LIST_DETECTORS_RESPONSE], [LIST_FINDING_IDS_RESPONSE], [FINDINGS],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=7,
                                                                              max_results=1,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1'])],
                                       [FINDING_OUTPUT],
                                       id='simple, no next tokens, high severity')

                          ])
def test_get_events_command(mocker, limit, severity, list_detectors_res, list_finding_ids_res, findings_res,
                            list_detectors_calls, list_findings_calls, get_findings_calls, expected_events):
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
        get_findings_res=findings_res)

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={},
        collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
        last_ids={},
        severity=severity,
        limit=limit)

    list_detectors_mock.assert_has_calls(list_detectors_calls)
    list_findings_mock.assert_has_calls(list_findings_calls)
    get_findings_mock.assert_has_calls(get_findings_calls)
    assert events == expected_events


@pytest.mark.parametrize('list_detectors_res, list_finding_ids_res, findings_res, '
                         'list_detectors_calls, list_findings_calls, get_findings_calls, expected_events',
                         [pytest.param([{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id1", "finding_id2", "finding_id3", "finding_id4",
                                                        "finding_id5"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1"),
                                                      update_finding_id(FINDING.copy(), "finding_id2")]},
                                        {"Findings": [update_finding_id(FINDING.copy(), "finding_id3"),
                                                      update_finding_id(FINDING.copy(), "finding_id4")]},
                                        {"Findings": [update_finding_id(FINDING.copy(), "finding_id5")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1', 'finding_id2']),
                                        call(DetectorId='detector_id1', FindingIds=['finding_id3', 'finding_id4']),
                                        call(DetectorId='detector_id1', FindingIds=['finding_id5'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id2"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id3"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id4"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id5")],
                                       id='1 detector, 5 findings, 2 is request limit')])
def test_get_events_with_chunked_finding_ids(mocker, list_detectors_res, list_finding_ids_res, findings_res,
                                             list_detectors_calls, list_findings_calls, get_findings_calls,
                                             expected_events):
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
        get_findings_res=findings_res)

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={},
        collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
        last_ids={},
        severity='Low',
        limit=10,
        max_ids_per_req=2)

    list_detectors_mock.assert_has_calls(list_detectors_calls)
    list_findings_mock.assert_has_calls(list_findings_calls)
    get_findings_mock.assert_has_calls(get_findings_calls)
    assert events == expected_events


@pytest.mark.parametrize('list_detectors_res, list_finding_ids_res, findings_res',
                         [pytest.param([{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id1"]}],
                                       [{"Findings": [update_finding_id(MOST_GENERAL_FINDING.copy(), "finding_id1")]}],
                                       id='datetime to str conversion in all available fields')
                          ])
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
        get_findings_res=findings_res)

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from={},
        collect_from_default=datetime(2022, 8, 28, 10, 12, 39, 923854),
        last_ids={},
        severity='Low',
        limit=10)

    assert len(events) == 1

    event_resource = events[0].get('Resource', {})
    event_service = events[0].get('Service', {})
    assert type(event_resource.get('EksClusterDetails', {}).get('CreatedAt')) is str
    assert type(event_resource.get('EcsClusterDetails', {}).get('TaskDetails', {}).get('TaskCreatedAt')) is str
    assert type(event_resource.get('EcsClusterDetails', {}).get('TaskDetails', {}).get('StartedAt')) is str
    assert type(event_service.get('EbsVolumeScanDetails', {}).get('ScanStartedAt')) is str
    assert type(event_service.get('EbsVolumeScanDetails', {}).get('ScanCompletedAt')) is str


@pytest.mark.parametrize('collect_from, last_ids, list_detectors_res, list_finding_ids_res, findings_res, '
                         'list_detectors_calls, list_findings_calls, get_findings_calls, expected_events, '
                         'expected_new_collect_from, expected_new_last_ids',
                         [pytest.param({"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id1"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1",
                                                                        updated_at="2022-09-28T10:12:39.923854")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1",
                                                          updated_at="2022-09-28T10:12:39.923854")],
                                       {"detector_id1": "2022-09-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id1"},
                                       id='1 detector, 1 new finding'),
                          pytest.param({"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id0", "finding_id1"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1",
                                                                        updated_at="2022-09-28T10:12:39.923854")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1",
                                                          updated_at="2022-09-28T10:12:39.923854")],
                                       {"detector_id1": "2022-09-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id1"},
                                       id='1 detector, 1 new finding, 1 old finding'),
                          pytest.param({"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": ["finding_id0"]}],
                                       [],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [], [],
                                       {"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       id='1 detector, 1 old finding'),
                          pytest.param({"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       [{"DetectorIds": ["detector_id1"]}],
                                       [{"FindingIds": []}],
                                       [],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None))],
                                       [], [],
                                       {"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       id='1 detector, no findings'),
                          pytest.param({"detector_id1": "2022-08-28T10:12:39.923854"},
                                       {"detector_id1": "finding_id0"},
                                       [{"DetectorIds": ["detector_id1", "detector_id2"]}],
                                       [{"FindingIds": ["finding_id1"]}, {"FindingIds": ["finding_id2"]}],
                                       [{"Findings": [update_finding_id(FINDING.copy(), "finding_id1",
                                                                        updated_at="2022-09-28T10:12:39.923854")]},
                                        {"Findings": [update_finding_id(FINDING.copy(), "finding_id2",
                                                                        updated_at="2022-07-29T10:12:39.923854")]}],
                                       [call(MaxResults=50)],
                                       [call(**get_expected_list_finding_args(detector_id='detector_id1',
                                                                              updated_at_ts=1661681559000,
                                                                              gd_severity=1,
                                                                              max_results=10,
                                                                              next_token=None)),
                                        call(**get_expected_list_finding_args(detector_id='detector_id2',
                                                                              updated_at_ts=1659003099000,
                                                                              gd_severity=1,
                                                                              max_results=9,
                                                                              next_token=None))],
                                       [call(DetectorId='detector_id1', FindingIds=['finding_id1']),
                                        call(DetectorId='detector_id2', FindingIds=['finding_id2'])],
                                       [update_finding_id(FINDING_OUTPUT.copy(), "finding_id1",
                                                          updated_at="2022-09-28T10:12:39.923854"),
                                        update_finding_id(FINDING_OUTPUT.copy(), "finding_id2",
                                                          updated_at="2022-07-29T10:12:39.923854")],
                                       {"detector_id1": "2022-09-28T10:12:39.923854",
                                        "detector_id2": "2022-07-29T10:12:39.923854"},
                                       {"detector_id1": "finding_id1",
                                        "detector_id2": "finding_id2"},
                                       id='1 old detector, 1 new detector, 1 new finding each')
                          ])
def test_fetch_events(mocker, collect_from, last_ids, list_detectors_res, list_finding_ids_res, findings_res,
                      list_detectors_calls, list_findings_calls, get_findings_calls,
                      expected_events, expected_new_collect_from, expected_new_last_ids):
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
        get_findings_res=findings_res)

    events, new_last_ids, new_collect_from = get_events(
        aws_client=mocked_client,
        collect_from=collect_from,
        collect_from_default=datetime(2022, 7, 28, 10, 11, 39, 923854),
        last_ids=last_ids,
        severity='Low',
        limit=10)

    list_detectors_mock.assert_has_calls(list_detectors_calls)
    list_findings_mock.assert_has_calls(list_findings_calls)
    get_findings_mock.assert_has_calls(get_findings_calls)
    assert events == expected_events
    assert new_collect_from == expected_new_collect_from
    assert new_last_ids == expected_new_last_ids

import json
from contextlib import nullcontext as does_not_raise
import demistomock as demisto  # noqa: F401

from AWSGuardDuty import get_members, parse_incident_from_finding, connection_test, list_members, \
    update_findings_feedback, archive_findings, unarchive_findings, create_sample_findings, get_findings, \
    list_findings, update_threat_intel_set, list_threat_intel_sets, get_threat_intel_set, delete_threat_intel_set, \
    create_threat_intel_set, update_ip_set, delete_ip_set, update_detector, delete_detector, list_ip_sets, get_ip_set, \
    create_ip_set, list_detectors, get_detector, create_detector, fetch_incidents
from test_data.api_responses_for_test import GET_MEMBERS_RESPONSE, FINDING, LIST_MEMBERS_RESPONSE, \
    THREAT_INTEL_SET_RESPONSE, IP_SET_RESPONSE, DETECTOR_RESPONSE, RESPONSE_METADATA

import pytest


class MockedBoto3Client:
    """Mocked AWSClient session for easier expectation settings."""

    def list_detectors(self, **kwargs):
        pass

    def list_findings(self, **kwargs):
        pass

    def get_findings(self, **kwargs):
        pass

    def archive_findings(self, **kwargs):
        pass

    def create_sample_findings(self, **kwargs):
        pass

    def unarchive_findings(self, **kwargs):
        pass

    def update_findings_feedback(self, **kwargs):
        pass

    def list_members(self, **kwargs):
        pass

    def get_members(self, **kwargs):
        pass

    def create_detector(self, **kwargs):
        pass

    def update_detector(self, **kwargs):
        pass

    def delete_detector(self, **kwargs):
        pass

    def get_detector(self, **kwargs):
        pass

    def create_ip_set(self, **kwargs):
        pass

    def delete_ip_set(self, **kwargs):
        pass

    def update_ip_set(self, **kwargs):
        pass

    def get_ip_set(self, **kwargs):
        pass

    def list_ip_sets(self, **kwargs):
        pass

    def create_threat_intel_set(self, **kwargs):
        pass

    def delete_threat_intel_set(self, **kwargs):
        pass

    def get_threat_intel_set(self, **kwargs):
        pass

    def list_threat_intel_sets(self, **kwargs):
        pass

    def update_threat_intel_set(self, **kwargs):
        pass

    def get_paginator(self, **kwargs):
        pass


def test_get_members(mocker):
    """
    Given
    - get-members command

    When
    - running get-members, that returns empty map

    Then
    - Ensure that empty map is not returned to the context
    """
    client = MockedBoto3Client()
    get_members_mock = mocker.patch.object(MockedBoto3Client, 'get_members', side_effect=[GET_MEMBERS_RESPONSE])
    command_results = get_members(client, {})
    assert command_results.outputs == [{'AccountId': 1, 'DetectorId': 1, 'MasterId': 1}]
    assert get_members_mock.is_called_once()


def test_parse_incident_from_finding():
    """
    Given:
    - Amazon GuardDuty finding with datetime object nested in it

    When:
    - Parsing finding to incident

    Then:
    - Ensure finding is parsed as expected
    """
    title = 'title'
    desc = 'desc'
    incident = parse_incident_from_finding(FINDING)
    assert incident['name'] == title
    assert incident['details'] == desc
    assert incident['severity'] == 0
    assert '2015-01-01' in incident['rawJSON']


@pytest.mark.parametrize('response, raises', [pytest.param({"DetectorIds": ["detector_id1"]}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param({}, pytest.raises(Exception), id='Failure')])
def test_test_module(mocker, response, raises):
    """
    Given:
        AWSClient session
        list_detectors valid responses

    When:
        Running test-module command

    Then:
        assert no exception is being raised.
        assert api calls are called exactly once.
    """
    mocked_client = MockedBoto3Client()
    list_detectors_mock = mocker.patch.object(MockedBoto3Client, 'list_detectors', side_effect=[response])

    with raises:
        connection_test(mocked_client)

    assert list_detectors_mock.is_called_once()


def test_list_members(mocker):
    """
    Given:
        AWSClient session
        list_members valid response

    When:
        Running list_members command

    Then:
        assert no exception is being raised.
        assert api calls are called exactly once.
    """
    mocked_client = MockedBoto3Client()
    get_paginator_mock = mocker.patch.object(MockedBoto3Client, 'get_paginator', side_effect=[MockedPaginator()])
    paginate_mock = mocker.patch.object(MockedPaginator, 'paginate', side_effect=[[LIST_MEMBERS_RESPONSE]])

    command_results = list_members(mocked_client, {'detectorId': 'some_id'})

    get_paginator_mock.assert_called_with('list_members')
    paginate_mock.assert_called_with(DetectorId='some_id', PaginationConfig={'MaxItems': 50, 'PageSize': 50})
    assert command_results.outputs == [{'Member': LIST_MEMBERS_RESPONSE.get('Members')[0]}]


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_update_findings_feedback(mocker, response, raises):
    """
    Given:
        AWSClient session
        update_findings_feedback various response

    When:
        Running update_findings_feedback command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once.
    """
    mocked_client = MockedBoto3Client()
    update_findings_feedback_mock = mocker.patch.object(MockedBoto3Client, 'update_findings_feedback',
                                                        side_effect=[response])

    with raises:
        update_findings_feedback(mocked_client, {'detectorId': 'some_id',
                                                 'findingIds': 'finding_id1, finding_id2',
                                                 'comments': 'some_comment1, some_comment2',
                                                 'feedback': 'some_feedback1, some_feedback2'})

    update_findings_feedback_mock.assert_called_with(DetectorId='some_id',
                                                     FindingIds=['finding_id1', 'finding_id2'],
                                                     Comments=['some_comment1', 'some_comment2'],
                                                     Feedback=['some_feedback1', 'some_feedback2'])


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_archive_findings(mocker, response, raises):
    """
    Given:
        AWSClient session
        archive_findings various response

    When:
        Running archive_findings command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once.
    """
    mocked_client = MockedBoto3Client()
    archive_findings_mock = mocker.patch.object(MockedBoto3Client, 'archive_findings',
                                                side_effect=[response])

    with raises:
        archive_findings(mocked_client, {'detectorId': 'some_id',
                                         'findingIds': 'finding_id1, finding_id2'})

    archive_findings_mock.assert_called_with(DetectorId='some_id',
                                             FindingIds=['finding_id1', 'finding_id2'])


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_unarchive_findings(mocker, response, raises):
    """
    Given:
        AWSClient session
        unarchive_findings various response

    When:
        Running unarchive_findings command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once.
    """
    mocked_client = MockedBoto3Client()
    unarchive_findings_mock = mocker.patch.object(MockedBoto3Client, 'unarchive_findings',
                                                  side_effect=[response])

    with raises:
        unarchive_findings(mocked_client, {'detectorId': 'some_id',
                                           'findingIds': 'finding_id1, finding_id2'})

    unarchive_findings_mock.assert_called_with(DetectorId='some_id', FindingIds=['finding_id1', 'finding_id2'])


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_create_sample_findings(mocker, response, raises):
    """
    Given:
        AWSClient session
        create_sample_findings various response

    When:
        Running create_sample_findings command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once.
    """
    mocked_client = MockedBoto3Client()
    create_sample_findings_mock = mocker.patch.object(MockedBoto3Client, 'create_sample_findings',
                                                      side_effect=[response])

    with raises:
        create_sample_findings(mocked_client, {'detectorId': 'some_id',
                                               'findingTypes': 'finding_type1, finding_type2'})

    create_sample_findings_mock.assert_called_with(DetectorId='some_id',
                                                   FindingTypes=['finding_type1', 'finding_type2'])


EXPECTED_FINDING_RESULT = {'AccountId': 'string',
                           'Arn': 'string',
                           'CreatedAt': 'string',
                           'Description': 'desc',
                           'Id': 'string',
                           'Region': 'string',
                           'Title': 'title',
                           'Type': 'string'}


def test_get_findings(mocker):
    """
    Given:
        AWSClient session
        get_findings valid response

    When:
        Running get_findings command

    Then:
        assert api calls are called exactly once and as expected.
    """
    from test_data.get_findings_expected_outputs import EXPECTED_FINDING_OUTPUTS
    mocked_client = MockedBoto3Client()
    get_findings_mock = mocker.patch.object(MockedBoto3Client, 'get_findings',
                                            side_effect=[{'Findings': [FINDING,
                                                                       update_finding_id(FINDING.copy(),
                                                                                         'finding2',
                                                                                         '2022-09-07T13:48:00.814Z')]}])

    command_results = get_findings(mocked_client, {'detectorId': 'some_id',
                                                   'findingIds': 'finding_id1, finding_id2'})

    get_findings_mock.assert_called_with(DetectorId='some_id',
                                         FindingIds=['finding_id1', 'finding_id2'])
    assert command_results.get('EntryContext') == EXPECTED_FINDING_OUTPUTS


class MockedPaginator:
    def paginate(self, **kwargs):
        pass


def test_list_findings(mocker):
    """
    Given:
        AWSClient session
        list_findings valid response

    When:
        Running list_findings command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_paginator_mock = mocker.patch.object(MockedBoto3Client, 'get_paginator', side_effect=[MockedPaginator()])
    paginate_mock = mocker.patch.object(MockedPaginator, 'paginate', side_effect=[
        [{'FindingIds': ['finding1', 'finding2']}, {'FindingIds': ['finding3', 'finding4']}]])

    command_results = list_findings(mocked_client, {'detectorId': 'some_id'})

    get_paginator_mock.assert_called_with('list_findings')
    paginate_mock.assert_called_with(DetectorId='some_id', PaginationConfig={'MaxItems': 50, 'PageSize': 50})

    assert command_results.outputs == [{'FindingId': 'finding1'},
                                       {'FindingId': 'finding2'},
                                       {'FindingId': 'finding3'},
                                       {'FindingId': 'finding4'}]


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_update_threat_intel_set(mocker, response, raises):
    """
    Given:
        AWSClient session
        update_threat_intel_set various responses

    When:
        Running update_threat_intel_set command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    update_threat_intel_set_mock = mocker.patch.object(MockedBoto3Client, 'update_threat_intel_set',
                                                       side_effect=[response])

    with raises:
        update_threat_intel_set(mocked_client, {'detectorId': 'some_id',
                                                'threatIntelSetId': 'ThreatIntelSetId1',
                                                'activate': 'True',
                                                'location': 'here',
                                                'name': 'some_name'})

    update_threat_intel_set_mock.assert_called_with(DetectorId='some_id',
                                                    ThreatIntelSetId='ThreatIntelSetId1',
                                                    Activate=True,
                                                    Location='here',
                                                    Name='some_name')


EXPECTED_THREAT_INTEL_RESULT = {'DetectorId': 'some_id',
                                'Format': 'TXT',
                                'Location': 'string',
                                'Name': 'string',
                                'Status': 'INACTIVE',
                                'ThreatIntelSetId': 'threat_id1'}


def test_get_threat_intel_set(mocker):
    """
    Given:
        AWSClient session
        get_threat_intel_set valid response

    When:
        Running get_threat_intel_set command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_threat_intel_set_mock = mocker.patch.object(MockedBoto3Client, 'get_threat_intel_set',
                                                    side_effect=[THREAT_INTEL_SET_RESPONSE])

    command_results = get_threat_intel_set(mocked_client, {'detectorId': 'some_id', 'threatIntelSetId': 'threat_id1'})

    get_threat_intel_set_mock.assert_called_with(DetectorId='some_id', ThreatIntelSetId='threat_id1')
    assert command_results.outputs == EXPECTED_THREAT_INTEL_RESULT


def test_list_threat_intel_sets(mocker):
    """
    Given:
        AWSClient session
        list_threat_intel_set valid response

    When:
        Running list_threat_intel_set command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_paginator_mock = mocker.patch.object(MockedBoto3Client, 'get_paginator', side_effect=[MockedPaginator()])
    paginate_mock = mocker.patch.object(MockedPaginator, 'paginate',
                                        side_effect=[[{'ThreatIntelSetIds': ['threat1', 'threat2']}]])

    command_results = list_threat_intel_sets(mocked_client, {'detectorId': 'some_id'})

    get_paginator_mock.assert_called_with('list_threat_intel_sets')
    paginate_mock.assert_called_with(DetectorId='some_id', PaginationConfig={'MaxItems': 50, 'PageSize': 50})
    assert command_results.outputs == [{'DetectorId': 'some_id'},
                                       {'ThreatIntelSetId': 'threat1'},
                                       {'ThreatIntelSetId': 'threat2'}]


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_delete_threat_intel_set(mocker, response, raises):
    """
    Given:
        AWSClient session
        list_threat_intel_set various response

    When:
        Running list_threat_intel_set command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    delete_threat_intel_set_mock = mocker.patch.object(MockedBoto3Client, 'delete_threat_intel_set',
                                                       side_effect=[response])

    with raises:
        delete_threat_intel_set(mocked_client, {'detectorId': 'some_id',
                                                'threatIntelSetId': 'ThreatIntelSetId1'})

    delete_threat_intel_set_mock.assert_called_with(DetectorId='some_id',
                                                    ThreatIntelSetId='ThreatIntelSetId1')


def test_create_threat_intel_set(mocker):
    """
    Given:
        AWSClient session
        create_threat_intel_set valid response

    When:
        Running create_threat_intel_set command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    create_threat_intel_set_mock = mocker.patch.object(MockedBoto3Client, 'create_threat_intel_set',
                                                       side_effect=[{'ThreatIntelSetId': 'threat1'}])

    command_results = create_threat_intel_set(mocked_client, {'detectorId': 'some_id',
                                                              'activate': 'True',
                                                              'format': 'some_format',
                                                              'location': 'some_location',
                                                              'name': 'some_name'})

    create_threat_intel_set_mock.assert_called_with(DetectorId='some_id',
                                                    Activate=True,
                                                    Format='some_format',
                                                    Location='some_location',
                                                    Name='some_name')
    assert command_results.outputs == {'DetectorId': 'some_id',
                                       'ThreatIntelSetId': 'threat1'}


EXPECTED_IP_SET_RESULT = {
    'DetectorId': 'some_id',
    'Format': 'TXT',
    'IpSetId': 'ipset1',
    'Location': 'string',
    'Name': 'string',
    'Status': 'INACTIVE'
}


def test_get_ip_set(mocker):
    """
    Given:
        AWSClient session
        get_ip_set valid response

    When:
        Running get_ip_set command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_ip_set_mock = mocker.patch.object(MockedBoto3Client, 'get_ip_set',
                                          side_effect=[IP_SET_RESPONSE])

    command_results = get_ip_set(mocked_client, {'detectorId': 'some_id', 'ipSetId': 'ipset1'})

    get_ip_set_mock.assert_called_with(DetectorId='some_id', IpSetId='ipset1')
    assert command_results.outputs == EXPECTED_IP_SET_RESULT


def test_list_ip_sets(mocker):
    """
    Given:
        AWSClient session
        list_ip_sets valid response

    When:
        Running list_ip_sets command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_paginator_mock = mocker.patch.object(MockedBoto3Client, 'get_paginator', side_effect=[MockedPaginator()])
    paginate_mock = mocker.patch.object(MockedPaginator, 'paginate', side_effect=[[{'IpSetIds': ['ipset1', 'ipset2']}]])

    command_results = list_ip_sets(mocked_client, {'detectorId': 'some_id'})

    get_paginator_mock.assert_called_with('list_ip_sets')
    paginate_mock.assert_called_with(DetectorId='some_id', PaginationConfig={'MaxItems': 50, 'PageSize': 50})

    assert command_results.outputs == [{'DetectorId': 'some_id'},
                                       {'IpSetId': 'ipset1'},
                                       {'IpSetId': 'ipset2'}]


def test_create_ip_set(mocker):
    """
    Given:
        AWSClient session
        create_ip_set valid response

    When:
        Running create_ip_set command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    create_ip_set_mock = mocker.patch.object(MockedBoto3Client, 'create_ip_set',
                                             side_effect=[{'IpSetId': 'ipset1'}])

    command_results = create_ip_set(mocked_client, {'detectorId': 'some_id',
                                                    'activate': 'True',
                                                    'format': 'some_format',
                                                    'location': 'some_location',
                                                    'name': 'some_name'})

    create_ip_set_mock.assert_called_with(DetectorId='some_id',
                                          Activate=True,
                                          Format='some_format',
                                          Location='some_location',
                                          Name='some_name')
    assert command_results.outputs == {'DetectorId': 'some_id',
                                       'IpSetId': 'ipset1'}


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_update_ip_set(mocker, response, raises):
    """
    Given:
        AWSClient session
        update_ip_set various response

    When:
        Running update_ip_set command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    update_ip_set_mock = mocker.patch.object(MockedBoto3Client, 'update_ip_set', side_effect=[response])

    with raises:
        update_ip_set(mocked_client, {'detectorId': 'some_id',
                                      'ipSetId': 'ipSetId1',
                                      'activate': 'True',
                                      'location': 'here',
                                      'name': 'some_name'})

    update_ip_set_mock.assert_called_with(DetectorId='some_id',
                                          IpSetId='ipSetId1',
                                          Activate=True,
                                          Location='here',
                                          Name='some_name')


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_delete_ip_set(mocker, response, raises):
    """
    Given:
        AWSClient session
        delete_ip_set various response

    When:
        Running delete_ip_set command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    delete_ip_set_mock = mocker.patch.object(MockedBoto3Client, 'delete_ip_set', side_effect=[response])

    with raises:
        delete_ip_set(mocked_client, {'detectorId': 'some_id',
                                      'ipSetId': 'IpSetId1'})

    delete_ip_set_mock.assert_called_with(DetectorId='some_id',
                                          IpSetId='IpSetId1')


@pytest.mark.parametrize('args, response_iterator, expected_pagination_config, expected_results', [
    ({'limit': '1'}, [{'DetectorIds': ['detector1']}],
     {'MaxItems': 1, 'PageSize': 50}, [{'DetectorId': 'detector1'}]),
    ({'page_size': '2', 'page': '2'}, [{'DetectorIds': ['detector1', 'detector2']},
                                       {'DetectorIds': ['detector3', 'detector4']}],
     {'MaxItems': 4, 'PageSize': 2}, [{'DetectorId': 'detector3'}, {'DetectorId': 'detector4'}])])
def test_list_detectors(mocker, args, response_iterator, expected_pagination_config, expected_results):
    """
    Given:
        AWSClient session
        list_detectors valid response

    When:
        Running list_detectors command with: 1. limit = 1 (Automatic Pagination)
                                             2. page_size = 2, page = 2 (Manual Pagination)
    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_paginator_mock = mocker.patch.object(MockedBoto3Client, 'get_paginator', side_effect=[MockedPaginator()])
    paginate_mock = mocker.patch.object(MockedPaginator, 'paginate', side_effect=[response_iterator])

    command_results = list_detectors(mocked_client, args)

    get_paginator_mock.assert_called_with('list_detectors')
    paginate_mock.assert_called_with(PaginationConfig=expected_pagination_config)
    assert command_results.outputs == expected_results


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_update_detector(mocker, response, raises):
    """
    Given:
        AWSClient session
        update_detector various response

    When:
        Running update_detector command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    update_detector_mock = mocker.patch.object(MockedBoto3Client, 'update_detector', side_effect=[response])

    with raises:
        update_detector(mocked_client, {'enable': 'True', 'detectorId': "some_id", 'findingFrequency': 'One Hour',
                                        'enableKubernetesLogs': 'True',
                                        'ebsVolumesMalwareProtection': 'True',
                                        'enableS3Logs': 'True'})
    assert update_detector_mock.call_args_list[0][1] == {'Enable': True, 'DetectorId': 'some_id',
                                                         'FindingPublishingFrequency': 'ONE_HOUR',
                                                         'DataSources': {'S3Logs': {'Enable': True},
                                                                         'Kubernetes': {'AuditLogs': {'Enable': True}},
                                                                         'MalwareProtection':
                                                                             {'ScanEc2InstanceWithFindings': {
                                                                                 'EbsVolumes': True}}}}


@pytest.mark.parametrize('response, raises', [pytest.param({}, does_not_raise(),
                                                           id='Success'),
                                              pytest.param(RESPONSE_METADATA, does_not_raise(),
                                                           id='Success with Metadata'),
                                              pytest.param({'response': 'bad'}, pytest.raises(Exception),
                                                           id='Failure')])
def test_delete_detector(mocker, response, raises):
    """
    Given:
        AWSClient session
        delete_detector various response

    When:
        Running delete_detector command

    Then:
        assert exceptions are being raised according to api response
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    delete_detector_mock = mocker.patch.object(MockedBoto3Client, 'delete_detector', side_effect=[response])

    with raises:
        delete_detector(mocked_client, {'detectorId': 'some_id', 'ipSetId': 'IpSetId1'})

    delete_detector_mock.assert_called_with(DetectorId='some_id')


EXPECTED_DETECTOR_RESPONSE = {
    'CloudTrailStatus': 'ENABLED',
    'CreatedAt': 'string',
    'DNSLogsStatus': 'ENABLED',
    'DetectorId': 'some_id',
    'FlowLogsStatus': 'ENABLED',
    'KubernetesAuditLogsStatus': 'ENABLED',
    'MalwareProtectionReason': None,
    'MalwareProtectionStatus': 'ENABLED',
    'S3LogsStatus': 'ENABLED',
    'ServiceRole': 'string',
    'Status': 'ENABLED',
    'Tags': {'string': 'string'},
    'UpdatedAt': 'string'
}


def test_get_detector(mocker):
    """
    Given:
        AWSClient session
        get_detector valid response

    When:
        Running get_detector command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    get_detector_mock = mocker.patch.object(MockedBoto3Client, 'get_detector',
                                            side_effect=[DETECTOR_RESPONSE])

    command_results = get_detector(mocked_client, {'detectorId': 'some_id'})

    get_detector_mock.assert_called_with(DetectorId='some_id')
    assert command_results.outputs == EXPECTED_DETECTOR_RESPONSE


def test_create_detector(mocker):
    """
    Given:
        AWSClient session
        create_detector valid response

    When:
        Running create_detector command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    create_detector_mock = mocker.patch.object(MockedBoto3Client, 'create_detector',
                                               side_effect=[{'DetectorId': 'some_id'}])

    command_results = create_detector(mocked_client, {'enabled': 'True', 'findingFrequency': 'One Hour',
                                                      'enableKubernetesLogs': 'True',
                                                      'ebsVolumesMalwareProtection': 'True',
                                                      'enableS3Logs': 'True'})
    assert create_detector_mock.call_args_list[0][1] == {'Enable': True, 'FindingPublishingFrequency': 'ONE_HOUR',
                                                         'DataSources': {'S3Logs': {'Enable': True},
                                                                         'Kubernetes': {'AuditLogs': {'Enable': True}},
                                                                         'MalwareProtection':
                                                                             {'ScanEc2InstanceWithFindings': {
                                                                                 'EbsVolumes': True}}}}
    assert command_results.outputs == {'DetectorId': 'some_id'}


def update_finding_id(finding, new_id, updated_at=None):
    """Update finding with new id and updatedAt fields."""
    finding["Id"] = new_id
    if updated_at:
        finding["UpdatedAt"] = updated_at
    return finding


''' FETCH CONSTANTS '''
FINDING_1 = update_finding_id(FINDING.copy(), "finding_id1")
FINDING_2 = update_finding_id(FINDING.copy(), "finding_id2")
INCIDENT_1 = {'name': 'title', 'details': 'desc', 'occurred': '2022-11-08T14:24:52.908Z', 'severity': 0,
              'rawJSON': json.dumps(FINDING_1, default=str)}
INCIDENT_2 = {'name': 'title', 'details': 'desc', 'occurred': '2022-11-08T14:24:52.908Z', 'severity': 0,
              'rawJSON': json.dumps(FINDING_2, default=str)}
INCIDENTS_NEXT_RUN = {'latest_created_time': '2022-11-08T14:24:52.908000Z',
                      'latest_updated_time': '2022-11-08T14:24:52.908000Z',
                      'last_incidents_ids': ['finding_id1', 'finding_id2'],
                      'last_next_token': ""}


@pytest.mark.parametrize('gd_severity, '
                         'last_run, fetch_limit, first_fetch_time,'
                         'expected_incidents, expected_next_run, '
                         'expected_criterion_conditions,'
                         'mock_list_finding_res, mock_get_finding_res, is_archive',
                         [
                             # case - 1: First run (no Last Run) should get all incident from 'First fetch timestamp'
                             # field to current time.
                             # is_archive = True, should archive the findings and to get only unarchived findings.
                             (["Medium"],
                              {}, 2, '2022-11-08T14:24:52.908Z',
                              [INCIDENT_1, INCIDENT_2], INCIDENTS_NEXT_RUN,
                              {'severity': {'Gte': 4}, 'service.archived': {'Eq': ['false']}},
                              {"FindingIds": ["finding_id1", "finding_id2"], "NextToken": ""}, [FINDING_1, FINDING_2],
                              True),

                             # case - 2: Second run should get all incidents from last run time to current time
                             # without duplicates
                             ([],
                              {'last_incidents_ids': ["finding_id1"],
                               'last_next_token': "",
                               'latest_created_time': '2022-11-08T14:24:52.908000Z',
                               'latest_updated_time': '2022-11-08T14:24:52.908000Z'}, 2, '3 days',
                              [INCIDENT_2], INCIDENTS_NEXT_RUN,
                              {'id': {'Neq': ['finding_id1']},
                               'severity': {'Gte': 1},
                               'updatedAt': {'Gte': 1667917492908}},
                              {"FindingIds": ["finding_id2"], "NextToken": ""}, [FINDING_2], False),

                             # case - 3: A run without new finding since last run, should not change the Last Run
                             ([],
                              INCIDENTS_NEXT_RUN, 2, '3 years',
                              [], INCIDENTS_NEXT_RUN,
                              {'severity': {'Gte': 1},
                               'updatedAt': {'Gte': 1667917492908},
                               'id': {'Neq': ['finding_id1', 'finding_id2']}},
                              {"FindingIds": [], 'NextToken': ""}, [], False),

                             # case - 4: A run without incidents (all incidents has earlier time then the last run)
                             # should get 0 incidents and should not change the Last Run
                             # [incidents created time is 08.11 but latest created time is 16.11]
                             ([],
                              {'latest_created_time': '2022-11-16T14:24:52.908000Z',
                               'latest_updated_time': '2022-11-06T14:24:52.908000Z'}, 2, '3 days',
                              [], {'last_incidents_ids': [],
                                   'last_next_token': "",
                                   'latest_created_time': '2022-11-16T14:24:52.908000Z',
                                   'latest_updated_time': '2022-11-08T14:24:52.908000Z'},
                              {'severity': {'Gte': 1}, 'updatedAt': {'Gte': 1667744692908}},
                              {"FindingIds": ["finding_id1", "finding_id2"], 'NextToken': ""}, [FINDING_1, FINDING_2],
                              False),

                             # case - 5: A run given last_next_token and latest_updated_time,
                             # validate the latest_updated_time is not used
                             ([],
                              {'last_incidents_ids': [],
                               'last_next_token': "test",
                               'latest_created_time': '2022-11-08T14:24:52.908000Z',
                               'latest_updated_time': '2022-11-11T14:24:52.908000Z'}, 2, '3 days',
                              [INCIDENT_1, INCIDENT_2], {'last_incidents_ids': ['finding_id1', 'finding_id2'],
                                                         'last_next_token': "",
                                                         'latest_created_time': '2022-11-08T14:24:52.908000Z',
                                                         'latest_updated_time': '2022-11-11T14:24:52.908000Z'},
                              {'severity': {'Gte': 1}},
                              {"FindingIds": ["finding_id1", "finding_id2"], 'NextToken': ""}, [FINDING_1, FINDING_2],
                              False)
                         ], ids=['case - 1', 'case - 2', 'case - 3', 'case - 4', 'case - 5'])
def test_fetch_incidents(mocker, gd_severity, last_run, fetch_limit, first_fetch_time,
                         expected_incidents, expected_next_run, expected_criterion_conditions,
                         mock_list_finding_res, mock_get_finding_res, is_archive):
    """
    Given:
        AWSClient session
        list_detectors, list_finding_ids, get_finding_ids valid responses.

    When:
        Running fetch-incidents.

    Then:
        assert incidents are returned as expected.
        assert api calls are called as expected.
    """
    mocked_client = MockedBoto3Client()
    list_detectors_mock = mocker.patch.object(MockedBoto3Client, 'list_detectors',
                                              side_effect=[{"DetectorIds": ["detector_id1"]}])
    list_findings_mock = mocker.patch.object(MockedBoto3Client, 'list_findings',
                                             return_value=mock_list_finding_res)
    get_findings_mock = mocker.patch.object(MockedBoto3Client, 'get_findings',
                                            return_value={'Findings': mock_get_finding_res})
    archive_findings_mock = mocker.patch.object(MockedBoto3Client, 'archive_findings', side_effect=[{}])

    next_run, incidents = fetch_incidents(client=mocked_client, aws_gd_severity=gd_severity, last_run=last_run,
                                          fetch_limit=fetch_limit, first_fetch_time=first_fetch_time,
                                          is_archive=is_archive)

    assert list_detectors_mock.is_called_once
    assert list_findings_mock.call_count == 1
    assert get_findings_mock.call_count == 1
    assert list_findings_mock.call_args[1]['FindingCriteria']['Criterion'] == expected_criterion_conditions
    if is_archive:
        assert archive_findings_mock.call_count == 1
        assert archive_findings_mock.call_args[1]['FindingIds'] == mock_list_finding_res['FindingIds']
    assert next_run == expected_next_run
    assert incidents == expected_incidents


@pytest.mark.parametrize('args, expected_results', [
    ({}, (50, 50, None)),  # no pagination arguments
    ({'limit': "3"}, (3, 50, None)),  # given limit argument
    ({'page_size': "5", "page": "2"}, (10, 5, 2))])  # given page_size and page arguments
def test_get_pagination_args(args, expected_results):
    """
       Given:
           - pagination arguments.

       When:
           - Running a list command.

       Then:
           - Make sure that the correct amount of results to display is returned.
            expected_results = (limit, page_size, page) == get_pagination_args(args)
   """
    from AWSGuardDuty import get_pagination_args
    assert expected_results == get_pagination_args(args)

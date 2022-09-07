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
from datetime import date


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
    list_members_mock = mocker.patch.object(MockedBoto3Client, 'list_members', side_effect=[LIST_MEMBERS_RESPONSE])

    command_results = list_members(mocked_client, {'detectorId': 'some_id'})

    assert list_members_mock.is_called_once_with({'DetectorId': 'some_id'})
    assert command_results.outputs == LIST_MEMBERS_RESPONSE.get('Members')


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
    update_findings_feedback_mock = mocker.patch.object(MockedBoto3Client, 'update_findings_feedback', side_effect=[response])

    with raises:
        update_findings_feedback(mocked_client, {'detectorId': 'some_id',
                                                 'findingIds': 'finding_id1, finding_id2',
                                                 'comments': 'some_comment1, some_comment2',
                                                 'feedback': 'some_feedback1, some_feedback2'})

    assert update_findings_feedback_mock.is_called_once_with({'DetectorId': 'some_id',
                                                              'FindingIds': ['finding_id1', 'finding_id2'],
                                                              'Comments': ['some_comment1', 'some_comment2'],
                                                              'Feedback': ['some_feedback1', 'some_feedback2']})


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

    assert archive_findings_mock.is_called_once_with({'DetectorId': 'some_id',
                                                      'FindingIds': ['finding_id1', 'finding_id2']})


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

    assert unarchive_findings_mock.is_called_once_with({'DetectorId': 'some_id',
                                                        'FindingIds': ['finding_id1', 'finding_id2']})


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

    assert create_sample_findings_mock.is_called_once_with({'DetectorId': 'some_id',
                                                            'FindingTypes': ['finding_type1', 'finding_type2']})


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
    mocked_client = MockedBoto3Client()
    get_findings_mock = mocker.patch.object(MockedBoto3Client, 'get_findings',
                                            side_effect=[{'Findings': [FINDING,
                                                                       update_finding_id(FINDING.copy(),
                                                                                         'finding2',
                                                                                         date(2015, 1, 1))]}])

    command_results = get_findings(mocked_client, {'detectorId': 'some_id',
                                                   'findingIds': 'finding_id1, finding_id2'})

    assert get_findings_mock.is_called_once_with({'DetectorId': 'some_id',
                                                  'FindingIds': ['finding_id1', 'finding_id2']})
    assert command_results.outputs == [EXPECTED_FINDING_RESULT,
                                       update_finding_id(EXPECTED_FINDING_RESULT.copy(), 'finding2')]


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

    assert get_paginator_mock.is_called_once_with('list_findings')
    assert paginate_mock.is_called_once_with({'DetectorId': 'some_id'})
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

    assert update_threat_intel_set_mock.is_called_once_with({'DetectorId': 'some_id',
                                                             'ThreatIntelSetId': 'ThreatIntelSetId1',
                                                             'Activate': True,
                                                             'Location': 'here',
                                                             'Name': 'some_name'})


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

    assert get_threat_intel_set_mock.is_called_once_with({'DetectorId': 'some_id', 'ThreatIntelSetId': 'threat_id1'})
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
    list_threat_intel_sets_mock = mocker.patch.object(MockedBoto3Client, 'list_threat_intel_sets',
                                                      side_effect=[{'ThreatIntelSetIds': ['threat1', 'threat2']}])

    command_results = list_threat_intel_sets(mocked_client, {'detectorId': 'some_id'})

    assert list_threat_intel_sets_mock.is_called_once_with({'DetectorId': 'some_id'})
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

    assert delete_threat_intel_set_mock.is_called_once_with({'DetectorId': 'some_id',
                                                             'ThreatIntelSetId': 'ThreatIntelSetId1'})


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

    assert create_threat_intel_set_mock.is_called_once_with({'DetectorId': 'some_id',
                                                             'Activate': 'True',
                                                             'Format': 'some_format',
                                                             'Location': 'some_location',
                                                             'Name': 'some_name'})
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

    assert get_ip_set_mock.is_called_once_with({'DetectorId': 'some_id', 'IpSetId': 'ipset1'})
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
    list_ip_sets_mock = mocker.patch.object(MockedBoto3Client, 'list_ip_sets',
                                            side_effect=[{'IpSetIds': ['ipset1', 'ipset2']}])

    command_results = list_ip_sets(mocked_client, {'detectorId': 'some_id'})

    assert list_ip_sets_mock.is_called_once_with({'DetectorId': 'some_id'})
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

    assert create_ip_set_mock.is_called_once_with({'DetectorId': 'some_id',
                                                   'Activate': 'True',
                                                   'Format': 'some_format',
                                                   'Location': 'some_location',
                                                   'Name': 'some_name'})
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

    assert update_ip_set_mock.is_called_once_with({'DetectorId': 'some_id',
                                                   'IpSetId': 'ipSetId1',
                                                   'Activate': True,
                                                   'Location': 'here',
                                                   'Name': 'some_name'})


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

    assert delete_ip_set_mock.is_called_once_with({'DetectorId': 'some_id',
                                                   'IpSetId': 'IpSetId1'})


def test_list_detectors(mocker):
    """
    Given:
        AWSClient session
        list_detectors valid response

    When:
        Running list_detectors command

    Then:
        assert api calls are called exactly once and as expected.
    """
    mocked_client = MockedBoto3Client()
    list_detectors_mock = mocker.patch.object(MockedBoto3Client, 'list_detectors',
                                              side_effect=[{'DetectorIds': ['some_id']}])

    command_results = list_detectors(mocked_client, {})

    assert list_detectors_mock.is_called_once_with({})
    assert command_results.outputs == {'DetectorId': 'some_id'}


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
        update_detector(mocked_client, {'detectorId': 'some_id',
                                        'enable': 'true'})

    assert update_detector_mock.is_called_once_with({'DetectorId': 'some_id',
                                                     'Enable': True})


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

    assert delete_detector_mock.is_called_once_with({'DetectorId': 'some_id'})


EXPECTED_DETECTOR_RESPONSE = {
    'CreatedAt': 'string',
    'DetectorId': 'some_id',
    'ServiceRole': 'string',
    'Status': 'ENABLED',
    'UpdatedAt': 'string',
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

    assert get_detector_mock.is_called_once_with({'DetectorId': 'some_id'})
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
    create_ip_set_mock = mocker.patch.object(MockedBoto3Client, 'create_detector',
                                             side_effect=[{'DetectorId': 'some_id'}])

    command_results = create_detector(mocked_client, {'enable': 'True'})

    assert create_ip_set_mock.is_called_once_with({'Enable': True})
    assert command_results.outputs == {'DetectorId': 'some_id'}


def update_finding_id(finding, new_id, updated_at=None):
    """Update finding with new id and updatedAt fields."""
    finding["Id"] = new_id
    if updated_at:
        finding["UpdatedAt"] = updated_at
    return finding


@pytest.mark.parametrize('xsoar_severity, gd_severity', [('Low', 1), ('Medium', 4), ('High', 7), ('Unknown', 1)])
def test_fetch_events(mocker, xsoar_severity, gd_severity):
    """
    Given:
        AWSClient session
        list_detectors, list_finding_ids, get_finding_ids valid responses.
        various sevirity levels of findings to get.

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
                                             side_effect=[{"FindingIds": ["finding_id1", "finding_id2"]}])
    get_findings_mock = mocker.patch.object(MockedBoto3Client, 'get_findings',
                                            side_effect=[{'Findings': [update_finding_id(FINDING.copy(), "finding_id1"),
                                                                       update_finding_id(FINDING.copy(), "finding_id2")]}])
    archive_findings_mock = mocker.patch.object(MockedBoto3Client, 'archive_findings', side_effect=[{}])
    incidents_mock = mocker.patch.object(demisto, 'incidents', side_effect=[{}])

    fetch_incidents(client=mocked_client, aws_gd_severity=xsoar_severity)

    list_detectors_mock.is_called_once_with({})
    list_findings_mock.is_called_once_with({'DetectorId': 'detector_id1',
                                            'FindingCriteria': {
                                                'Criterion': {
                                                    'service.archived': {'Eq': ['false', 'false']},
                                                    'severity': {'Gt': gd_severity}}}})
    get_findings_mock.is_called_once_with({'DetectorId': 'detector_id1', 'FindingIds': ["finding_id1", "finding_id2"]})
    archive_findings_mock.is_called_once_with({'DetectorId': 'detector_id1',
                                               'FindingIds': ["finding_id1", "finding_id2"]})
    incidents_mock.is_called_once_with([])

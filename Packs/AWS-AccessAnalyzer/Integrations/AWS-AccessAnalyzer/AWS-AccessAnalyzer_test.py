import demistomock as demisto
import importlib
import datetime
import pytest


AWSAccessAnalyzer = importlib.import_module("AWS-AccessAnalyzer")


def get_mocked_client(mocker):
    mocker.patch.object(AWSAccessAnalyzer, 'get_aws_session')
    return AWSAccessAnalyzer.get_aws_session()


def mock_required_fields(mocker, command_name, mocked_method_name, method_return_value=None):
    mocked_params = {
        'defaultRegion': 'test_region',
        'role_arn': 'test_role_arn',
        'role_session_name': 'test_role_session_name',
        'credentials': {
            'identifier': 'tets_access_key_id',
            'password': 'test_secret_access_key'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value=command_name)
    mocker.patch.object(AWSAccessAnalyzer, 'return_results')
    mocker.patch.object(get_mocked_client(mocker), mocked_method_name, return_value=method_return_value)


def test_test_module(mocker):
    mocked_results = {'ResponseMetadata': {'HTTPStatusCode': 200}}
    mock_required_fields(mocker,
                         command_name='test-module',
                         mocked_method_name='list_analyzers',
                         method_return_value=mocked_results)

    AWSAccessAnalyzer.main()

    assert 'ok' in AWSAccessAnalyzer.return_results.call_args[0][0]


def test_list_analyzers_command(mocker):
    mocked_results = {
        'analyzers': [
            {'arn': 'test_arn_1', 'createdAt': datetime.datetime(2023, 2, 13, 21, 28, 4)},
            {'arn': 'test_arn_2', 'createdAt': datetime.datetime(2023, 2, 13, 21, 28, 6)}
        ]}
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-list-analyzers',
                         mocked_method_name='list_analyzers',
                         method_return_value=mocked_results)

    AWSAccessAnalyzer.main()

    command_results = AWSAccessAnalyzer.return_results.call_args[0][0]
    analyzers = command_results.outputs
    assert command_results.outputs_key_field == 'arn'
    assert analyzers[0]['arn'] == mocked_results['analyzers'][0]['arn']
    assert analyzers[0]['createdAt'] == '2023-02-13T21:28:04'
    assert analyzers[1]['createdAt'] == '2023-02-13T21:28:06'


def test_list_analyzed_resource_command(mocker):
    mocked_results = {'analyzedResources': [{'resourceArn': 'test_arn_1'}, {'resourceArn': 'test_arn_2'}]}
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-list-analyzed-resource',
                         mocked_method_name='list_analyzed_resources',
                         method_return_value=mocked_results)

    AWSAccessAnalyzer.main()

    command_results = AWSAccessAnalyzer.return_results.call_args[0][0]
    resources = command_results.outputs
    assert len(resources) == len(mocked_results['analyzedResources'])
    assert command_results.outputs_key_field == 'resourceArn'
    assert all(resource['resourceArn'] for resource in resources)


def test_list_findings_command(mocker):
    mocked_results = {
        'findings': [
            {'id': 'test_id_1', 'updatedAt': datetime.datetime(2023, 2, 13, 21, 28, 4)},
            {'id': 'test_id_2', 'updatedAt': datetime.datetime(2023, 2, 13, 21, 28, 6)}
        ]}
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-list-findings',
                         mocked_method_name='list_findings',
                         method_return_value=mocked_results)

    AWSAccessAnalyzer.main()

    command_results = AWSAccessAnalyzer.return_results.call_args[0][0]
    findings = command_results.outputs
    assert command_results.outputs_key_field == 'id'
    assert findings[0]['id'] == mocked_results['findings'][0]['id']
    assert findings[0]['updatedAt'] == '2023-02-13T21:28:04'
    assert findings[1]['updatedAt'] == '2023-02-13T21:28:06'


@pytest.mark.parametrize(argnames='filter_args', argvalues=[['resourceType'], ['status'], ['resourceType', 'status']])
def test_list_findings_command__with_filters(mocker, filter_args):
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-list-findings',
                         mocked_method_name='list_findings',
                         method_return_value={'findings': []})
    mocker.patch.object(demisto, 'args', return_value={filter_arg: 'filter_val' for filter_arg in filter_args})

    AWSAccessAnalyzer.main()

    filters = AWSAccessAnalyzer.get_aws_session().list_findings.call_args[1]['filter']
    assert all(filters[filter_arg] == {'eq': ['filter_val']} for filter_arg in filter_args)
    assert len(filters) == len(filter_args)


def test_get_analyzed_resource_command(mocker):
    mocked_results = {'resource': {'id': 'test_id_1', 'analyzedAt': datetime.datetime(2023, 2, 13, 21, 28, 4)}}
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-get-analyzed-resource',
                         mocked_method_name='get_analyzed_resource',
                         method_return_value=mocked_results)

    AWSAccessAnalyzer.main()

    command_results = AWSAccessAnalyzer.return_results.call_args[0][0]
    resource = command_results.outputs
    assert command_results.outputs_key_field == 'id'
    assert resource['id'] == mocked_results['resource']['id']
    assert resource['analyzedAt'] == '2023-02-13T21:28:04'


def test_get_finding_command(mocker):
    mocked_results = {'finding': {'id': 'test_id_1'}}
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-get-finding',
                         mocked_method_name='get_finding',
                         method_return_value=mocked_results)

    AWSAccessAnalyzer.main()

    command_results = AWSAccessAnalyzer.return_results.call_args[0][0]
    finding = command_results.outputs
    assert finding['id'] == mocked_results['finding']['id']
    assert command_results.outputs_key_field == 'id'


def test_start_resource_scan_command(mocker):
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-start-resource-scan',
                         mocked_method_name='start_resource_scan')

    AWSAccessAnalyzer.main()

    results = AWSAccessAnalyzer.return_results.call_args[0][0]
    assert 'Resource scan request sent.' in results


def test_update_findings_command(mocker):
    mock_required_fields(mocker,
                         command_name='aws-access-analyzer-update-findings',
                         mocked_method_name='update_findings')

    AWSAccessAnalyzer.main()

    results = AWSAccessAnalyzer.return_results.call_args[0][0]
    assert 'Findings updated.' in results


@pytest.mark.parametrize(
    argnames='lats_run_obj, expected_inc_number',
    argvalues=[
        (None, 1),
        ({'time': '1676316480000'}, 2),
        ({'time': '1000'}, 3)
    ]
)
def test_fetch_incidents_command__various_last_run(mocker, lats_run_obj, expected_inc_number):
    """
    Given   - only one mocked incidents updated now
    When    - run fetch incidents
    Then    - validate the number of returned incidents
    """
    mocked_results = {
        'findings': [
            {'id': 'test_id_1', 'updatedAt': datetime.datetime.now()},
            {'id': 'test_id_2', 'updatedAt': datetime.datetime(2023, 2, 13, 21, 28, 6)},
            {'id': 'test_id_3', 'updatedAt': datetime.datetime(2022, 1, 13, 21, 28, 6)}
        ]}
    mock_required_fields(mocker,
                         command_name='fetch-incidents',
                         mocked_method_name='list_findings',
                         method_return_value=mocked_results)
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'getLastRun', return_value=lats_run_obj)

    AWSAccessAnalyzer.main()

    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == expected_inc_number
    assert incidents[0]['name'] == f"AWS Access Analyzer Alert - {mocked_results['findings'][0]['id']}"


@pytest.mark.parametrize(argnames='next_token, expected_call_count', argvalues=[(None, 1), ('next_token', 2)])
def test_fetch_incidents_command__with_next_token(mocker, next_token, expected_call_count):
    """
    Given   - next token in findings response
    When    - run fetch incidents
    Then    - validate that get_findings run twice
    """
    def get_mocked_results(**kwargs):
        result = {
            'findings': [
                {'id': 'test_id_1', 'updatedAt': datetime.datetime.now()},
                {'id': 'test_id_2', 'updatedAt': datetime.datetime.now()}
            ]
        }
        if next_token and 'nextToken' not in kwargs:
            result['nextToken'] = next_token
        return result

    mock_required_fields(mocker,
                         command_name='fetch-incidents',
                         mocked_method_name='list_findings')
    AWSAccessAnalyzer.get_aws_session().list_findings.side_effect = get_mocked_results
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')

    AWSAccessAnalyzer.main()

    assert AWSAccessAnalyzer.get_aws_session().list_findings.call_count == expected_call_count


def test_exception_in_test_module(mocker):
    err_msg = 'connection failed.'
    mock_required_fields(mocker,
                         command_name='test-module',
                         mocked_method_name='list_analyzers')

    mocker.patch.object(AWSAccessAnalyzer, 'return_error')
    AWSAccessAnalyzer.get_aws_session().list_analyzers.side_effect = Exception(err_msg)

    AWSAccessAnalyzer.main()

    expected_err_msg = f'Error has occurred in AWS Access Analyzer Integration: Failed to run test-module: {err_msg}'
    assert expected_err_msg in AWSAccessAnalyzer.return_error.call_args[0][0]

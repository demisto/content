import pytest
from AnomaliSecurityAnalyticsAlerts import *
import demistomock as demisto
from CommonServerPython import * 
from CommonServerUserPython import * 
from freezegun import freeze_time

VENDOR_NAME = 'Anomali Security Analytics Alerts'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': VENDOR_NAME}})


@freeze_time("2025-03-01")
def test_command_create_search_job(mocker):
    """
    Given:
        - Valid query, source, from, to and timezone parameters

    When:
        - client.create_search_job returns a job id

    Then:
        - Validate that command_create_search_job returns a CommandResults object
          with outputs containing the correct job_id and a status of "in progress"

    """
    client = Client(server_url='https://test.com',
                    username='test_user',
                    api_key='test_api_key',
                    verify=True,
                    proxy=False)

    return_data = {'job_id': '1234'}
    mocker.patch.object(client, 'create_search_job', return_value=return_data)

    args = {
        'query': 'alert',
        'source': 'source',
        'from': '1 day',
    }

    result = command_create_search_job(client, args)
    assert isinstance(result, CommandResults)
    outputs = result.outputs
    assert outputs.get('job_id') == '1234'
    assert outputs.get('status') == 'in progress'
    assert "Search Job Created" in result.readable_output


def test_command_get_search_job_status(mocker):
    """
    Given:
        - A valid job_id

    When:
        - client.get_search_job_status returns a response with a status

    Then:
        - Validate that command_get_search_job_status returns a list of CommandResults
          where each contains the job_id and its status

    """
    client = Client(server_url='https://test.com',
                    username='test_user',
                    api_key='test_api_key',
                    verify=True,
                    proxy=False)

    return_data = {'status': 'completed'}
    mocker.patch.object(client, 'get_search_job_status', return_value=return_data)

    args = {
        'job_id': 'job123'
    }

    results = command_get_search_job_status(client, args)
    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs.get('job_id') == 'job123'
    assert outputs.get('status') == 'completed'
    assert "Search Job Status" in results[0].readable_output


def test_command_get_search_job_status_invalid(mocker):
    """
    Given:
        - An invalid job_id
    
    When:
        - client.get_search_job_status returns a response with an error.
    
    Then:
        - Validate that command_get_search_job_status raises an Exception indicating 
          that the Job ID might be expired or incorrect.
    """
    client = Client(
        server_url='https://test.com',
        username='test_user',
        api_key='test_api_key',
        verify=True,
        proxy=False
    )

    return_data = {'error': 'Invalid Job ID'}
    mocker.patch.object(client, 'get_search_job_status', return_value=return_data)

    args = {'job_id': 'invalid_job'}
    results = command_get_search_job_status(client, args)

    assert isinstance(results, list)
    assert len(results) == 1

    outputs = results[0].outputs
    assert outputs == {}

    readable_output = results[0].readable_output
    assert "No results found for Job ID: invalid_job" in readable_output


def test_command_get_search_job_results(mocker):
    """
    Given:
        - A valid job_id

    When:
        - client.get_search_job_results returns a valid response

    Then:
        - Validate that command_get_search_job_results returns a list of CommandResults
          with the expected job results

    """
    client = Client(server_url='https://test.com',
                    username='test_user',
                    api_key='test_api_key',
                    verify=True,
                    proxy=False)

    return_data = {
        'fields': ['id', 'name'],
        'records': [
            ['1', 'record1'],
            ['2', 'record2']
        ],
        'complete': True
    }
    mocker.patch.object(client, 'get_search_job_results', return_value=return_data)

    args = {'job_id': 'job789'}
    results = command_get_search_job_results(client, args)

    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs.get('fields') == return_data.get('fields')
    assert outputs.get('records') == return_data.get('records')

    human_readable = results[0].readable_output
    assert "Search Job Results" in human_readable
    for header in return_data['fields']:
        assert header in human_readable
    assert "record1" in human_readable


def test_command_get_search_job_results_no_fields_records(mocker):
    """
    Given:

        - A valid job_id
    
    When:
        - client.get_search_job_results returns a response without 'fields' and 'records'
    
    Then:
        - Validate that command_get_search_job_results returns a list of CommandResults
          with the expected output from the fallback branch
    """
    client = Client(
        server_url='https://test.com',
        username='test_user',
        api_key='test_api_key',
        verify=True,
        proxy=False
    )

    return_data = {
        'result': 'raw data',
        'complete': True
    }
    mocker.patch.object(client, 'get_search_job_results', return_value=return_data)

    args = {
        'job_id': 'job_no_fields'
    }

    results = command_get_search_job_results(client, args)

    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs == return_data

    human_readable = results[0].readable_output
    assert "Search Job Results" in human_readable
    assert "raw data" in human_readable


def test_command_update_alert_status(mocker):
    """
    Given:
        - 'status' and 'uuid' parameters

    When:
        - client.update_alert returns a response

    Then:
        - Validate that command_update_alert_status returns a CommandResults object
          with outputs equal to the mocked response

    """
    client = Client(server_url='https://test.com',
                    username='test_user',
                    api_key='test_api_key',
                    verify=True,
                    proxy=False)

    return_data = {'updated': True}
    mocker.patch.object(client, 'update_alert', return_value=return_data)

    args = {
        'status': 'IN_PROGRESS',
        'uuid': 'alert-uuid-123'
    }

    result = command_update_alert_status(client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs == return_data
    assert "Update Alert Status" in result.readable_output


def test_command_update_alert_comment(mocker):
    """
    Given:
        - 'uuid' and 'comment' parameters

    When:
        - client.update_alert returns a response

    Then:
        - Validate that command_update_alert_comment returns a CommandResults object
          with outputs equal to the mocked response

    """
    client = Client(server_url='https://test.com',
                    username='test_user',
                    api_key='test_api_key',
                    verify=True,
                    proxy=False)

    return_data = {'updated': True}
    mocker.patch.object(client, 'update_alert', return_value=return_data)

    args = {
        'comment': 'Test comment',
        'uuid': 'alert-uuid-456'
    }

    result = command_update_alert_comment(client, args)
    assert isinstance(result, CommandResults)
    assert result.outputs == return_data
    assert "Update Alert Comment" in result.readable_output

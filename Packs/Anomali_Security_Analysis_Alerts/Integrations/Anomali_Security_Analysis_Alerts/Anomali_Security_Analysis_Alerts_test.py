import pytest
from Anomali_Security_Analysis_Alerts import *
import demistomock as demisto

VENDOR_NAME = 'Anomali Security Analysis Alerts'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': VENDOR_NAME}})


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
        'from': '10 day',
        'to': '1 day'
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

    return_data = {'result': 'some results', 'complete': True}
    mocker.patch.object(client, 'get_search_job_results', return_value=return_data)

    args = {
        'job_id': 'job456'
    }

    results = command_get_search_job_results(client, args)
    assert isinstance(results, list)
    assert len(results) == 1
    outputs = results[0].outputs
    assert outputs.get('result') == 'some results'
    assert results[0].raw_response == return_data
    assert "Search Job Results" in results[0].readable_output


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

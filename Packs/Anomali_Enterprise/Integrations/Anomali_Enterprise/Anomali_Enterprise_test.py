import pytest
from Anomali_Enterprise import *


def test_domain_command_benign(mocker):
    """
    Given:
        - a domain

    When:
        - mocking the server response for a benign domain, running domain_command

    Then:
        - validating that the domain score is unknown
        - validating the returned context data

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {'data': {'test.com': {'malware_family': '', 'probability': 0}}, 'result': 'success'}
    mocker.patch.object(client, 'domain_request', return_value=return_data)
    command_results = domain_command(client, args={'domain': 'test.com'})
    output = command_results[0].to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    expected_result = {
        'Domain': [
            {
                'Name': 'test.com'
            }
        ],
        'DBotScore': [
            {
                'Indicator': 'test.com',
                'Type': 'domain',
                'Vendor': 'Anomali Enterprise',
                'Score': 0
            }
        ]
    }
    assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    assert output.get(dbot_key, []) == expected_result.get('DBotScore')


def test_domain_command_suspicious(mocker):
    """
    Given:
        - a domain

    When:
        - mocking the server response for a suspicious domain, running domain_command

    Then:
        - validating that the domain score is suspicious
        - validating the returned context data, including the suspicious context

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {'data': {'suspicious.com': {'malware_family': 'my_suspicious', 'probability': 0.4}},
                   'result': 'success'}
    mocker.patch.object(client, 'domain_request', return_value=return_data)
    command_results = domain_command(client, args={'domain': 'suspicious.com'})
    output = command_results[0].to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    expected_result = {
        'Domain': [
            {'Name': 'suspicious.com', 'Tags': 'DGA'}
        ],
        'DBotScore': [
            {
                'Indicator': 'suspicious.com',
                'Type': 'domain',
                'Vendor': 'Anomali Enterprise',
                'Score': 2
            }
        ]
    }

    assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    assert output.get(dbot_key, []) == expected_result.get('DBotScore')


def test_domain_command_malicious(mocker):
    """
    Given:
        - a domain

    When:
        - mocking the server response for a malicious domain, running domain_command

    Then:
        - validating that the domain score is malicious
        - validating the returned context data, including the malicious context

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {'data': {'malicious.com': {'malware_family': 'my_malware', 'probability': 0.9}}, 'result': 'success'}
    mocker.patch.object(client, 'domain_request', return_value=return_data)
    command_results = domain_command(client, args={'domain': 'malicious.com'})
    output = command_results[0].to_context().get('EntryContext', {})
    dbot_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
               ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    expected_result = {
        'Domain': [
            {'Malicious': {'Description': 'my_malware', 'Vendor': 'Anomali Enterprise'},
             'Name': 'malicious.com', 'Tags': 'DGA'}
        ],
        'DBotScore': [
            {
                'Indicator': 'malicious.com',
                'Type': 'domain',
                'Vendor': 'Anomali Enterprise',
                'Score': 3
            }
        ]
    }

    assert output.get('Domain(val.Name && val.Name == obj.Name)', []) == expected_result.get('Domain')
    assert output.get(dbot_key, []) == expected_result.get('DBotScore')


def test_start_search_job_command(mocker):
    """
    Given:
        - a from_, to_ and indicators to search

    When:
        - mocking the server response for the start of a job, running start_search_job

    Then:
        - validating the arguments are parsed correctly
        - validating the returned context data

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {'jobid': '1234'}
    mocker.patch.object(client, 'start_search_job_request', return_value=return_data)
    command_results = start_search_job(client, args={'from': '1 month', 'indicators': '8.8.8.8'})
    output = command_results.to_context().get('EntryContext', {})
    expected_result = {
        'status': 'in progress',
        'job_id': '1234'
    }

    assert output.get('AnomaliEnterprise.ForensicSearch(val.job_id == obj.job_id)', []) == expected_result


def test_get_search_job_result_command_with_matches(mocker):
    """
    Given:
        - a job_id

    When:
        - mocking the server response for getting the results of a job with matches, running get_search_job_result

    Then:
        - validating the returned context data

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {
        'status': 'completed', 'category': 'forensic_api_result', 'totalFiles': 1,
        'streamResults': [{
            'count': '1', 'indicator': '', 'itype': '', 'severity': '',
            'event_time': '2020-10-14T09:10:00.000+0000', 'age': '', 'event.dest': '8.8.8.8',
            'confidence': '', 'event.src': '8.8.8.8'}],
        'scannedEvents': 269918, 'result_file_name': 'org0_1234_job1234_result.tar.gz',
        'complete': True, 'processedFiles': 1, 'totalMatches': 1
    }
    mocker.patch.object(client, 'get_search_job_result_request', return_value=return_data)
    command_results = get_search_job_result(client, args={'job_id': '111'})
    output = command_results.to_context().get('EntryContext', {})
    expected_result = {
        'status': 'completed', 'category': 'forensic_api_result', 'totalFiles': 1,
        'streamResults': [{
            'count': '1', 'indicator': '', 'itype': '', 'severity': '',
            'event_time': '2020-10-14T09:10:00.000+0000', 'age': '', 'event.dest': '8.8.8.8',
            'confidence': '', 'event.src': '8.8.8.8'}],
        'scannedEvents': 269918, 'result_file_name': 'org0_1234_job1234_result.tar.gz', 'complete': True,
        'processedFiles': 1, 'totalMatches': 1, 'job_id': '111'
    }

    assert output.get('AnomaliEnterprise.ForensicSearch(val.job_id == obj.job_id)', []) == expected_result


def test_get_search_job_result_command_with_matches_and_limit(mocker):
    """
    Given:
        - a job_id

    When:
        - mocking the server response for getting the results of a job with matches, running get_search_job_result
        - limit the stream results

    Then:
        - validating that the context was limited

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {
        'status': 'completed', 'category': 'forensic_api_result', 'totalFiles': 1,
        'streamResults': [
            {
                'count': '1', 'indicator': '', 'itype': '', 'severity': '',
                'event_time': '2020-10-14T09:10:00.000+0000', 'age': '', 'event.dest': '8.8.8.8',
                'confidence': '', 'event.src': '8.8.8.8'
            },
            {
                'count': '1', 'indicator': '', 'itype': '', 'severity': '',
                'event_time': '2020-11-14T09:10:00.000+0000', 'age': '', 'event.dest': '8.8.8.8',
                'confidence': '', 'event.src': '8.8.8.8'
            },
            {
                'count': '1', 'indicator': '', 'itype': '', 'severity': '',
                'event_time': '2020-12-14T09:10:00.000+0000', 'age': '', 'event.dest': '8.8.8.8',
                'confidence': '', 'event.src': '8.8.8.8'
            }
        ],
        'scannedEvents': 269918, 'result_file_name': 'org0_1234_job1234_result.tar.gz',
        'complete': True, 'processedFiles': 1, 'totalMatches': 3
    }
    mocker.patch.object(client, 'get_search_job_result_request', return_value=return_data)
    command_results = get_search_job_result(client, args={'job_id': '111', 'limit': '2'})
    output = command_results.to_context().get('EntryContext', {})

    assert len(output.get('AnomaliEnterprise.ForensicSearch(val.job_id == obj.job_id)', {}).get('streamResults')) == 2


def test_get_search_job_result_command_without_matches(mocker):
    """
    Given:
        - a job_id

    When:
        - mocking the server response for getting the results of a job without matches, running get_search_job_result

    Then:
        - validating the returned context data
        - validating the returned human readable

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {
        'totalFiles': 0, 'streamResults': [], 'scannedEvents': 269918,
        'complete': True, 'processedFiles': 0, 'totalMatches': 0
    }
    mocker.patch.object(client, 'get_search_job_result_request', return_value=return_data)
    command_results = get_search_job_result(client, args={'job_id': '222'})

    output = command_results.to_context().get('EntryContext', {})
    expected_result = {
        'status': 'completed', 'totalFiles': 0, 'streamResults': [],
        'scannedEvents': 269918, 'complete': True, 'processedFiles': 0, 'totalMatches': 0, 'job_id': '222'
    }
    assert output.get('AnomaliEnterprise.ForensicSearch(val.job_id == obj.job_id)', []) == expected_result

    hr_ = command_results.to_context().get('HumanReadable', '')
    assert hr_ == 'No matches found for the given job ID: 222.'


def test_get_search_job_result_command_expired_job_id(mocker):
    """
    Given:
        - a job_id

    When:
        - mocking the server response for an expired job id, running get_search_job_result

    Then:
        - validating the raised error

    """
    client = Client(server_url='test', username='test', password='1234', verify=True, proxy=False)
    return_data = {
        'error': 'Error: Cannot find the jobId: job222'
    }
    mocker.patch.object(client, 'get_search_job_result_request', return_value=return_data)

    with pytest.raises(Exception, match="Error: Cannot find the jobId: job222. Job ID might have expired."):
        get_search_job_result(client, args={'job_id': 'job222'})

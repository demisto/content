import json

import pytest
from freezegun import freeze_time

import demistomock as demisto
from CommonServerPython import Common, ScheduledCommand, DBotScoreReliability
from CrowdStrikeFalconSandboxV2 import Client, \
    validated_search_terms, get_search_term_args, split_query_to_term_args, crowdstrike_result_command, \
    crowdstrike_scan_command, map_dict_keys, BWCFile, crowdstrike_submit_url_command, crowdstrike_submit_sample_command, \
    get_api_id, get_submission_arguments, crowdstrike_analysis_overview_summary_command, \
    crowdstrike_analysis_overview_command, get_default_file_name, validated_term, \
    crowdstrike_analysis_overview_refresh_command, main

BASE_URL = 'https://test.com'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


client = Client(base_url=BASE_URL,
                verify=False,
                proxy=False,
                headers={})


def test_validated_term():
    assert validated_term('country', 'USA') == 'USA'
    assert validated_term('verdict', 'Whitelisted') == 1


def test_validated_search_terms():
    """

    Given:
        - query arguments that need to be converted

    When:
        - Turning demisto args into query args

    Then:
        - We get proper key-val pairs
    """
    pre_validation = {"hello": "world", "verdict": 'NoSpecificThreat'}
    post_validation = validated_search_terms(pre_validation)
    assert post_validation == {'hello': 'world', 'verdict': 3}


def test_validated_search_terms_bad_arg():
    """
    Given:
        - A bad country code

    When:
        - Turning demisto args into query args

    Then:
        - We get an error
    """
    pre_validation = {"country": "US", "verdict": 'NoSpecificThreat'}
    with pytest.raises(ValueError) as e:
        validated_search_terms(pre_validation)
    if not e:
        assert False
    else:
        assert e.value.args[0] == 'Country ISO code should be 3 characters long'


@pytest.mark.parametrize('demisto_args, st_args', [
    ({'query': 'country:USA,port:8080'}, {'country': 'USA', 'port': '8080'}),
    ({'country': 'USA', 'port': '8080'}, {'country': 'USA', 'port': '8080'})])
def test_get_search_term_args(demisto_args, st_args):
    """

    Given:
        - arguments coming in as query or not

    When:
        - Turning demisto args into query args

    Then:
        - We get results regardless of how it came in
    """
    assert st_args == get_search_term_args(demisto_args)


@pytest.mark.parametrize('query_string, query_dict',
                         [('hello:world,three:split:fine,heelo:, another: arg ',
                           {'hello': 'world', 'three': 'split:fine', 'another': 'arg'}),
                          ('arg1 :val1, arg2: val2  ', {'arg1': 'val1', 'arg2': 'val2'})
                          ])
def test_split_query_to_term_args(query_string, query_dict):
    """

   Given:
       - arguments coming in as joint query string

   When:
       - Turning demisto args into query args

   Then:
       - Query argument gets parsed properly
    """
    assert query_dict == split_query_to_term_args(query_string)


@pytest.mark.parametrize('state', ['IN_PROGRESS', 'IN_QUEUE'])
def test_results_poll_state_polling_true(state, mocker, requests_mock):
    """

    Given:
      - result request, polling true

    When:
      - result response in progress

    Then:
      - Get a scheduledcommand result
    """
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    key = "dummy_key"
    filetype = "pdf"
    args = {'JobID': key, 'polling': True, 'file-type': 'pdf'}
    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=404)
    state_call = requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state': state})

    response = crowdstrike_result_command(args, client)
    sc = response.scheduled_command
    assert state_call.called
    assert sc._args['polling']
    assert sc._args['JobID'] == key
    assert sc._args['file-type'] == filetype
    assert sc._args['hide_polling_output']


def test_results_in_progress_polling_true_with_file(mocker, requests_mock):
    """

    Given:
      - result request with file given, polling true

    When:
      - result response is ready

    Then:
      - Get a final result and a scan result
    """

    mocker.patch.object(demisto, 'params', return_value={'integrationReliability': DBotScoreReliability.D})
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    filetype = "pdf"
    hash_response_json = util_load_json('test_data/scan_response.json')

    args = {'file': 'abcd', 'environmentID': 300, 'polling': True, 'file-type': filetype}
    raw_response_data = 'RawDataOfFileResult'
    key = get_api_id(args)
    assert key == 'abcd:300'

    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=200, text=raw_response_data)
    requests_mock.post(BASE_URL + "/search/hashes", json=hash_response_json)

    response = crowdstrike_result_command(args, client)

    assert isinstance(response, list)
    file_result, scan_result = response

    assert file_result['Type'] == 9
    assert file_result['File'].endswith("pdf")
    assert len(scan_result) == len(hash_response_json) + 1
    assert [o['state'] for o in scan_result[0].outputs] == ['SUCCESS', 'SUCCESS']
    assert [o['verdict'] for o in scan_result[0].outputs] == ['malicious', 'malicious']
    assert [o.bwc_fields['url_analysis'] for o in map(lambda x: x.indicator, scan_result[1:])] == [False, False]


def test_results_in_progress_polling_false(requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """

    key = "dummy_key"
    filetype = "pdf"
    args = {'JobID': key, 'polling': False, 'file-type': filetype}
    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=404)
    state_call = requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state': 'IN_PROGRESS'})

    response = crowdstrike_result_command(args, client)

    assert not state_call.called
    assert not response.scheduled_command
    assert response.readable_output == 'Falcon Sandbox returned an error: status code 404, response: '


def test_crowdstrike_scan_command_polling_true(mocker, requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    requests_mock.post(BASE_URL + '/search/hashes', json=[])
    response = crowdstrike_scan_command({"file": "filehash", "polling": True}, client)
    assert response.scheduled_command._args['file'] == 'filehash'
    assert response.scheduled_command._args['hide_polling_output']


def test_crowdstrike_scan_command_polling_false(requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """
    requests_mock.post(BASE_URL + '/search/hashes', json=[])
    response = crowdstrike_scan_command({"file": "filehash", 'polling': 'false'}, client)
    assert len(response) == 1
    assert response[0].scheduled_command is None
    assert response[0].outputs == []


def test_results_in_progress_polling_true_error_state(mocker, requests_mock):
    """

    Given:
      - result request, polling false

    When:
      - result response in progress

    Then:
      - Get a 404 result
    """

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')

    key = "dummy_key"
    filetype = "pdf"
    args = {'JobID': key, 'polling': True, 'file-type': 'pdf'}
    requests_mock.get(BASE_URL + f"/report/{key}/report/{filetype}", status_code=404)
    requests_mock.get(BASE_URL + f"/report/{key}/state", json={'state': 'ERROR'})
    with pytest.raises(Exception) as e:
        crowdstrike_result_command(args, client)
    assert e.value.args[0] == "Got Error state from server: {'state': 'ERROR'}"


def test_map_dict_keys():
    orig = {'propertyName': 'propertyValue', 'a': 'b', 'x': 'y'}

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, True)
    assert res['c'] == 'b'
    assert res.get('propertyName') is None

    res = map_dict_keys(orig, {'a': 'c', 'x': 'z'}, False)
    assert res['z'] == 'y'
    assert res['propertyName'] == 'propertyValue'


def test_bwc_file_context():
    """

    Given:
      - creating a bwc file

    When:
      - getting context

    Then:
      - Get non-file fields as well
    """

    ed_val = "Static Analysis"
    type_val = "typeval"
    sha256 = 'filehash'
    context = BWCFile({"environment_description": ed_val, "type": type_val}, {"type": "type1"}, False, sha256=sha256,
                      dbot_score=Common.DBotScore.NONE).to_context()
    file_dict = context.popitem()[1]
    assert file_dict['type1'] == type_val
    assert file_dict['SHA256'] == sha256
    assert file_dict['environment_description'] == ed_val


def test_crowdstrike_submit_url_command_no_poll(requests_mock):
    """

       Given:
         - poll false

       When:
         - submit url

       Then:
         - get submission result without polling scan
       """
    submit_response = {
        "submission_type": "page_url",
        "job_id": "jobid",
        "submission_id": "submissionId",
        "environment_id": 100,
        "sha256": "filehash"
    }
    mock_call = requests_mock.post(BASE_URL + '/submit/url', json=submit_response)
    result = crowdstrike_submit_url_command(client, {'url': BASE_URL, 'environmentID': 300, 'comment': 'some comment'})
    assert result[0].outputs['CrowdStrike.Submit(val.submission_id && val.submission_id === obj.submission_id)'] == \
        submit_response
    assert 'environment_id' in mock_call.last_request.text
    assert 'comment' in mock_call.last_request.text


def test_crowdstrike_submit_sample_command(mocker, requests_mock):
    submit_response = util_load_json("test_data/submission_response.json")
    requests_mock.post(BASE_URL + '/submit/file', json=submit_response)
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'id': id, 'path': './test_data/scan_response.json', 'name': 'scan_response.json'})
    result = crowdstrike_submit_sample_command(client, {'entryId': '33'})
    assert result[0].outputs['CrowdStrike.Submit(val.submission_id && val.submission_id === obj.submission_id)'] == \
        submit_response
    assert result[0].outputs['CrowdStrike.JobID'] == submit_response['job_id']


def test_crowdstrike_submit_url_command_poll(requests_mock, mocker):
    """

       Given:
         - poll true, scan result in progress

       When:
         - submit url

       Then:
         - submission result returned and polling scan result
       """
    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    submit_response = util_load_json("test_data/submission_response.json")
    mocker.patch.object(demisto, 'results')
    submit_call = requests_mock.post(BASE_URL + '/submit/url', json=submit_response)
    search_call = requests_mock.post(BASE_URL + '/search/hashes', json=[])
    state_call = requests_mock.get(BASE_URL + "/report/12345/state", json={'state': 'IN_PROGRESS'})

    result = crowdstrike_submit_url_command(client, {'url': BASE_URL, 'environmentID': 300, 'comment': 'some comment',
                                                     "polling": True})

    assert submit_call.called and search_call.called and state_call.called

    assert submit_response in [args.args[0]['Contents'] for args in list(demisto.results.call_args_list)]
    assert result.scheduled_command is not None


def test_get_api_id_deprecated_env_id():
    assert get_api_id({'environmentId': 200, 'environementID': 100, 'file': 'filename'}) == 'filename:200'


def test_get_api_id_onlyfile():
    with pytest.raises(ValueError) as e:
        get_api_id({'file': 'filename', 'environmentId': '', 'JobID': ''})
    if not e:
        assert False
    else:
        assert e.value.args[0] == 'Must supply JobID or environmentID and file'


def test_get_submission_arguments():
    assert get_submission_arguments({'environmentId': 200, 'environmentID': 300, 'submit_name': 'steve'}) == \
        {'environment_id': 200, 'submit_name': 'steve'}


def test_crowdstrike_analysis_overview_summary_command(requests_mock):
    """

      Given:
        - any file hash

      When:
        - getting analysis summary

      Then:
        - get a response
      """
    response_json = {
        "sha256": "filehash",
        "threat_score": None,
        "verdict": "malicious",
        "analysis_start_time": None,
        "last_multi_scan": "2021-12-01T15:44:18+00:00",
        "multiscan_result": 88
    }
    requests_mock.get(BASE_URL + '/overview/filehash/summary', json=response_json)
    result = crowdstrike_analysis_overview_summary_command(client, {'file': 'filehash'})
    assert result.outputs == response_json


def test_crowdstrike_analysis_overview_refresh_command(requests_mock):
    call = requests_mock.get(BASE_URL + '/overview/filehash/refresh', status_code=200, json={})
    assert crowdstrike_analysis_overview_refresh_command(client, {'file': 'filehash'}).readable_output == \
        'The request to refresh the analysis overview was sent successfully.' \
        and call.called


def test_crowdstrike_analysis_overview_command(requests_mock):
    """

    Given:
      - any file hash

    When:
      - getting analysis overview

    Then:
      - get a response
    """
    response_json = {
        "sha256": "filehash",
        "threat_score": None,
        "verdict": "malicious",
        "analysis_start_time": None,
        "last_multi_scan": "2021-12-01T15:44:18+00:00",
        "multiscan_result": 88,
        'size': 40,
        'type': 'pdf',
        'last_file_name': 'steven.pdf'
    }
    requests_mock.get(BASE_URL + '/overview/filehash', json=response_json)
    result = crowdstrike_analysis_overview_command(client, {'file': 'filehash'})
    assert result.outputs == response_json
    assert result.indicator is not None


@freeze_time("2000-10-31")
def test_get_default_file_name():
    assert get_default_file_name('pdf') == 'CrowdStrike_report_972950400.pdf'


@pytest.mark.parametrize('command_name, method_name', [('cs-falcon-sandbox-search', 'crowdstrike_search_command'),
                                                       ('crowdstrike-get-environments',
                                                        'crowdstrike_get_environments_command'),
                                                       ('cs-falcon-sandbox-report-state',
                                                        'crowdstrike_report_state_command')])
def test_main(command_name, method_name, mocker):
    mocker.patch.object(demisto, 'command', return_value=command_name)
    mocker.patch.object(demisto, 'params', return_value={})
    mocker.patch.object(demisto, 'args', return_value={})
    env_method_mock = mocker.patch(f'CrowdStrikeFalconSandboxV2.{method_name}', return_value='OK')
    main()
    assert env_method_mock.called and env_method_mock.return_value == 'OK'

import time
import sys

import demistomock as demisto
import requests_mock

import pytest


@pytest.fixture(autouse=True)
def mock_sleep(monkeypatch):
    def sleep(seconds):
        pass

    monkeypatch.setattr(time, "sleep", sleep)


def test_upload_sample_command(mocker):
    """
    Given:
        A file that has already been analyzed
    When:
        upload_sample_command is running
    Then:
        Make sure the error includes a hint how to change the Analysis Caching mode.
    """
    expected_output = str("Error in API call to VMRay [200] - [{'error_msg': 'Submission not stored because no jobs "
                          "were created. There is a possibility this file has been analyzed before. Please change the "
                          "Analysis Caching mode for this API key to something other than \"Legacy\" in the VMRay "
                          "Web Interface.', 'submission_filename': 'README.md'}]")
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    mocker.patch.object(demisto, 'command', return_value='vmray-upload-sample')
    mocker.patch.object(demisto, 'getFilePath', return_value={'id': 'id', 'path': 'README.md', 'name': 'README.md'})
    mocker_output = mocker.patch('VMRay.return_error')
    with requests_mock.Mocker() as m:
        m.request('POST',
                  'https://cloud.vmray.com/rest/sample/submit',
                  json={'data': {'errors': [{'error_msg': 'Submission not stored because no jobs were created',
                                             'submission_filename': 'README.md'}]}},
                  status_code=200)
        from VMRay import main

        main()

    assert mocker_output.call_args.args[0] == expected_output


def test_encoding_file_name(mocker):
    """
    Given:
        A string representing a file name with backslashes
    When:
        encode_file_name is running
    Then:
        Verify the output of encode_file_name is the same as the input string (in bytes) without it's backslashes
    """
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    file_name = '\\test\\encode\\file\\name'
    expected_output = 'testencodefilename'
    from VMRay import encode_file_name

    assert encode_file_name(file_name) == expected_output.encode('ascii', 'ignore')


def test_is_json(mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    from VMRay import is_json
    from requests.models import Response

    response = Response()
    response._content = b'{ "key" : "a" }'
    assert is_json(response)
    response._content = b'{ "key" : a }'
    assert not is_json(response)


def test_check_id(mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    from VMRay import check_id

    assert check_id(5)


def test_build_errors_string(mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    from VMRay import build_errors_string
    assert build_errors_string('Error') == 'Error'
    assert build_errors_string([{'error_msg': 'Error'}, {'error_msg': 'Another error'}]) == 'Error.\nAnother error.\n'
    assert build_errors_string({'error_msg': 'Error'}) == 'Error'


def test_dbot_score_by_hash(mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    from VMRay import dbot_score_by_hash

    assert dbot_score_by_hash({'MD5': '0322ea0cb2fcfa4281cf7804c8f553d1'}) == [
        {'Indicator': '0322ea0cb2fcfa4281cf7804c8f553d1',
         'Reliability': 'C - Fairly reliable',
         'Score': None,
         'Type': 'hash',
         'Vendor': 'VMRay'}]


def test_build_job_data(mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    from VMRay import build_job_data

    entry = {'job_id': 'test', 'job_sample_id': 'test',
             'job_submission_id': 'test', 'job_sample_md5': 'test',
             'job_sample_sha1': 'test', 'job_sample_sha256': 'test',
             'job_sample_ssdeep': 'test', 'job_vm_name': 'test',
             'job_vm_id': 'test', 'job_status': 'test'}
    assert build_job_data(entry) == {'JobID': 'test',
                                     'MD5': 'test',
                                     'SHA1': 'test',
                                     'SHA256': 'test',
                                     'SSDeep': 'test',
                                     'SampleID': 'test',
                                     'Status': 'test',
                                     'SubmissionID': 'test',
                                     'VMID': 'test',
                                     'VMName': 'test'}


def test_build_finished_job(mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/",
                                                         'shareable': False, 'reanalyze': False})
    from VMRay import build_finished_job

    assert build_finished_job('test', 'test') == {'JobID': 'test', 'SampleID': 'test', 'Status': 'Finished/NotExists'}


def test_rate_limit(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value={"api_key": "123456", "server": "https://cloud.vmray.com/"})
    requests_mock.get(
        "https://cloud.vmray.com/rest/submission/123",
        [
            {
                "status_code": 429,
                "json": {
                    "error_msg": "Request was throttled. Expected available in 2 seconds.",
                    "result": "error"
                },
                "headers": {
                    "Retry-After": "2"
                }
            },
            {
                "status_code": 200,
                "json": {
                    "foo": "bar"
                }
            }
        ]
    )

    from VMRay import http_request
    response = http_request("GET", "submission/123")

    assert requests_mock.call_count == 2
    assert response == {"foo": "bar"}


def test_rate_limit_max_reties(requests_mock, mocker):
    mocker.patch.object(demisto, "params", return_value={"api_key": "123456", "server": "https://cloud.vmray.com/"})
    mocker.patch.object(sys, "exit", return_value=None)
    requests_mock.get(
        "https://cloud.vmray.com/rest/analysis/123",
        [
            {
                "status_code": 429,
                "json": {
                    "error_msg": "Request was throttled. Expected available in 60 seconds.",
                    "result": "error"
                },
                "headers": {
                    "Retry-After": "60"
                }
            }
        ]
    )

    from VMRay import http_request
    response = http_request("GET", "analysis/123")

    assert requests_mock.call_count == 11
    assert response["error_msg"] == "Request was throttled. Expected available in 60 seconds."

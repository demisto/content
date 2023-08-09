import time
import sys

import demistomock as demisto
import requests_mock

import pytest

from CommonServerPython import EntryType

MOCK_URL = "https://cloud.vmray.com/"
MOCK_API_KEY = "123456"


@pytest.fixture(autouse=True)
def params(mocker):
    mocker.patch.object(demisto, "params", return_value={"api_key": MOCK_API_KEY, "server": MOCK_URL, "shareable": False})


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


@pytest.mark.parametrize(
    "file_name, expected",
    [
        ("abc.exe", b"abc.exe"),
        ("<>:\"/\\|?*a.exe", b"a.exe"),
        ("\\test\\encode\\file\\name", b"testencodefilename"),
        ("ñá@.exe", b"\xc3\xb1\xc3\xa1@.exe"),
    ]
)
def test_encoding_file_name(file_name, expected):
    """
    Given:
        A string representing a file name
    When:
        `encode_file_name` is running
    Then:
        Verify the output of `encode_file_name` is the same as the expected bytes.
        Characters that Windows doesn't allow for filenames get removed from the string.
    """
    from VMRay import encode_file_name

    assert encode_file_name(file_name) == expected


def test_is_json():
    from VMRay import is_json
    from requests.models import Response

    response = Response()
    response._content = b'{ "key" : "a" }'
    assert is_json(response)
    response._content = b'{ "key" : a }'
    assert not is_json(response)


@pytest.mark.parametrize(
    "input",
    [1, "1"]
)
def test_valid_id(input):
    from VMRay import check_id

    assert check_id(input)


@pytest.mark.parametrize(
    "input",
    [1.1, "foo"]
)
def test_invalid_id(input):
    from VMRay import check_id

    with pytest.raises(ValueError):
        check_id(input)


def test_build_errors_string():
    from VMRay import build_errors_string
    assert build_errors_string('Error') == 'Error'
    assert build_errors_string([{'error_msg': 'Error'}, {'error_msg': 'Another error'}]) == 'Error.\nAnother error.\n'
    assert build_errors_string({'error_msg': 'Error'}) == 'Error'


def test_dbot_score_by_hash():
    from VMRay import dbot_score_by_hash

    assert dbot_score_by_hash({'MD5': '0322ea0cb2fcfa4281cf7804c8f553d1'}) == [
        {'Indicator': '0322ea0cb2fcfa4281cf7804c8f553d1',
         'Reliability': 'C - Fairly reliable',
         'Score': None,
         'Type': 'hash',
         'Vendor': 'VMRay'}]


def test_build_job_data():
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


def test_build_finished_job():
    from VMRay import build_finished_job

    assert build_finished_job('test', 'test') == {'JobID': 'test', 'SampleID': 'test', 'Status': 'Finished/NotExists'}


def test_rate_limit(requests_mock):
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


def test_rate_limit_max_retries(requests_mock, mocker):
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


def test_billing_type(requests_mock):
    requests_mock.get(
        MOCK_URL + "rest/analysis/123",
        json={
            "data": {
                "analysis_billing_type": "detector"
            }
        }
    )

    from VMRay import get_billing_type
    billing_type = get_billing_type(123)
    assert billing_type == "detector"


def test_get_screenshots_command(requests_mock, mocker):
    from VMRay import main

    raw_screenshots_zip = (
        b'PK\x03\x04\x14\x00\x00\x00\x00\x00\x94k\tW\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00'
        b'screenshots/PK\x03\x04\x14\x00\x01\x00\x00\x00\xc3j\tW/Lw$\x83\x00\x00\x00w\x00\x00\x008\x00\x00\x00'
        b'screenshots/0d8bcf13d159a14aed6b2bf8b75a094aab4a6aeb.pngy\x1a\xc2\xf8(\xb1\xeb\x07Sf`\x05\x8d\xc8C\xa6\xb4~$'
        b'\xdd\xcd\x85\xd1GD\xa0\x87\x99Xh\xd1\xce"\x9c7a\xdd\x19\xd0}\xb8\xc8\xc1\x13\xd0\xc0?->\x8b\x02\xf8h^/\xdd'
        b'\x83\x10\xb9u\xb5\xe4td\x15\xd8w\xbfNM.&\xf5C \r>o\x8e`\xad\x98\xfevI\xf4\xb1\xafj<(\xb9[\xa7j5\x9a\xb2\xb2:'
        b'\xf1\xf3\xf2\xd3\xa0v\xf7V\xf9\xd4/A"\xb8\xa9\xac\xa1\x01N\xd7 \x1e\xf6\xf5\xf7Pk^\x8c\xaeFPK\x03\x04\x14'
        b'\x00\x01\x00\x08\x00\x8bk\tW\xbdA`\xb4\x95\x00\x00\x00\xd8\x00\x00\x00\x15\x00\x00\x00screenshots/index.log:'
        b'MVZm\xeb}\xb2a\xf9\xfcj(\x9c\xb5\n\xb0/\n\x81\x0b\xf9\xed\xfc\x18\xa8|\xea\x88\xe1\x96lr,Oz\xf1\x9f\xad\xb0'
        b'\xbe4\xe39h\xd8\x9a\xcc\xba\xc7\t\xfb\x0f\x85D\x1bZ?\x91B\x8f\x90\x1a\xb4\x9c\x8f\x8d\xb2\xf5\xee]\x8c\xeaG,'
        b'\xa3R\xadU\xc4\xbe_3\xbf\xfa\xc0 \xa4|\x85*\xac\x06s,S]1Y-\xd4\xdcV\x10\xe6kD\tca\xd9\x80$\xe2\xd6\x91<\xfa9'
        b'\x8d\xefUG\xbd\xd1n\x0fvq\x87\xa3\xf7m%\x0f\x18\xd0\x04+\xa7\xa3\'\x1b\xbfD\x0f\x858RPK\x01\x02?\x00\x14\x00'
        b'\x00\x00\x00\x00\x94k\tW\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00$\x00\x00\x00\x00\x00\x00\x00'
        b'\x10\x00\x00\x00\x00\x00\x00\x00screenshots/\n\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00\xbd\xb3)\xa4\xb4\xca'
        b'\xd9\x01\xbd\xb3)\xa4\xb4\xca\xd9\x01=\xd6?\xa0\xb4\xca\xd9\x01PK\x01\x02?\x00\x14\x00\x01\x00\x00\x00\xc3j'
        b'\tW/Lw$\x83\x00\x00\x00w\x00\x00\x008\x00$\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00*\x00\x00\x00screenshots'
        b'/0d8bcf13d159a14aed6b2bf8b75a094aab4a6aeb.png\n\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00?\xea5\xba\xb3\xca'
        b'\xd9\x01\xbd\xc86\xa4\xb4\xca\xd9\x01\xef\x02\xcb\xb9\xb3\xca\xd9\x01PK\x01\x02?\x00\x14\x00\x01\x00\x08\x00'
        b'\x8bk\tW\xbdA`\xb4\x95\x00\x00\x00\xd8\x00\x00\x00\x15\x00$\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x03\x01'
        b'\x00\x00screenshots/index.log\n\x00 \x00\x00\x00\x00\x00\x01\x00\x18\x00\x0f0\x98\x99\xb4\xca\xd9\x01\x0f0'
        b'\x98\x99\xb4\xca\xd9\x01Y\xfa\xac]\xb4\xca\xd9\x01PK\x05\x06\x00\x00\x00\x00\x03\x00\x03\x00O\x01\x00\x00\xcb'
        b'\x01\x00\x00\x00\x00'
    )
    file_result_return_value = {
        'Contents': b'',
        'File': 'analysis_123_screenshot_0.png',
        'FileID': '00000000-0000-0000-0000-000000000000',
        'Type': EntryType.IMAGE,
    }

    mocker.patch.object(demisto, 'args', return_value={'analysis_id': '123'})
    mocker.patch.object(demisto, 'command', return_value='vmray-get-screenshots')
    mocker.patch('VMRay.get_screenshots', return_value=raw_screenshots_zip)
    return_results_mock = mocker.patch('VMRay.return_results')
    file_result_mock = mocker.patch('VMRay.fileResult', return_value=file_result_return_value)

    main()

    file_result_mock.assert_called_once_with(
        filename='analysis_123_screenshot_0.png',
        data=(
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00'
            b'\x00\x00\x01sRGB\x00\xae\xce\x1c\xe9\x00\x00\x00\x04gAMA\x00\x00\xb1\x8f\x0b\xfca\x05\x00\x00\x00\tpHYs'
            b'\x00\x00\x0e\xc3\x00\x00\x0e\xc3\x01\xc7o\xa8d\x00\x00\x00\x0cIDAT\x18Wc8PY\r\x00\x03\xb1\x01\xb5\x95'
            b'\xd8i\xe4\x00\x00\x00\x00IEND\xaeB`\x82'
        ),
        file_type=EntryType.IMAGE,
    )
    return_results_mock.assert_called_once_with([file_result_return_value])

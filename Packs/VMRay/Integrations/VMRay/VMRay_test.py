import time
from unittest.mock import MagicMock

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
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00\xc3j\tW/Lw$l\x00\x00\x00w\x00\x00\x008\x00\x00\x00screenshots/"
        b"0d8bcf13d159a14aed6b2bf8b75a094aab4a6aeb.png\xeb\x0c\xf0s\xe7\xe5\x92\xe2b``\xe0\xf5\xf4p\t\x02\xd2\x8c "
        b"\xcc\xc1\x04$'\x94\x07\xdf\x03q\x8a\x83\xdc\x9d\x18\xd6\x9d\x93y\t\xe4\xb0\xa4;\xfa:20l\xec\xe7\xfe\x93\xc8"
        b"\n\xe4s\x16xD\x1630\xf0\x1d\x06a\xc6\xe3\xf9+R\x80\x82<\x9e.\x8e!\x12\xe1\xc9\x16\x01\x91\xbc\x0c\xcc\x1b"
        b"\x19\xb7N\xbd\x91\xf9\x04(\xce\xe0\xe9\xea\xe7\xb2\xce)\xa1\t\x00PK\x03\x04\x14\x00\x00\x00\x08\x00\x8bk"
        b"\tW\xbdA`\xb4\x89\x00\x00\x00\xd8\x00\x00\x00\x15\x00\x00\x00screenshots/index.log\x8d\x8e1\x0e\x021\x0c"
        b"\x04{$\xfep\x0f@(v\x1c'.\xee1^;\x81\x06\x84D\xcb\xe39~@\xb7\xd2\xcej\xb6l\x9f\x8d\xb8J\xd3#<\xb2\xed\xd2c-K"
        b"\xa2@\x93Ai\xa9u\xaa\x18\x81\x8d\x18zy\xdf\x9d\xf6\x92\x03\xb1\xa8&5s\x12\x9f\xa9`\xac\x81\xde\xbc\x98"
        b"\xb8C\\}\xe2Gs\xd3=\xe8\xa8\xcc\xca\xec\xd3\xe0>\xaa\x94\xc1VK\xd4\xa8sx\x8cL\x10z\xf5u,\xd3m\xa00\x07VB"
        b"\x1d@\x1e\xe7\xfeU^_\xcf\xdb\xf9\xf4\x05PK\x01\x02\x14\x00\x14\x00\x00\x00\x08\x00\xc3j\tW/Lw$l\x00\x00"
        b"\x00w\x00\x00\x008\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00screenshots"
        b"/0d8bcf13d159a14aed6b2bf8b75a094aab4a6aeb.pngPK\x01\x02\x14\x00\x14\x00\x00\x00\x08\x00\x8bk\tW\xbdA`\xb4"
        b"\x89\x00\x00\x00\xd8\x00\x00\x00\x15\x00\x00\x00\x00\x00\x00\x00\x01\x00 \x00\x00\x00\xc2\x00\x00"
        b"\x00screenshots/index.logPK\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00\xa9\x00\x00\x00~\x01\x00\x00\x00\x00"
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


@pytest.fixture
def mock_http_request(mocker):
    """Fixture to mock VMRay.generic_http_request with a specific response."""
    is_json = MagicMock()
    is_json.return_value = True
    mocker.patch('VMRay.is_json', return_value=is_json)

    def mock_request(method=None, url_suffix=None, params=None, files=None, get_raw=False, ignore_errors=False, status_code=200,
                     response_data=None, text=None):
        mock_response = MagicMock()
        mock_response.status_code = status_code
        if response_data:
            mock_response.json.return_value = response_data
        if text:
            mock_response.text = text
        mocker.patch('VMRay.generic_http_request', return_value=mock_response)
        return mock_request

    return mock_request


def test_http_request_success_200(mock_http_request):
    """
     Given: A successfully http request.
     When: Making a http request.
     Then: Assert correct data is returned.
    """
    from VMRay import http_request

    # Configure mock_http_request with desired status code and data
    mock_http_request(status_code=200, response_data={"data": "success"})

    # Call the function
    response = http_request("GET", "/api/endpoint")

    assert response == {"data": "success"}


def test_http_request_rate_limit_exceeded(mocker, mock_http_request):
    """
     Given: A failing http request.
     When: Making a http request.
     Then: Assert correct error message is returned.
    """
    from VMRay import http_request

    error_mock = mocker.patch('VMRay.return_error')

    # Configure mock_http_request for rate limit exceeded (429)
    mock_http_request(status_code=429, response_data={"message": "Rate limit exceeded"}, text="Rate limit exceeded")

    # Call the function
    http_request("GET", "/api/endpoint")

    # Assert expected behavior in the error message
    assert "Rate limit exceeded" in error_mock.call_args[0][0]

from CommonServerPython import *
import pytest
import tempfile
import requests

BASE_URL = "http://localhost:8008/metascan_rest/"
SCAN_RESULTS_RES_1: dict = {}
SCAN_RESULTS_RES_2: dict = {
    "file_info": {"file_type_description": "type_desc", "display_name": "display_name", "md5": "some_md5_hash"},
    "process_info": {"progress_percentage": 50},
    "scan_results": {
        "total_avs": 100,
        "scan_all_result_a": "scan_all_result_a",
        "scan_all_result_i": 100,
        "scan_details": {"key": {"def_time": "1/1/2023", "threat_found": "threat"}},
    },
}
HASH_INFO_RES_1: dict = {}
HASH_INFO_RES_2: dict = {
    "file_info": {"display_name": "display_name", "file_type_description": "type_desc"},
    "scan_results": {
        "scan_all_result_a": "scan_all_result_a",
        "total_detected_avs": 100,
        "total_avs": 100,
        "scan_details": {"key": {"def_time": "1/1/2023", "threat_found": "threat"}},
    },
}


class MockResponse:
    def __init__(self, json_data, status_code, content=None):
        self.json_data = json_data
        self.status_code = status_code
        self.content = content

    def json(self):
        return self.json_data

    def content(self):
        return self.content


# This method will be used by the mock to replace requests.post
def mocked_requests_post(*args, **kwargs):
    file_name = kwargs.get("headers", {}).get("filename", "")
    try:
        if type(file_name) is str:
            file_name.encode("latin-1")
        else:
            file_name.decode("latin-1")
        return MockResponse({"data_id": "mock_id"}, 200)
    except Exception as e:
        return MockResponse(str(e), 404)


@pytest.mark.parametrize(
    "file_name, data, expected_md_results",
    [
        (
            "2022年年年年年.docx",
            "年年年年年",
            "# OPSWAT-Metadefender\nThe file has been successfully submitted to scan.\nScan id: mock_id\n",
        )
    ],
)
def test_scan_file_command(mocker, file_name, data, expected_md_results):
    """
    Given:
    - File_name and content to mock file_entry.
    - case 1: a docx file with chinese letters in the name and content
    When:
    - Calling scan_file_command.
    Then:
    - Ensures the String type was parsed correctly and that the entry was generated correctly.
    - case 1: Ensures the request didn't fail due to letters parsing issue and that the entry was generated correctly.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = f"{temp_dir}/{file_name}"
        with open(file_path, "w") as f:
            f.write(data)
        mocker.patch.object(demisto, "getFilePath", return_value={"path": file_path, "name": file_name})
        mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})
        mocker.patch.object(requests, "post", side_effect=mocked_requests_post)
        mocker.patch.object(demisto, "args", return_value={"fileId": "1191@302", "scanRule": "Test"})
        mocker.patch.object(demisto, "results")

        from OPSWATMetadefenderV2 import scan_file_command

        scan_file_command()

    entry = demisto.results.call_args[0][0]
    ec_results = entry.get("EntryContext", {}).get("OPSWAT", {})
    assert entry.get("HumanReadable") == expected_md_results
    assert ec_results.get("ScanId") == "mock_id"
    assert ec_results.get("FileName") == file_name


# This method will be used by the mock to replace requests.get
def mocked_requests_get(*args, **kwargs):
    url = args[0]
    data = {}
    if "file" in url:
        id = url[-1]
        if id == "1":
            data = SCAN_RESULTS_RES_1
        elif id == "2":
            data = SCAN_RESULTS_RES_2
    elif "hash" in url:
        hash = url[-32:]
        if hash == "9d59494ca97bac09a2fb22188b03961f":
            data = HASH_INFO_RES_1
        elif hash == "9d59494ca97bac09a2fb22188b03961s":
            data = HASH_INFO_RES_2
    return MockResponse(data, 200)


@pytest.mark.parametrize(
    "id, expected_md_results",
    [
        ("1", "# OPSWAT-Metadefender\n### Results for scan id 1\nNo results for this id\n"),
        (
            "2",
            "# OPSWAT-Metadefender\n### Results for scan id 2\n### The scan proccess is in progrees (done: 50%) \nFile "
            "name: display_name\nScan result:scan_all_result_a\nDetected AV: 100/100\nAV Name|Def Time|Threat Name Found\n"
            "---|---|---\nkey|1/1/2023|threat\n",
        ),
    ],
)
def test_get_scan_result_command(mocker, id, expected_md_results):
    """
    Given:
    - a file id.
    - case 1: an id that return empty response
    - case 2: an id that return a non empty response
    When:
    - Running get_scan_result_command.
    Then:
    - Ensures the HumanReadable in the result entry was generated correctly.
    - case 1: Ensures the human readable contains a no results message.
    - case 2: Ensures the table in the human readable was generated correctly.
    """
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})
    mocker.patch.object(requests, "get", side_effect=mocked_requests_get)
    mocker.patch.object(demisto, "args", return_value={"id": id})
    mocker.patch.object(demisto, "results")

    from OPSWATMetadefenderV2 import get_scan_result_command

    get_scan_result_command()
    entry = demisto.results.call_args[0][0]
    assert entry.get("HumanReadable") == expected_md_results


@pytest.mark.parametrize(
    "hash, expected_md_results",
    [
        ("9d59494ca97bac09a2fb22188b03961f", "# OPSWAT-Metadefender\nNo results for hash 9d59494ca97bac09a2fb22188b03961f\n"),
        (
            "9d59494ca97bac09a2fb22188b03961s",
            "# OPSWAT-Metadefender\nFile name: display_name\nFile description: type_desc\n"
            "Scan result: scan_all_result_a\nDetected AV: 100/100\nAV Name|Def Time|Threat Name Found\n"
            "---|---|---\nkey|1/1/2023|threat\n",
        ),
    ],
)
def test_get_hash_info_command(mocker, hash, expected_md_results):
    """
    Given:
    - a file hash.
    - case 1: a hash that return empty response
    - case 2: a hash that return a non empty response
    When:
    - Running get_hash_info_command.
    Then:
    - Ensures the HumanReadable in the result entry was generated correctly.
    - case 1: Ensures the human readable contains a no results message.
    - case 2: Ensures the table in the human readable was generated correctly.
    """
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})
    mocker.patch.object(requests, "get", side_effect=mocked_requests_get)
    mocker.patch.object(demisto, "args", return_value={"hash": hash})
    mocker.patch.object(demisto, "results")

    from OPSWATMetadefenderV2 import get_hash_info_command

    get_hash_info_command()
    entry = demisto.results.call_args[0][0]
    assert entry.get("HumanReadable") == expected_md_results


def test_get_sanitized_file_command(mocker):
    """
    Given:
    - a file id.
    When:
    - Running get_sanitized_file_command.
    Then:
    - Ensures that sanitized file was created.
    """
    mocker.patch.object(demisto, "args", return_value={"id": "1"})
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})
    mocker.patch(
        "OPSWATMetadefenderV2.get_scan_result",
        return_value={
            "process_info": {"post_processing": {"converted_destination": "sanitized.pdf", "actions_ran": "Sanitized"}}
        },
    )
    mocker.patch("OPSWATMetadefenderV2.get_sanitized_file", return_value=b"sanitized file content")
    mocker.patch.object(demisto, "results")
    from OPSWATMetadefenderV2 import get_sanitized_file_command

    get_sanitized_file_command()
    entry = demisto.results.call_args[0][0]
    assert entry.get("File") == "sanitized.pdf"


def test_get_sanitized_file_fail_command(mocker):
    """
    Given:
    - a file id.
    When:
    - Running get_sanitized_file_command.
    Then:
    - Ensures that sanitized file wasn't created and warning was created.
    """
    mocker.patch.object(demisto, "args", return_value={"id": "1"})
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})
    mocker.patch("OPSWATMetadefenderV2.get_scan_result", return_value={"process_info": {}})
    mocker.patch("OPSWATMetadefenderV2.get_sanitized_file", return_value=b"sanitized file content")
    mocker.patch.object(demisto, "results")
    from OPSWATMetadefenderV2 import get_sanitized_file_command

    get_sanitized_file_command()
    entry = demisto.results.call_args[0][0]
    assert entry == {"Type": 11, "ContentsFormat": "text", "Contents": "No sanitized file."}


@pytest.mark.parametrize(
    "method, url_suffix, file_name, parse_json, scan_rule, expected_result, expected_status_code",
    [
        # # Test case 1: Basic GET request
        ("GET", "test", None, True, None, {"success": True}, 200),
        # # Test case 2: GET request with scan rule
        ("GET", "hash/123", None, True, "custom_rule", {"file_info": {"md5": "123"}}, 200),
        # # Test case 3: POST request
        ("POST", "file", None, True, None, {"data_id": "scan123"}, 200),
        # # Test case 5: File upload
        ("POST", "file", "test_file.txt", True, None, {"data_id": "file123"}, 200),
        # # Test case 6: Non-JSON response
        ("GET", "file/converted/123", None, False, None, b"test file content", 200),
    ],
)
def test_http_req(mocker, method, url_suffix, file_name, parse_json, scan_rule, expected_result, expected_status_code):
    """
    Given:
    - Different HTTP request scenarios for the http_req function
    - Case 1: Basic GET request
    - Case 2: GET request with custom scan rule
    - Case 3: POST request
    - Case 5: File upload
    - Case 6: Non-JSON response

    When:
    - Calling http_req with various parameters

    Then:
    - Ensures the function handles different HTTP methods correctly
    - Ensures proper headers are set based on parameters
    - Ensures file uploads are handled correctly
    - Ensures response parsing works as expected
    """
    # Setup mocks
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL, "api_key_creds": {"password": "test_api_key"}})

    # Mock file operations
    mock_open = mocker.mock_open(read_data=b"test file content")
    mocker.patch("builtins.open", mock_open)

    # Create mock response
    mock_response = MockResponse(expected_result, expected_status_code, b"test file content")

    # Mock requests methods
    if method.upper() == "GET":
        mocker.patch.object(requests, "get", return_value=mock_response)
    elif method.upper() == "POST":
        mocker.patch.object(requests, "post", return_value=mock_response)

    # Import the function after mocking
    from OPSWATMetadefenderV2 import http_req

    # Call the function
    result = http_req(method=method, url_suffix=url_suffix, file_name=file_name, parse_json=parse_json, scan_rule=scan_rule)

    # Verify the result
    assert result == expected_result

    # Verify the correct request method was called with proper parameters
    if method.upper() == "GET":
        requests_mock = requests.get
    elif method.upper() == "POST":
        requests_mock = requests.post

    # Verify URL
    expected_url = BASE_URL + url_suffix
    assert requests_mock.call_args[0][0] == expected_url

    # Verify headers
    headers = requests_mock.call_args[1]["headers"]
    assert headers["Accept"] == "application/json"

    # Verify scan rule if provided
    if scan_rule:
        assert headers["rule"] == scan_rule.encode("utf-8")

    # Verify file upload headers if file_name is provided
    if file_name:
        assert headers["content-type"] == "application/octet-stream"
        assert headers["filename"] == file_name.encode("utf-8")
        assert mock_open.call_args[0][0] == file_name
        assert requests_mock.call_args.kwargs["data"].read() == b"test file content"


@pytest.mark.parametrize(
    "status_code, expected_error",
    [
        (400, "Request failed, got status 400: bad request. Check command parameters"),
        (401, "Request failed, got status 401: unauthorized. Check your API Key"),
        (404, "Request failed, got status 404: not found. Check integration URL Address"),
        (500, "Request failed got status 500"),
    ],
)
def test_http_req_error_handling(mocker, status_code, expected_error):
    """
    Given:
    - Different HTTP error status codes
    - Case 1: 400 Bad Request
    - Case 2: 401 Unauthorized
    - Case 3: 404 Not Found
    - Case 4: 500 Server Error (not in predefined error codes)

    When:
    - Calling http_req and receiving an error status code

    Then:
    - Ensures the function handles error codes correctly
    - Ensures appropriate error messages are returned
    """
    # Setup mocks
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})

    # Create mock response with error status
    mock_response = MockResponse({}, status_code)
    mocker.patch.object(requests, "get", return_value=mock_response)

    # Mock return_error function
    mock_return_error = mocker.patch("OPSWATMetadefenderV2.return_error")

    # Import the function after mocking
    from OPSWATMetadefenderV2 import http_req

    # Call the function
    http_req(method="GET", url_suffix="test")

    # Verify return_error was called with the expected error message
    mock_return_error.assert_called_once_with(expected_error)


def test_http_req_unsupported_method(mocker):
    """
    Given:
    - An unsupported HTTP method

    When:
    - Calling http_req with an unsupported method

    Then:
    - Ensures the function handles unsupported methods correctly
    - Ensures appropriate error message is returned
    """
    # Setup mocks
    mocker.patch.object(demisto, "params", return_value={"url": BASE_URL})

    # Mock return_error function
    mock_return_error = mocker.patch("OPSWATMetadefenderV2.return_error")

    # Import the function after mocking
    from OPSWATMetadefenderV2 import http_req

    # Call the function with unsupported method
    result = http_req(method="PUT", url_suffix="test")

    # Verify return_error was called with the expected error message
    mock_return_error.assert_called_once_with("Got unsupporthed http method: PUT")

    # Verify the function returns an empty string
    assert result == ""

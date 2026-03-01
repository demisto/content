from CommonServerPython import *
import pytest

RETURN_ERROR_TARGET = "AbuseDB.return_error"


class DotDict(dict):
    """dot.notation access to dictionary attributes"""

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


@pytest.mark.parametrize("days", [1, 400, 0])
def test_ip_command_api_params(mocker, days):
    """
    Given: A mocked AbuseDB API that returns a successful response
          And integration params with conditional days handling (uses 50 when days=0)
    When: The check_ip_command is called with different days parameters (1, 400, 0)
    Then: The API request should be made with correct parameters including:
          - ipAddress set to the provided IP (1.1.1.1)
          - maxAgeInDays set to the exact days value passed to the function
          And the integration params should handle edge cases (days=0 → fallback to 50)
    """
    from requests import Session

    expected_res = {
        "data": {
            "ipAddress": "1.1.1.1",
            "abuseConfidencePercentage": 0,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "countryName": "United States",
            "usageType": "dummy",
            "isp": "dummy",
            "domain": "dummy.com",
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
            "reports": [],
            "hostnames": [],
            "ipVersion": 4,
            "isPublic": True,
            "isTor": False,
            "isWhitelisted": False,
        }
    }

    def json_func():
        return expected_res

    success_response = {"status_code": 200, "json": json_func}

    params = {
        "server": "https://api.abuseipdb.com/api/v2/",
        "proxy": True,
        "disregard_quota": True,
        "disable_private_ip_lookup": False,
        "integrationReliability": DBotScoreReliability.C,
        "days": days if days else 50,
    }

    success_response_with_dot_access = DotDict(success_response)

    mocker.patch.object(demisto, "params", return_value=params)
    request_mock = mocker.patch.object(Session, "request", return_value=success_response_with_dot_access)
    mocker.patch.object(demisto, "results")
    from AbuseDB import check_ip_command

    check_ip_command(DBotScoreReliability.C, ["1.1.1.1"], days=days, threshold=75)

    # Verify the API call was made with correct parameters
    assert request_mock.call_count == 1
    call_args = request_mock.call_args

    # Check method and URL
    assert call_args[0][0] == "GET"  # method
    assert "check" in call_args[0][1]  # URL contains 'check' endpoint

    # Check parameters sent to API
    api_params = call_args[1]["params"]
    assert api_params["ipAddress"] == "1.1.1.1"
    assert api_params["maxAgeInDays"] == days


def test_ip_command_when_api_quota_reached(mocker):
    from requests import Session

    def json_func():
        return {}

    api_quota_reached_request_response = {"status_code": 429, "json": json_func}

    params = {
        "server": "test",
        "proxy": True,
        "disregard_quota": True,
        "disable_private_ip_lookup": False,
        "integrationReliability": DBotScoreReliability.C,
    }

    api_quota_reached_request_response_with_dot_access = DotDict(api_quota_reached_request_response)

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(Session, "request", return_value=api_quota_reached_request_response_with_dot_access)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    from AbuseDB import check_ip_command

    check_ip_command(DBotScoreReliability.C, ["1.1.1.1"], days=7, verbose=False, threshold=10)
    assert return_error_mock.call_count == 0


def test_get_fplist_command_json(mocker):
    """
    Given:
        - A JSON response from Abuse.ch Hunting API for get_fplist.
    When:
        - get_fplist_command is called with format='json'.
    Then:
        - Verify the flattening logic (ID injection).
        - Verify CommandResults output.
    """
    mocker.patch.object(demisto, "command", return_value="abuseipdb-get-fplist")
    from AbuseDB import get_fplist_command
    import AbuseDB

    mock_response = {
        "1001": {
            "time_stamp": "2024-01-01 12:00:00 UTC",
            "platform": "TestPlatform",
            "entry_type": "ip",
            "entry_value": "8.8.8.8",
            "removed_by": "user1",
            "removal_notes": "test note",
        },
        "1002": {
            "time_stamp": "2024-01-01 13:00:00 UTC",
            "platform": "TestPlatform",
            "entry_type": "domain",
            "entry_value": "test.com",
            "removed_by": "user2",
            "removal_notes": "another note",
        },
    }

    class MockResponse:
        def __init__(self, json_data):
            self.json_data = json_data
            self.status_code = 200

        def json(self):
            return self.json_data

    mocker.patch.object(AbuseDB, "abusech_hunting_http_request", return_value=MockResponse(mock_response))

    results = get_fplist_command(format="json", limit=1, all_results=False)

    assert isinstance(results, CommandResults)
    assert isinstance(results.outputs, list)
    assert len(results.outputs) == 1
    assert results.outputs[0]["id"] == "1001"
    assert results.outputs[0]["entry_value"] == "8.8.8.8"
    assert "Abuse.ch False Positive List" in results.readable_output


def test_get_fplist_command_csv(mocker):
    """
    Given:
        - A CSV response from Abuse.ch Hunting API for get_fplist.
    When:
        - get_fplist_command is called with format='csv'.
    Then:
        - Verify fileResult is returned with correct content.
    """
    mocker.patch.object(demisto, "command", return_value="abuseipdb-get-fplist")
    from AbuseDB import get_fplist_command
    import AbuseDB

    # Mock demisto.uniqueFile and demisto.investigation to prevent physical file creation
    # while still allowing fileResult to execute its internal logic.
    mocker.patch.object(demisto, "uniqueFile", return_value="test_file")
    mocker.patch.object(demisto, "investigation", return_value={"id": "test_inv"})

    # Mock the built-in open to prevent writing to the file system
    mocked_open = mocker.patch("builtins.open", mocker.mock_open())

    csv_content = b'"time_stamp","removal_id","platform","entry_type","entry_value","removed_by","removal_notes"'

    class MockResponse:
        def __init__(self, content):
            self.content = content
            self.status_code = 200

    mocker.patch.object(AbuseDB, "abusech_hunting_http_request", return_value=MockResponse(csv_content))

    results = get_fplist_command(format="csv", limit=10, all_results=True)

    assert results["Type"] == EntryType.FILE
    assert results["File"] == "abusech_fplist.csv"
    assert results["ContentsFormat"] == "text"

    # Verify that open was called with the expected filename and mode
    mocked_open.assert_called_once_with("test_inv_test_file", "wb")
    # Verify that the correct content was written
    mocked_open().write.assert_called_once_with(csv_content)


def test_get_fplist_command_error(mocker):
    """
    Given:
        - An API error from Abuse.ch Hunting API.
    When:
        - get_fplist_command is called.
    Then:
        - Verify Exception is raised with the expected message.
    """
    import AbuseDB
    from AbuseDB import get_fplist_command

    mocker.patch.object(AbuseDB, "ABUSECH_API_KEY", "test-key")
    mocker.patch.object(AbuseDB, "abusech_hunting_http_request", side_effect=Exception("API Error"))

    with pytest.raises(Exception, match="API Error"):
        get_fplist_command(format="json", limit=10, all_results=True)


def test_abusech_hunting_http_request_success(mocker):
    """
    Given:
        - Valid headers and payload.
        - A successful 200 OK response from the API.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify the request is made with correct parameters.
        - Verify the response object is returned.
    """
    from requests import Session
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": None}  # No error wrapped in JSON

    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
    mocker.patch.object(AbuseDB, "ABUSECH_API_KEY", "test-key")
    mocker.patch.object(AbuseDB, "INSECURE", False)
    request_mock = mocker.patch.object(Session, "request", return_value=mock_response)

    headers = {"Auth-Key": "test"}
    payload = {"query": "test"}

    response = abusech_hunting_http_request(headers, payload)

    assert response is not None
    assert response.status_code == 200
    request_mock.assert_called_once_with(method="POST", url="https://test-url", headers=headers, json=payload, verify=True)


def test_abusech_hunting_http_request_api_error(mocker):
    """
    Given:
        - A non-200 response from the API.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify Exception is raised with the expected message.
    """
    from requests import Session
    import requests
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mock_response = mocker.Mock()
    mock_response.status_code = 404
    # raise_for_status raises HTTPError
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error: Not Found")

    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
    mocker.patch.object(AbuseDB, "ABUSECH_API_KEY", "test-key")
    mocker.patch.object(Session, "request", return_value=mock_response)

    with pytest.raises(Exception, match="Failed to connect to Abuse.ch: 404 Client Error: Not Found"):
        abusech_hunting_http_request({}, {})


def test_abusech_hunting_http_request_api_warpped_error(mocker):
    """
    Given:
        - A response where the error is wrapped in a 200 OK response.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify Exception is raised with the error message from the 'data' field.
    """
    from requests import Session
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "unknown_auth_key",
        "data": "The Auth-Key you provided is unknown.",
    }

    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
    mocker.patch.object(AbuseDB, "ABUSECH_API_KEY", "test-key")
    mocker.patch.object(Session, "request", return_value=mock_response)

    with pytest.raises(Exception, match="The Auth-Key you provided is unknown"):
        abusech_hunting_http_request({}, {})


def test_abusech_hunting_http_request_connection_error(mocker):
    """
    Given:
        - A connection exception during the request.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify Exception is raised with the connection error message.
    """
    from requests import Session
    import requests
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mocker.patch.object(
        demisto,
        "params",
        return_value={"abusech_hunting_url": "https://test-url", "hunting_credentials": {"password": "test-key"}},
    )
    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
    mocker.patch.object(AbuseDB, "ABUSECH_API_KEY", "test-key")
    mocker.patch.object(Session, "request", side_effect=requests.exceptions.RequestException("Connection failed"))

    with pytest.raises(Exception, match="Failed to connect to Abuse.ch: Connection failed"):
        abusech_hunting_http_request({}, {})


def test_abusech_hunting_http_request_missing_url(mocker):
    """
    Given:
        - A missing ABUSECH_URL parameter.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify Exception is raised with the missing URL message.
    """
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    # Patch the global variable directly to simulate missing parameter
    mocker.patch.object(AbuseDB, "ABUSECH_URL", None)
    mocker.patch.object(AbuseDB, "ABUSECH_API_KEY", "test-key")

    with pytest.raises(Exception, match="Hunting API URL was not provided"):
        abusech_hunting_http_request({}, {})

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
    mock_response.text = "OK"

    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
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
        - Verify return_error is called with the expected message.
    """
    from requests import Session
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mock_response = mocker.Mock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"

    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
    mocker.patch.object(Session, "request", return_value=mock_response)
    return_error_mock = mocker.patch.object(AbuseDB, "return_error")

    abusech_hunting_http_request({}, {})

    return_error_mock.assert_called_once_with("Abuse.ch API error: 404 - Not Found")


def test_abusech_hunting_http_request_connection_error(mocker):
    """
    Given:
        - A connection exception during the request.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify return_error is called with the connection error message.
    """
    from requests import Session
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mocker.patch.object(AbuseDB, "ABUSECH_URL", "https://test-url")
    mocker.patch.object(Session, "request", side_effect=Exception("Connection failed"))
    return_error_mock = mocker.patch.object(AbuseDB, "return_error")

    abusech_hunting_http_request({}, {})

    return_error_mock.assert_called_once_with("Failed to connect to Abuse.ch: Connection failed")


def test_abusech_hunting_http_request_missing_url(mocker):
    """
    Given:
        - A missing ABUSECH_URL parameter.
    When:
        - abusech_hunting_http_request is called.
    Then:
        - Verify return_error is called with the missing URL message.
    """
    import AbuseDB
    from AbuseDB import abusech_hunting_http_request

    mocker.patch.object(AbuseDB, "ABUSECH_URL", None)
    return_error_mock = mocker.patch.object(AbuseDB, "return_error", side_effect=Exception("return_error"))

    with pytest.raises(Exception, match="return_error"):
        abusech_hunting_http_request({}, {})

    assert return_error_mock.call_args_list[0] == mocker.call("Hunting API URL was not provided in the params.")

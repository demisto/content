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

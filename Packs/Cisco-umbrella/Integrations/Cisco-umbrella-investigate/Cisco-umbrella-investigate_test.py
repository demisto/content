import pytest
import requests

import demistomock as demisto
import importlib
from CommonServerPython import DBotScoreReliability, Common

Cisco_umbrella_investigate = importlib.import_module('Cisco-umbrella-investigate')


ERROR_VERIFY_THRESHOLD_MESSAGE = 'Please provide valid threshold values for the Suspicious and Malicious thresholds when ' \
                                 'Suspicious is greater than Malicious and both are within a range of -100 to 100'


@pytest.mark.parametrize('suspicous, malicious, expected_mock_result', [
    (0, -100, None),
    (0, -200, ERROR_VERIFY_THRESHOLD_MESSAGE),
    (200, -100, ERROR_VERIFY_THRESHOLD_MESSAGE),
    (0, 50, ERROR_VERIFY_THRESHOLD_MESSAGE)
])
def test_verify_threshold_suspicouns_and_malicious_parameters(suspicous, malicious, expected_mock_result, mocker):
    """
        Given:
            - The suspicious and malicious thresholds params
        When:
            - Running the integration
        Then:
            - Verify suspicious is bigger then malicious and both of them in range of -100 to 100
    """
    mock_result = mocker.patch('Cisco-umbrella-investigate.return_error')
    Cisco_umbrella_investigate.verify_threshold_params(suspicous, malicious)

    if not mock_result.call_args:
        assert not expected_mock_result
    else:
        assert mock_result.call_args[0][0] == expected_mock_result


def test_reliability_in_get_domain_security_command(mocker):
    """
        Given:
            - The user reliability param
        When:
            - Running get_domain_security_command
        Then:
            - Verify reliability as excepted
    """
    params = {
        'APIToken': '12345678',
        'baseURL': 'https://test.com',
        'integrationReliability': DBotScoreReliability.B
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'domain': 'test.com'})
    mocker.patch.object(Cisco_umbrella_investigate, 'http_request')

    results = Cisco_umbrella_investigate.get_domain_security_command()

    assert results[0]['EntryContext']['DBotScore']['Reliability'] == 'B - Usually reliable'


def test_get_domain_command_all_domains_are_valid(mocker):
    """
        Given:
            - list of domains
        When:
            - All of the domains can be found by whois
        Then:
            - returns results for all of the domains
            - return successful metrics
    """
    mocker.patch.object(demisto, 'args', return_value={'domain': ["good1.com", "good2.com", "good3.com"]})
    mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', return_value={})
    domains_info = {
        "good1.com": {"key": "val"},
        "good2.com": {"key": "val"},
        "good3.com": {"key": "val"}
    }
    mocker.patch.object(Cisco_umbrella_investigate, 'http_request', return_value=domains_info)
    mocker.patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.8.0',
        'buildNumber': '12345'
    })

    results = Cisco_umbrella_investigate.get_domain_command()
    assert len(results) == 4
    metrics = results[3].execution_metrics
    assert metrics == [{'Type': 'Successful', 'APICallsCount': 3}]


def test_get_domain_command_no_valid_domains(mocker):
    """
        Given:
            - list of domains
        When:
            - All of the domains cannot be found by whois
        Then:
            - return an empty list
            - return general error metrics
    """
    error = requests.HTTPError()
    error.response = requests.Response()
    error.response.status_code = 404
    mocker.patch.object(demisto, 'args', return_value={'domain': ["bad1.com", "bad2.com"]})
    mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', side_effect=error)
    mocker.patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.8.0',
        'buildNumber': '12345'
    })

    results = Cisco_umbrella_investigate.get_domain_command()
    assert len(results) == 3
    metrics = results[2].execution_metrics
    assert metrics == [{'Type': 'GeneralError', 'APICallsCount': 2}]


def test_get_domain_command_quota_error(mocker):
    """
        Given:
            - list of domains
        When:
            - Quota limit reached
        Then:
            - return an empty list
            - return quota error metrics
    """
    error = requests.HTTPError()
    error.response = requests.Response()
    error.response.status_code = 429
    mocker.patch.object(demisto, 'args', return_value={'domain': ["quota.com", "quota.com"]})
    mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', side_effect=error)
    mocker.patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.8.0',
        'buildNumber': '12345'
    })

    results = Cisco_umbrella_investigate.get_domain_command()
    assert len(results) == 3
    metrics = results[2].execution_metrics
    assert metrics == [{'Type': 'QuotaError', 'APICallsCount': 2}]


def test_get_domain_command_some_valid_domains(mocker):
    """
        Given:
            - list of domains
        When:
            - Some of the domains can be found by whois
        Then:
            - returns results for all of the domains that can be found
    """
    mocker.patch.object(demisto, 'args', return_value={'domain': ["good.com", "bad.com"]})
    mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', side_effect=different_inputs_handling)
    mocker.patch.object(Cisco_umbrella_investigate, 'http_request', return_value={"good.com": {"key": "val"}})
    mocker.patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.8.0',
        'buildNumber': '12345'
    })

    results = Cisco_umbrella_investigate.get_domain_command()
    assert len(results) == 3
    metrics = results[2].execution_metrics
    assert metrics == [{'Type': 'Successful', 'APICallsCount': 1}, {'Type': 'GeneralError', 'APICallsCount': 1}]


def test_get_whois_command_for_domain(mocker):
    """
        Given:
            - list of domains
        When:
            - Some of the domains can be found by whois
        Then:
            - returns results for all of the domains that can be found
            - returns metrics command results
    """
    mocker.patch.object(demisto, 'args', return_value={'domain': "good.com"})
    domains_info = {
        "good1.com": {"key": "val"},
        "domainName": "good1.com"
    }
    mocker.patch.object(Cisco_umbrella_investigate, 'http_request', return_value=domains_info)
    mocker.patch.object(demisto, 'demistoVersion', return_value={
        'version': '6.8.0',
        'buildNumber': '12345'
    })
    results_whois_command = Cisco_umbrella_investigate.get_whois_for_domain_command()
    assert len(results_whois_command) == 2
    metrics = results_whois_command[1].execution_metrics
    assert metrics == [{'Type': 'Successful', 'APICallsCount': 1}]


def test_get_domain_command_non_404_request_exception(mocker):
    """
        Given:
            - list of domains
        When:
            - A non 404 http error is returned
        Then:
            - raise error
    """
    with pytest.raises(SystemExit):
        error = requests.HTTPError()
        error.response = requests.Response()
        error.response.status_code = 403
        mocker.patch.object(demisto, 'args', return_value={'domain': ["bad1.com", "bad2.com"]})
        mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', side_effect=error)
        Cisco_umbrella_investigate.get_domain_command()


def different_inputs_handling(*args):
    if args[0] == "good.com":
        return {}
    if args[0] == "bad.com":
        error = requests.HTTPError()
        error.response = requests.Response()
        error.response.status_code = 404
        raise error


@pytest.mark.parametrize(("status", "securerank2", "expected_score"), (
    pytest.param(0, None, Common.DBotScore.NONE, id="status 0"),
    pytest.param(-1, None, Common.DBotScore.BAD, id="status -1"),
    pytest.param(1, None, Common.DBotScore.GOOD, id="status 1"),
    pytest.param(None, None, Common.DBotScore.NONE, id="status None, rank None"),
    pytest.param(0, Cisco_umbrella_investigate.SUSPICIOUS_THRESHOLD + 1, Common.DBotScore.GOOD, id="above suspicious threshold"),
    pytest.param(1, Cisco_umbrella_investigate.SUSPICIOUS_THRESHOLD + 1,
                 Common.DBotScore.GOOD, id="status (1) is stronger than threshold"),
    pytest.param(-1, Cisco_umbrella_investigate.SUSPICIOUS_THRESHOLD + 1,
                 Common.DBotScore.BAD, id="status (-1) is stronger than threshold"),
    pytest.param(0, Cisco_umbrella_investigate.SUSPICIOUS_THRESHOLD, Common.DBotScore.GOOD, id="equal to suspicious threshold"),
    pytest.param(0, Cisco_umbrella_investigate.SUSPICIOUS_THRESHOLD - 1,
                 Common.DBotScore.SUSPICIOUS, id="below suspicious to threshold"),
    pytest.param(0, Cisco_umbrella_investigate.MALICIOUS_THRESHOLD + 1,
                 Common.DBotScore.SUSPICIOUS, id="above malicious threshold"),
    pytest.param(0, Cisco_umbrella_investigate.MALICIOUS_THRESHOLD,
                 Common.DBotScore.SUSPICIOUS, id="equal to malicious threshold"),
    pytest.param(0, Cisco_umbrella_investigate.MALICIOUS_THRESHOLD - 1, Common.DBotScore.BAD, id="below malicious threshold"),
))
def test_calculate_domain_dbot_score(status: int | None, securerank2: int | None, expected_score: int):
    assert Cisco_umbrella_investigate.calculate_domain_dbot_score(status, securerank2) == expected_score


@pytest.mark.parametrize("status", (("", "3", "none", "na", "NA", "🥲")))
def test_calculate_domain_dbot_score_unexpected_status(status: str):
    with pytest.raises(ValueError, match=f"unexpected {status=}, expected 0,1 or -1"):
        Cisco_umbrella_investigate.calculate_domain_dbot_score(status, 0)

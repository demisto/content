import pytest

import demistomock as demisto
import importlib
from CommonServerPython import DBotScoreReliability

Cisco_umbrella_investigate = importlib.import_module('Cisco-umbrella-investigate')


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
    """
    mocker.patch.object(demisto, 'args', return_value={'domain': ["good1.com", "good2.com", "good3.com"]})
    mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', return_value={})

    assert len(Cisco_umbrella_investigate.get_domain_command()) == 3


def test_get_domain_command_no_valid_domains(mocker):
    """
        Given:
            - list of domains
        When:
            - All of the domains cannot be found by whois
        Then:
            - An Exception is raised
    """
    with pytest.raises(Exception):
        mocker.patch.object(demisto, 'args', return_value={'domain': ["bad1.com", "bad2.com"]})
        mocker.patch.object(Cisco_umbrella_investigate, 'get_whois_for_domain', side_effect=Exception())

        Cisco_umbrella_investigate.get_domain_command()


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

    assert len(Cisco_umbrella_investigate.get_domain_command()) == 1


def different_inputs_handling(*args):
    if args[0] == "good.com":
        return {}
    if args[0] == "bad.com":
        raise Exception()

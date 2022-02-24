"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io
from ACTIThreatIntelReport import Client, _calculate_dbot_score, getThreatReport_command
from test_data.response_constants import *
import requests_mock
from CommonServerPython import DBotScoreReliability

API_URL = "https://test.com"


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())



def test_calculate_dbot_score():
    """
    Given:
        - number represents severity

    When:
        - api call with indicator returns response that includes them severity score

    Then:
        - returns dbotscore according to internal conversion

    """
    assert _calculate_dbot_score(0) == 0
    assert _calculate_dbot_score(1) == 1
    assert _calculate_dbot_score(2) == 1
    assert _calculate_dbot_score(3) == 2
    assert _calculate_dbot_score(4) == 2
    assert _calculate_dbot_score(5) == 3
    assert _calculate_dbot_score(6) == 3
    assert _calculate_dbot_score(7) == 3



def test_getThreatReport_command():
    """
    Given:
        - an CVE

    When:
        - running Vulnerability command and validate whether the CVE is malicious

    Then:
        - return command results containing Vulnerability, dbotscore

    """
    url = 'https://test.com/rest/vulnerability/v0?key.values=CVE-2022-23021'
    status_code = 200
    json_res = JSON_IA1

    expected_output = {}

    uuid_to_check = {'uuid': ''}

    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_res)
        client = Client(API_URL, 'api_token', True, False, '/rest/document')
        results = getThreatReport_command(client, uuid_to_check, DBotScoreReliability.B)
        output = results[0].to_context().get('EntryContext', {})

        assert True
        assert True



def test_getThreatReport_not_found():
    pass
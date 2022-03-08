import json
import io
from ACTIThreatIntelReport import Client, _calculate_dbot_score, getThreatReport_command, fix_markdown, connection_module
from test_data.response_constants import *
import requests_mock
from CommonServerPython import DBotScoreReliability

API_URL = "https://test.com"
DBOT_SCORE = "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)"


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


def test_fix_markdown():
    text_to_update = "##Key Findings and Judgements\n\n* The sophisticated [cyber espionage operation](/#/node/intelligence"\
        "_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4) was selective; it used supply-chain attack techniques,"\
        " mainly a malicious update of a widely used product from IT monitoring firm SolarWinds,"\
        " but its final target list appears to number only in the hundreds. Known targets include public-"\
        " and private-sector entities, mostly in the US, including IT vendors, US government entities, and think"\
        " tanks (#/node/intelligence_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4)."
    expected_output = "## Key Findings and Judgements\n\n* The sophisticated [cyber espionage operation](https://intelgraph."\
        "idefense.com/#/node/intelligence_alert/view/a655306d-bd95-426d-8c93-ebeef57406e4) was selective; it"\
        " used supply-chain attack techniques, mainly a malicious update of a widely used product from IT "\
        "monitoring firm SolarWinds, but its final target list appears to number only in the hundreds. Known "\
        "targets include public- and private-sector entities, mostly in the US, including IT vendors, US "\
        "government entities, and think tanks (https://intelgraph.idefense.com/#/node/intelligence_alert"\
        "/view/a655306d-bd95-426d-8c93-ebeef57406e4)."
    output = fix_markdown(text_to_update)
    assert expected_output == output


def test_getThreatReport_ia_command():
    """
    Given:
        - an URL

    When:
        - running ThreatReport command and fetch IA/IR

    Then:
        - return command results containing UUID, dbotscore

    """
    url = 'https://test.com/rest/document/v0/a487dfdc-08b4-4909-82ea-2d934c27d901'
    status_code = 200
    json_res = RES_JSON_IA

    expected_output = expected_output_ia

    url_to_check = {'url': 'https://intelgraph.idefense.com/#/node/intelligence_alert/view/a487dfdc-08b4-4909-82ea-2d934c27d901'}

    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_res)
        client = Client(API_URL, 'api_token', True, False, '/rest/document')
        results = getThreatReport_command(client, url_to_check, DBotScoreReliability.B)
        output = results.to_context().get('EntryContext', {})
        assert output.get('IAIR(val.value && val.value == obj.value)', []) == expected_output.get('IA')
        assert output.get(DBOT_SCORE, []) == expected_output.get('DBot')


def test_getThreatReport_ir_command():
    """
    Given:
        - an URL

    When:
        - running ThreatReport command and fetch IA/IR

    Then:
        - return command results containing UUID, dbotscore

    """
    url = 'https://test.com/rest/document/v0/bdc9d16f-6040-4894-8544-9c98986a41fd'
    status_code = 200
    json_res = RES_JSON_IR

    expected_output = expected_output_ir

    url_to_check = {'url': 'https://intelgraph.idefense.com/#/node/intelligence_report/view/bdc9d16f-6040-4894-8544-9c98986a41fd'}

    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_res)
        client = Client(API_URL, 'api_token', True, False, '/rest/document')
        results = getThreatReport_command(client, url_to_check, DBotScoreReliability.B)
        output = results.to_context().get('EntryContext', {})
        assert output.get('IAIR(val.value && val.value == obj.value)', []) == expected_output.get('IR')
        assert output.get(DBOT_SCORE, []) == expected_output.get('DBot')


def test_getThreatReport_not_found():
    url = 'https://test.com/rest/document/v0/a487dfdc-08b4-49a09-82ea-2d934c27d901'
    status_code = 200
    json_res = None

    expected_output = 'No report was found for UUID: a487dfdc-08b4-49a09-82ea-2d934c27d901 !!'

    url_to_check = {'url': 'https://intelgraph.idefense.com/#/node/intelligence_alert/view/a487dfdc-08b4-49a09-82ea-2d934c27d901'}

    with requests_mock.Mocker() as m:
        m.get(url, status_code=status_code, json=json_res)
        client = Client(API_URL, 'api_token', True, False, '/rest/document')
        results = getThreatReport_command(client, url_to_check, DBotScoreReliability.B)
        output = results.to_context().get('HumanReadable')
        assert expected_output in output


def test_connection_module():
    """
    Given:
        - an api token

    When:
        - checking api access

    Then:
        - ok if there is access

    """
    with requests_mock.Mocker() as m:
        print("test----final")
        url = 'https://test.com/rest/document/v0'
        m.get(url, status_code=200, json={})
        client = Client(API_URL, 'api_token', True, False, '/rest/document')
        assert connection_module(client) in "ok"
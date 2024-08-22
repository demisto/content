from bs4 import BeautifulSoup
import bs4
import pytest
import CiscoWebExFeed
import json
from CommonServerPython import *  # noqa: F401


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def MockedClient(Client):
    client = Client(base_url='test')
    return client


__BASE_URL = "https://help.webex.com/en-us/WBX264/How-Do-I-Allow-Webex-Meetings-Traffic-on-My-Network"
DOMAIN_TABLE = [['Client Type', 'Domain(s)'],
                ['domain1', '*.d1.com\t\t\t*.d5.com'],
                ['domain2', '*.d2.com'],
                ['Long message without domain name']]

IP_LIST = [['1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)',
            '1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)', '1.2.3.4/5 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)']]

HTML_DOMAIN_SECTION = util_load_json('test_data/tests_data_1.json')


HTML_IP_SECTION = '''<div class="panel-collapse collapse" id="id_135011">
<div class="panel-body">
<div class="body refbody">
<ul><li></li><li></li><li>1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)</li><li></li><li></li></ul>
</div>
</div>
</div>'''


FETCH_INDICATORS_INPUT_1 = {'CIDR': ['ipmock'], 'DOMAIN': ['domainmock']}
FETCH_INDICATORS_OUTPUT_1 = [{'value': 'ipmock', 'type': 'Domain', 'fields': {'tags': ('very_good', 'very_bad'),
                                                                              'trafficlightprotocol': 'very_yellow'}},
                             {'value': 'domainmock', 'type': 'Domain', 'fields': {'tags': ('very_good', 'very_bad'),
                                                                                  'trafficlightprotocol': 'very_yellow'}}]

FETCH_INDICATORS_NO_ENRICH_OUTPUT_1 = [{'value': 'ipmock', 'type': 'Domain',
                                        'fields': {'tags': ('very_good', 'very_bad'),
                                                   'trafficlightprotocol': 'very_yellow'}, 'enrichmentExcluded': True},
                                       {'value': 'domainmock', 'type': 'Domain',
                                        'fields': {'tags': ('very_good', 'very_bad'),
                                                   'trafficlightprotocol': 'very_yellow'}, 'enrichmentExcluded': True}]

FETCH_INDICATORS_INPUT_2 = {'CIDR': ['ipmock1', 'ipmock2'], 'DOMAIN': ['domainmock1', 'domainmock2']}
FETCH_INDICATORS_OUTPUT_2 = [{'value': 'ipmock1', 'type': 'Domain', 'fields': {'tags': ('very_good', 'very_bad'),
                                                                               'trafficlightprotocol': 'very_yellow'}},
                             {'value': 'ipmock2', 'type': 'Domain', 'fields': {'tags': ('very_good', 'very_bad'),
                                                                               'trafficlightprotocol': 'very_yellow'}},
                             {'value': 'domainmock1', 'type': 'Domain', 'fields': {'tags': ('very_good', 'very_bad'),
                                                                                   'trafficlightprotocol': 'very_yellow'}},
                             {'value': 'domainmock2', 'type': 'Domain', 'fields': {'tags': ('very_good', 'very_bad'),
                                                                                   'trafficlightprotocol': 'very_yellow'}}]


def test_grab_domains():
    """
    Given:
        - Raw list of tuples that contains domain name and domain url, returned by api call:
        first array is the title, 2 seconds arrays are data, last array is message.
    When:
        - Filtered list contains domain's urls only
    Then:
        - Return domains list without errors
    """
    from CiscoWebExFeed import grab_domains
    expected_result = ['*.d1.com', '*.d2.com', '*.d5.com']
    assert sorted(grab_domains(DOMAIN_TABLE)) == expected_result


def test_grab_CIDR_ips():
    """
    Given:
        - Raw list that contains ips CIDR and NET RANGE, returned by api call:
    When:
        - Calling grab_CIDR_ips
    Then:
        - Return CIDR ips list without without duplicates
    """
    from CiscoWebExFeed import grab_CIDR_ips
    expected_result = ['1.1.1.1/1', '1.2.3.4/5']
    assert sorted(grab_CIDR_ips(IP_LIST)) == expected_result


def test_grab_domain_table():
    """
    Given: a beautiful soup object that is similar to the domain table

    When:
        - grab_domain_table(soup)
    Then:
        - the function should return a list of lists that contains the domain table
    """
    from CiscoWebExFeed import grab_domain_table
    soup = BeautifulSoup(HTML_DOMAIN_SECTION, "html.parser")
    expected_result = util_load_json('test_data/tests_data_2.json')
    assert grab_domain_table(soup) == expected_result


def test_grab_ip_table():
    """
    Given: a soup object that is similar to the ip table

    When:
        - grab_ip_table(soup)
    Then:
        - the function should return a list of lists that contains the ips from the table
    """
    from CiscoWebExFeed import grab_ip_table
    soup = BeautifulSoup(HTML_IP_SECTION, "html.parser")
    expected_result = [['1.1.1.1/1 (CIDR) or 8.8.8.8 - 8.8.8.8 (net range)']]
    assert grab_ip_table(soup) == expected_result


@pytest.mark.parametrize('input, expected', [
    ('1.1.1.1/16', 'CIDR'),
    ('*.example.com', 'DomainGlob'),
    ('example.com', 'Domain')])
def test_check_indicator_type__diffrent_inputs(input, expected):
    """
    Given: A indicator of type: ip, domain or domain glob

    When:
        - check_indicator_type is called
    Then:
        - the function should return the correct indicator type
    """
    from CiscoWebExFeed import check_indicator_type
    assert check_indicator_type(input) == expected


@pytest.mark.parametrize('input, limit, expected', [
    ('Both', 1,
     '### Indicators from Webex:\n|value|type|\n|---|---|\n| ipmock1 | mocked_type |\n| domainmock1 | mocked_type |\n'),
    ('CIDR', 2,
     '### Indicators from Webex:\n|value|type|\n|---|---|\n| ipmock1 | mocked_type |\n| ipmock2 | mocked_type |\n'),
    ('DOMAIN', 5,
     '### Indicators from Webex:\n|value|type|\n|---|---|\n| domainmock1 | mocked_type |\n| domainmock2 | mocked_type |\n')])
def test_get_indicators_command__diffrent_indicator_type_and_limit_as_input(mocker, input, expected, limit):
    """
    Given:
        - a limit and an indicator type
    When:
        - get_indicators_command is called
    Then:
        - the function should return the expectetd result with the correct limit and indicator type
    """
    from CiscoWebExFeed import get_indicators_command, Client
    client = MockedClient(Client)
    mocker.patch.object(Client, 'all_raw_data', return_value='gg')
    mocker.patch.object(CiscoWebExFeed, 'check_indicator_type', return_value='mocked_type')
    mocker.patch.object(CiscoWebExFeed, 'parse_indicators_from_response',
                        return_value={'CIDR': ['ipmock1', 'ipmock2'], 'DOMAIN': ['domainmock1', 'domainmock2']})

    res = get_indicators_command(client=client, limit=limit, indicator_type=input)
    assert res.readable_output == expected


def test_get_indicators_command__wrong_indicator_type(mocker):
    """
    Given:
        - illegal indicator type as input
    When:
        - get_indicators_command is called
    Then:
        - the function should return the expectetd error message
    """
    from CiscoWebExFeed import get_indicators_command, Client
    client = MockedClient(Client)
    mocker.patch.object(Client, 'all_raw_data', return_value='gg')
    mocker.patch.object(CiscoWebExFeed, 'check_indicator_type')
    mocker.patch.object(CiscoWebExFeed, 'parse_indicators_from_response',
                        return_value={'CIDR': ['ipmock1', 'ipmock2'], 'DOMAIN': ['domainmock1', 'domainmock2']})
    with pytest.raises(DemistoException) as e:
        get_indicators_command(client=client, indicator_type="mock_type")
    assert e.value.message == 'The indicator_type argument must be one of the following: Both, CIDR, DOMAIN'


@pytest.mark.parametrize('input, expected', [(FETCH_INDICATORS_INPUT_1, FETCH_INDICATORS_OUTPUT_1),
                                             (FETCH_INDICATORS_INPUT_2, FETCH_INDICATORS_OUTPUT_2)])
def test_fetch_indicators_command__different_sizes_of_inputs(mocker, input, expected):
    """
    Given:
        -  tags and tlp_color
    When:
        - the fetch_indicators_command is called and uses the output of parse_indicators_from_response as input
    Then:
        - the function should return the expectetd result with the correct tags and tlp_color
    """
    from CiscoWebExFeed import fetch_indicators_command, Client
    client = MockedClient(Client)
    mocker.patch.object(Client, 'all_raw_data', return_value='gg')
    mocker.patch.object(CiscoWebExFeed, 'parse_indicators_from_response',
                        return_value=input)
    expected_result = expected
    assert fetch_indicators_command(client=client, tags=("very_good", "very_bad"), tlp_color="very_yellow") == expected_result


def test_fetch_indicators_command__exclude_enrichment(mocker):
    """
    Given:
        - Exclude enrichment parameter is used
    When:
        - Calling the fetch_indicators_command
    Then:
        - The indicators should include the enrichmentExcluded field if exclude is True.
    """
    from CiscoWebExFeed import fetch_indicators_command, Client

    input = FETCH_INDICATORS_INPUT_1
    expected_result = FETCH_INDICATORS_NO_ENRICH_OUTPUT_1

    client = MockedClient(Client)
    mocker.patch.object(Client, 'all_raw_data', return_value='gg')
    mocker.patch.object(CiscoWebExFeed, 'parse_indicators_from_response',
                        return_value=input)

    assert fetch_indicators_command(client=client,
                                    tags=("very_good", "very_bad"),
                                    tlp_color="very_yellow",
                                    enrichment_excluded=True) == expected_result


def test_parse_indicators_from_response__fail_to_parse(mocker, requests_mock):
    """
    Given:
        - a response from the website that is not in the expected format
    When:
        - parse_indicators_from_response is called
    Then:
        - the function should return the expected error message
    """
    from CiscoWebExFeed import parse_indicators_from_response

    mocker.patch.object(bs4, ('BeautifulSoup'))
    mocker.patch.object(CiscoWebExFeed, 'grab_domain_table')
    mocker.patch.object(CiscoWebExFeed, 'grab_ip_table')
    mocker.patch.object(CiscoWebExFeed, 'grab_CIDR_ips')
    mocker.patch.object(CiscoWebExFeed, 'grab_domains', side_effect=DemistoException('No domains to grab'))
    mocked_response = requests_mock.get({__BASE_URL}, json={'name': 'awesome-mock'})
    mocked_response.text = 'mocked text'
    with pytest.raises(DemistoException) as e:
        parse_indicators_from_response(mocked_response)
    assert e.value.message == 'Failed to parse the response from the website. Error: No domains to grab'


@pytest.mark.parametrize('CIDR_results, domain_results', [("domainmock", None),
                                                          (None, "domainmock")])
def test_parse_indicators_from_response__ip_or_domain_indicators_are_None(mocker, requests_mock, CIDR_results, domain_results):
    """
    Given:
        - a response from the website, (CIDR or domains) with the value None
    When:
        - parse_indicators_from_response is called
    Then:
        - the function should return the expected error message
    """
    from CiscoWebExFeed import parse_indicators_from_response

    mocker.patch.object(bs4, ('BeautifulSoup'))
    mocker.patch.object(CiscoWebExFeed, 'grab_domain_table')
    mocker.patch.object(CiscoWebExFeed, 'grab_ip_table')
    mocker.patch.object(CiscoWebExFeed, 'grab_CIDR_ips', return_value=CIDR_results)
    mocker.patch.object(CiscoWebExFeed, 'grab_domains', return_value=domain_results)
    mocked_response = requests_mock.get({__BASE_URL}, json={'name': 'awesome-mock'})
    mocked_response.text = 'mocked text'
    with pytest.raises(DemistoException) as e:
        parse_indicators_from_response(mocked_response)
    assert e.value.message == 'Did not find the expected indicators in the response from the website'

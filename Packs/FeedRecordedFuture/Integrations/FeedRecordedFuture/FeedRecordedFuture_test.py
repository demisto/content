import collections
import os

import pytest
from collections import OrderedDict
from FeedRecordedFuture import get_indicator_type, get_indicators_command, Client, fetch_indicators_command
from csv import DictReader
from CommonServerPython import argToList

GET_INDICATOR_TYPE_INPUTS = [
    ('ip', OrderedDict([('Name', '192.168.1.1'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'IP'),
    ('ip', OrderedDict([('Name', '192.168.1.1/32'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'CIDR'),
    ('ip', OrderedDict([('Name', '2001:db8:a0b:12f0::1'), ('Risk', '89'), ('RiskString', '5/12'),
                        ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'IPv6'),
    ('hash', OrderedDict([('Name', '52483514f07eb14570142f6927b77deb7b4da99f'), ('Algorithm', 'SHA-1'), ('Risk', '89'),
                          ('RiskString', '5/12'), ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File'),
    ('hash', OrderedDict([('Name', '42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59'),
                          ('Algorithm', 'SHA-256'), ('Risk', '89'), ('RiskString', '5/12'),
                          ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File'),
    ('hash', OrderedDict([('Name', 'c8092abd8d581750c0530fa1fc8d8318'), ('Algorithm', 'MD5'), ('Risk', '89'),
                          ('RiskString', '5/12'), ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'File'),
    ('domain', OrderedDict([('Name', 'domaintools.com'), ('Risk', '89'), ('RiskString', '5/12'),
                            ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'Domain'),
    ('domain', OrderedDict([('Name', '*domaintools.com'), ('Risk', '89'), ('RiskString', '5/12'),
                            ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'DomainGlob'),
    ('url', OrderedDict([('Name', 'www.securityadvisor.io'), ('Risk', '89'), ('RiskString', '5/12'),
                         ('EvidenceDetails', '{"EvidenceDetails": []}')]), 'URL')
]


@pytest.mark.parametrize('indicator_type, csv_item, answer', GET_INDICATOR_TYPE_INPUTS)
def test_get_indicator_type(indicator_type, csv_item, answer):
    returned_indicator_type = get_indicator_type(indicator_type, csv_item)
    assert returned_indicator_type == answer


build_iterator_answer_domain = [
    [{
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': 'domaintools.com',
        'Risk': '97',
        'RiskString': '4/37'
    }]
]

build_iterator_answer_domain_glob = [
    [{
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': '*domaintools.com',
        'Risk': '92',
        'RiskString': '4/37'
    }]
]

build_iterator_answer_ip = [
    [{
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': '192.168.1.1',
        'Risk': '50',
        'RiskString': '4/37'
    }]
]

build_iterator_answer_hash = [
    [{
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': '52483514f07eb14570142f6927b77deb7b4da99f',
        'Algorithm': 'SHA-1',
        'Risk': '0',
        'RiskString': '4/37'
    }]
]

build_iterator_answer_url = [
    [{
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': 'www.securityadvisor.io',
        'Risk': '97',
        'RiskString': '4/37'
    }]
]

build_iterator_no_evidence_details_value = [
    [{
        'EvidenceDetails': None,
        'Name': '192.168.1.1',
        'Risk': '50',
        'RiskString': '4/37'
    }]
]

build_iterator_answer_vulnerability = [
    [{
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': 'CVE-2014-1111',
        'Risk': '90',
        'RiskString': '4/37'
    }]
]

GET_INDICATOR_INPUTS = [
    ('ip', build_iterator_answer_ip, '192.168.1.1', 'IP'),
    ('domain', build_iterator_answer_domain, 'domaintools.com', 'Domain'),
    ('domain', build_iterator_answer_domain_glob, '*domaintools.com', 'DomainGlob'),
    ('hash', build_iterator_answer_hash, '52483514f07eb14570142f6927b77deb7b4da99f', 'File'),
    ('url', build_iterator_answer_url, 'www.securityadvisor.io', 'URL'),
    ('vulnerability', build_iterator_answer_vulnerability, 'CVE-2014-1111', 'CVE'),
]


@pytest.mark.parametrize('indicator_type, build_iterator_answer, value, type', GET_INDICATOR_INPUTS)
def test_get_indicators_command(mocker, indicator_type, build_iterator_answer, value, type):
    client = Client(indicator_type=indicator_type, api_token='123', services='fusion')
    args = {
        'indicator_type': indicator_type,
        'limit': 1
    }
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    mocker.patch('FeedRecordedFuture.Client.get_batches_from_file', return_value=build_iterator_answer)
    hr, _, entry_result = get_indicators_command(client, args)
    assert entry_result[0]['Value'] == value
    assert entry_result[0]['Type'] == type


GET_INDICATORS_BY_RISK_RULES_INPUTS = [
    ('url', 'dhsAis', build_iterator_answer_url, 'www.securityadvisor.io', 'URL'),
    ('url', 'dhsAis,phishingUrl', build_iterator_answer_url, 'www.securityadvisor.io', 'URL'),
    ('ip', 'dhsAis,phishingUrl,defangedURL', build_iterator_answer_ip, '192.168.1.1', 'IP')
]


@pytest.mark.parametrize('indicator_type, risk_rules, build_iterator_answer, value, type',
                         GET_INDICATORS_BY_RISK_RULES_INPUTS)
def test_get_indicators_command_by_risk_rules(mocker, indicator_type, risk_rules, build_iterator_answer, value, type):
    """
    Given:
     - Recorded Future Feed client initialized with a 'ConnectApi' service, and a:
      1. URL indicator type, and a valid risk rule.
      2. URL indicator type, and a comma separated list of two valid risk rules.
      3. IP indicator type, and a comma separated list of three valid risk rules.

     - Mock response of the fetched indicators

    When:
     - Running the 'get_indicators_command'

    Then:
     - Verify the raw response and the human readable output of the command are correct, and include fetched indicators
      of all the defined risk rules.
    """
    client = Client(indicator_type=indicator_type, api_token='123', risk_rule=risk_rules, services=['ConnectApi'])
    args = {
        'indicator_type': indicator_type,
        'limit': 1
    }
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    mocker.patch('FeedRecordedFuture.Client.get_batches_from_file', return_value=build_iterator_answer)
    hr, _, entry_results = get_indicators_command(client, args)

    risk_rules_list = argToList(risk_rules)
    for rule in risk_rules_list:
        assert f'Indicators from RecordedFuture Feed for {rule} risk rule' in hr, \
            f"human readable output doesn't contain indicators from risk rule {rule}"
        for entry in entry_results:
            assert entry.get('Value', '') == value
            assert entry.get('Type', '') == type


CALCULATE_DBOT_SCORE_INPUTS = [
    ('97', '65', 3),
    ('90', '91', 3),
    ('50', '65', 2),
    ('0', '65', 0),
    ('0', '0', 3),
]


@pytest.mark.parametrize('risk_from_feed, threshold, expected_score', CALCULATE_DBOT_SCORE_INPUTS)
def test_calculate_dbot_score(risk_from_feed, threshold, expected_score):
    client = Client(indicator_type='ip', api_token='123', services=['fusion'], threshold=threshold)
    score = client.calculate_indicator_score(risk_from_feed)
    assert score == expected_score


def test_fetch_indicators_command(mocker):
    """
    Given:
     - Recorded Future Feed client initialized with ip indicator type
     - Iterator which returns entry of IP object with name only

    When:
     - Fetching indicators

    Then:
     - Verify the fetch runs successfully.
    """
    indicator_type = 'ip'
    client = Client(indicator_type=indicator_type, api_token='dummytoken', services=['fusion'])
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    mocker.patch(
        'FeedRecordedFuture.Client.get_batches_from_file',
        return_value=DictReaderGenerator(DictReader(open('test_data/response.txt')))
    )
    client_outputs = []
    for output in fetch_indicators_command(client, indicator_type):
        client_outputs.extend(output)
    assert {'fields': {'recordedfutureevidencedetails': [], 'tags': []},
            'rawJSON': {'Name': '192.168.0.1',
                        'a': '3',
                        'type': 'IP',
                        'value': '192.168.0.1'},
            'score': 0,
            'type': 'IP',
            'value': '192.168.0.1'} == client_outputs[0]
    assert len(client_outputs) == 1


def test_fetch_indicators_risk_threshold_command(mocker):
    """
    Given:
     - Recorded Future Feed client initialized with ip indicator type
     - Iterator which returns entry of IP object with name and risk score

    When:
     - Fetching indicators with risk score threshold equal to 40

    Then:
     - Verify the fetch does not returns indicators with lower score than the threshold.
    """
    indicator_type = 'ip'
    client = Client(indicator_type=indicator_type, api_token='dummytoken', services=['fusion'], risk_score_threshold=40)
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    mocker.patch(
        'FeedRecordedFuture.Client.get_batches_from_file',
        return_value=DictReaderGenerator(DictReader(open('test_data/response_risk_score.txt')))
    )
    client_outputs = []
    for output in fetch_indicators_command(client, indicator_type):
        client_outputs.extend(output)
    assert {'fields': {'recordedfutureevidencedetails': [], 'tags': []},
            'rawJSON': {'Criticality Label': 'Malicious',
                        'Name': '192.168.0.1',
                        'Risk': '80',
                        'score': 3,
                        'type': 'IP',
                        'value': '192.168.0.1'},
            'score': 3,
            'type': 'IP',
            'value': '192.168.0.1'} == client_outputs[0]

    assert len(client_outputs) == 1


@pytest.mark.parametrize('tags', (['tag1', 'tag2'], []))
def test_feed_tags(mocker, tags):
    """
    Given:
    - tags parameters
    When:
    - Executing any command on feed
    Then:
    - Validate the tags supplied exists in the indicators
    """
    client = Client(indicator_type='ip', api_token='dummytoken', services=['fusion'], tags=tags)
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    mocker.patch('FeedRecordedFuture.Client.get_batches_from_file', return_value=[[{'Name': '192.168.1.1'}]])
    indicators = next(fetch_indicators_command(client, 'ip'))
    assert tags == indicators[0]['fields']['tags']


class DictReaderGenerator:
    def __init__(self, dict_reader):
        self.dict_reader = dict_reader
        self.has_returned_dict_reader = False

    def __iter__(self):
        return self

    def __next__(self):
        if self.has_returned_dict_reader:
            raise StopIteration()
        self.has_returned_dict_reader = True
        return self.dict_reader


@pytest.mark.parametrize('indicator_type, risk_rules, service, expected_err_msg',
                         [('url', 'dhsAis', 'fusion',
                           "You entered a risk rule but the 'connectApi' service is not chosen."),
                          ('url', 'dhsAi', 'connectApi', "The given risk rule: dhsAi does not exist"),
                          ('url', 'dhsAis,phishinUrl', 'connectApi', "The given risk rule: phishinUrl does not exist")
                          ])
def test_risk_rule_validations(mocker, indicator_type, risk_rules, service, expected_err_msg):
    """
    Given:
     - Recorded Future Feed client initialized with URL indicator type and:
      1. 'fusion' service, and a valid risk rule.
      2. 'connectApi' service, and an invalid risk rule.
      3. 'connectApi' service, and a comma separated list of a valid risk rule (the first) and an invalid risk rule
        (the second).

     - Mock response of the 'FeedRecordedFuture.return_error function', and the
      'FeedRecordedFuture.Client.get_risk_rules' command.

    When:
     - Running the 'Client.run_parameters_validations'.

    Then:
     - Verify the right error message appears for each case:
     1. Error message for setting 'connectApi' service.
     2. Error message for invalid risk rule.
     3. Error message for invalid risk rule on the second risk rule in the risk rules list.
    """
    mocker.patch('FeedRecordedFuture.Client.get_risk_rules',
                 return_value={'data': {'results': [{'name': 'dhsAis'}, {'name': 'phishingUrl'}]}})

    client = Client(indicator_type=indicator_type, api_token='123', risk_rule=risk_rules, services=[service])

    return_error_result = mocker.patch('FeedRecordedFuture.return_error')
    Client.run_parameters_validations(client)
    assert expected_err_msg in return_error_result.call_args[0][0]


def test_duplicated_indicators_in_different_batches(mocker):
    """
    Given:
    - Recorded Future Feed client initialized with URL indicator type and a file named response.txt which is created
      during the run of the test in order to simulate the response of the Client.build_iterator function.
      The response file includes 4 urls:
      1. http://www.google.com
      2. http://michosalementres.test.zapto.org/vg
      3. http://michosalementres.test.zapto.org/VG
      4. http://michosalementres.test.zapto.org/vg
      Two of the urls (2,4) are equal and the third url (3) is almost equal (the only difference is 'VG' suffix instead
      of 'vg' - case sensitive difference).

    When:
    - Running fetch_indicators_command with limit=1 (what determined that indicators 1+2 will composed a batch and
      indicators 3+4 will composed a different batch. The duplicated indicator appears in two different batches).

    Then:
    - Verify that the fetched output includes only 3 indicators (1, 2 and 3) what means that the duplicated indicator
      was skipped and wasn't send to server again.
    - Verify that the duplicated url appears in the fetch function's output only once.
    - Verify that the third indicator (with the 'VG' suffix) considered as a new indicator from content side -
      i.e url indicators are case sensitive.
    """
    indicator_type = 'url'
    response_content = 'Name,Risk,RiskString,EvidenceDetails\n' \
                       'http://www.google.com,72,4/24,{"EvidenceDetails": []}\n' \
                       'http://michosalementres.test.zapto.org/vg,72,4/24,{"EvidenceDetails": [{"Rule": "test"}]}\n' \
                       'http://michosalementres.test.zapto.org/VG,72,4/24,{"EvidenceDetails": [{"Rule": "test1"}]}\n' \
                       'http://michosalementres.test.zapto.org/vg,72,4/24,{"EvidenceDetails": [{"Rule": "test"}]}\n'

    with open('response.txt', 'w') as f:
        f.write(response_content)
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    client = Client(indicator_type=indicator_type, api_token='123', services=['fusion'])

    client_outputs = []
    indicators_values = []
    for output in fetch_indicators_command(client, indicator_type, limit=1):
        client_outputs.extend(output)
        for indicator in output:
            indicators_values.append(indicator.get('value'))

    if os.path.exists('response.txt'):
        os.remove('response.txt')

    assert len(client_outputs) == 3
    indicators_occurrences = collections.Counter(indicators_values)
    assert indicators_occurrences.get('http://michosalementres.test.zapto.org/vg') == 1
    assert indicators_occurrences.get('http://michosalementres.test.zapto.org/VG') == 1


def test_duplicated_indicator_in_the_same_batch(mocker):
    """
    Given:
    - Recorded Future Feed client initialized with URL indicator type and a mock response of
      Client.get_batches_from_file which includes 3 URL indicators in one batch.
      Two of the urls are equal and the third is almost equal (the only difference is 'ORG' suffix instead of 'org')

    When:
    - Fetching indicators

    Then:
    - Verify that the fetch output includes only 2 indicators - what means that the duplicated indicator
      was skipped and wasn't send to server again, and that the third indicator considered as a new indicator from
      content side - i.e url indicators are case sensitive.
    """
    indicator_type = 'url'
    mocker.patch('FeedRecordedFuture.Client.build_iterator')
    mocker.patch(
        'FeedRecordedFuture.Client.get_batches_from_file',
        return_value=DictReaderGenerator(DictReader(open('test_data/response_for_duplicate_indicator_test.txt')))
    )
    client = Client(indicator_type=indicator_type, api_token='123', services=['fusion'])

    client_outputs = []
    indicators_values = []
    for output in fetch_indicators_command(client, indicator_type):
        client_outputs.extend(output)
        for indicator in output:
            indicators_values.append(indicator.get('value'))

    assert len(client_outputs) == 2
    indicators_occurrences = collections.Counter(indicators_values)
    assert indicators_occurrences.get('http://www.test.duckdns.org/') == 1
    assert indicators_occurrences.get('http://www.test.duckdns.ORG/') == 1

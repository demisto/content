import collections
import os
from pytest_mock import MockerFixture
import pytest
from collections import OrderedDict
from FeedRecordedFuture import get_indicator_type, get_indicators_command, Client, fetch_indicators_command, requests
from csv import DictReader
from CommonServerPython import argToList


class TestStreamCompressedData:

    @pytest.fixture()
    def mock_response(self) -> requests.Response:
        """This is a fixture used to mock the response object when streaming compressed data.

        Returns:
            requests.Response: The response object that will mock the streaming of compressed data.
        """
        import io
        gzip_compressed_data = b''
        # The file below should be a gzip compressed file. The content of the compressed file was obtained by running:
        # gzip -k test_data/test_gzip_compressed.txt (The -k flag tells gzip to keep the original file)
        with open('test_data/test_gzip_compressed.txt.gz', 'rb') as test_compressed_stream:
            gzip_compressed_data = test_compressed_stream.read()
        response_mocker = requests.Response()
        response_mocker.raw = io.BytesIO(gzip_compressed_data)
        response_mocker.encoding = 'utf-8'
        return response_mocker

    def test_stream_compressed_data_iterations(self, mocker: MockerFixture, mock_response: requests.Response):
        """
        Given:
        - A response that will stream the compressed data.

        When:
        - Fetching indicators using the connectApi service

        Then:
        - Verify that the decoding mechanism is able to handle when we try to decode part of a character.
        """
        client = Client(indicator_type='url', api_token='123', services=['connectApi'])
        decoding_mocker = mocker.patch.object(client, 'decode_bytes', side_effect=client.decode_bytes)
        client.stream_compressed_data(response=mock_response, chunk_size=3)
        os.remove("response.txt")
        # The first 12 bytes in our case are for the gzip compressing method, not relevant
        call_args_list = decoding_mocker.call_args_list[12:]
        # The first character uses 4 bytes, and our chunk size is 3, therefore, we will first try to decode the first 3 bytes
        assert call_args_list[0][0][0] == b'\xf0\x9f\x98'
        # Since the first 3 bytes don't represent a valid character, we cut off one byte and decode again
        assert call_args_list[1][0][0] == b'\xf0\x9f'
        # We keep on cutting and decoding until we reach a valid character
        assert call_args_list[2][0][0] == b'\xf0'
        # We reached a valid character, therefore, decoding will pass
        assert call_args_list[3][0][0] == b''
        # We save the cut off bytes from the last chunk, and add it to the current chunk so we can decode
        assert call_args_list[4][0][0][0:3] == b'\xf0\x9f\x98'

    @pytest.mark.parametrize('chunk_size', [(1), (2), (3), (4), (8), (10), (25), (27)])
    def test_stream_compressed_data_file_content(self, chunk_size: int, mock_response: requests.Response):
        """
        Given:
        - A response that will stream the compressed data.
        - The chunk size of the streamed data.

        When:
        - Fetching indicators using the connectApi service

        Then:
        - Validate that the decoded chunks from the response make up the correct content.
        """
        client = Client(indicator_type='url', api_token='123', services=['connectApi'])
        client.stream_compressed_data(response=mock_response, chunk_size=chunk_size)
        file_stream = open("response.txt")
        file_content = file_stream.read()
        file_stream.close()
        os.remove("response.txt")
        # test_data/test_gzip_compressed.txt holds the decompressed data of test_data/test_gzip_compressed.txt.gz
        # We want to check if the code is able to decode the chunks correctly
        with open('test_data/test_gzip_compressed.txt') as file:
            assert file.read() == file_content


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
    ('ip', build_iterator_no_evidence_details_value, '192.168.1.1', 'IP'),
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
    ('90', '65', '25', 3),
    ('45', '65', '25', 2),
    ('15', '65', '25', 0),
    ('0', '65', '25', 1),
    ('90', '95', '25', 2),
    ('45', '30', '25', 3),
    ('15', '26', '25', 0),
    ('0', '0', '-1', 3),
    ('90', '98', '91', 0),
    ('45', '65', '40', 2),
    ('15', '10', '5', 3),
    ('0', '65', '0', 2),
    ('65', '65', '25', 3),
    ('25', '65', '25', 2),
    ('50', '51', '50', 2),
]


@pytest.mark.parametrize('risk_from_feed, malicious_threshold, suspicious_threshold, expected_score', CALCULATE_DBOT_SCORE_INPUTS)
def test_calculate_dbot_score(risk_from_feed, malicious_threshold, suspicious_threshold, expected_score):
    """
    Given:
     - Values for calculating an indicator's verdict including:
        1. The Recorded Future Risk Score of the indicator (0 - 100)
        2. The minimum score to be malicious (0 - 100)
        3. The minimum score to be suspicious (-1 - 100, must be less than the malicious_threshold)
        4. What the expected D-Bot Score (verdict) is (0 - 3)
     - Individually adjust values 1, 2 & 3 to capture the cases
        - Score is greater than the malicious threshold
        - Score is between the malicious threshold and suspicious threshold
        - Score is less than the suspicious threshold
        - Score is 0
        - Score equals a threshold

    When:
     - Running the 'calculate_indicator_score'

    Then:
     - Verify the indicator's dbot score is set correctly given the suspicious and malicious risk score range.
    """
    client = Client(indicator_type='ip', api_token='123', services=[
                    'fusion'], malicious_threshold=malicious_threshold, suspicious_threshold=suspicious_threshold)
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
    assert {'fields': {'recordedfutureevidencedetails': [], 'recordedfutureriskscore': None, 'tags': []},
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
    assert {'fields': {'recordedfutureevidencedetails': [], 'recordedfutureriskscore': '80', 'tags': []},
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
            raise StopIteration
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


def test_client_init_with_null_values():
    """
    Given:
     - malicious_threshold, suspicious_threshold, and risk_score_threshold params all set to None

    When:
     - Initializing a client

    Then:
     - Verify that no errors were thrown (especially the part that check that malicious_threshold <= suspicious_threshold)
    """
    Client(indicator_type='ip', api_token='123', services=[
        'fusion'], malicious_threshold=None, suspicious_threshold=None)

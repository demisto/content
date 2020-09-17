import pytest
from collections import OrderedDict
from FeedRecordedFuture import get_indicator_type, get_indicators_command, Client, fetch_indicators_command

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
    {
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': 'domaintools.com',
        'Risk': '97',
        'RiskString': '4/37'
    }
]

build_iterator_answer_domain_glob = [
    {
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': '*domaintools.com',
        'Risk': '92',
        'RiskString': '4/37'
    }
]

build_iterator_answer_ip = [
    {
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': '192.168.1.1',
        'Risk': '50',
        'RiskString': '4/37'
    }
]

build_iterator_answer_hash = [
    {
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': '52483514f07eb14570142f6927b77deb7b4da99f',
        'Algorithm': 'SHA-1',
        'Risk': '0',
        'RiskString': '4/37'
    }
]

build_iterator_answer_url = [
    {
        'EvidenceDetails': '{"EvidenceDetails": []}',
        'Name': 'www.securityadvisor.io',
        'Risk': '97',
        'RiskString': '4/37'
    }
]

GET_INDICATOR_INPUTS = [
    ('ip', build_iterator_answer_ip, '192.168.1.1', 'IP'),
    ('domain', build_iterator_answer_domain, 'domaintools.com', 'Domain'),
    ('domain', build_iterator_answer_domain_glob, '*domaintools.com', 'DomainGlob'),
    ('hash', build_iterator_answer_hash, '52483514f07eb14570142f6927b77deb7b4da99f', 'File'),
    ('url', build_iterator_answer_url, 'www.securityadvisor.io', 'URL')
]


@pytest.mark.parametrize('indicator_type, build_iterator_answer, value, type', GET_INDICATOR_INPUTS)
def test_get_indicators_command(mocker, indicator_type, build_iterator_answer, value, type):
    client = Client(indicator_type=indicator_type, api_token='123', services='fusion')
    args = {
        'indicator_type': indicator_type,
        'limit': 1
    }
    mocker.patch('FeedRecordedFuture.Client.build_iterator', return_value=build_iterator_answer)
    hr, _, entry_result = get_indicators_command(client, args)
    assert entry_result[0]['Value'] == value
    assert entry_result[0]['Type'] == type


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
    client = Client(indicator_type=indicator_type, api_token='dummytoken', services='fusion')
    mocker.patch(
        'FeedRecordedFuture.Client.build_iterator',
        return_value=[{'Name': '192.168.1.1'}]
    )
    fetch_indicators_command(client, indicator_type)


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
    client = Client(indicator_type='ip', api_token='dummytoken', services='fusion', tags=tags)
    mocker.patch(
        'FeedRecordedFuture.Client.build_iterator',
        return_value=[{'Name': '192.168.1.1'}]
    )
    indicators = fetch_indicators_command(client, 'ip')
    assert tags == indicators[0]['fields']['tags']

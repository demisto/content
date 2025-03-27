import json
import pytest
from CommonServerPython import Common
from typing import *

params = {
    "api_url": "http://test.com/api/v1",
    "use_ssl": "True",
    "reliability": "C - Fairly reliable",
    "create_relationships": True,
    "max_num_of_relationships": 1
}


def util_load_json(path: str) -> Any:
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


url_command_test = [
    ('http://gfrewdfsersfsfersfgergre.com', 'no_results', []),
    ('www.test_url.com', 'ok', ['test_tag1', 'test_tag2']),
    ('www.test_url.com', 'ok', []),
    ('www.test_url.com', 'no_results', ['test_tag1', 'test_tag2']),
    ('www.test_url.com', 'no_results', []),
    ('www.testurl.com', 'invalid_url', ['test_tag1', 'test_tag2']),
]


@pytest.mark.parametrize('url_to_check, query_status,tags', url_command_test)
def test_url_command(requests_mock, url_to_check, query_status: str, tags: List[str]):
    """
        Given
        - A URL.

        When
        - Calling run_url_command() methood.

        Then
        - Validate that the Tags were created.
        - Validate that the URL and DBotScore entry context have the proper values.
        - Validate that the relationships were created.

    """
    from URLHaus import run_url_command

    mock_response = util_load_json('test_data/url_command.json')
    mock_response['query_status'] = query_status
    mock_response['tags'] = tags
    requests_mock.post('http://test.com/api/v1/url/',
                       json=mock_response)
    results = run_url_command(url_to_check, params)

    url_indicator = results.indicator
    if url_indicator:
        assert url_indicator.url == url_to_check
        if query_status == 'ok':
            assert all(elem in url_indicator.tags for elem in tags)
            assert url_indicator.relationships
        else:
            assert not url_indicator.tags
            assert not url_indicator.relationships


url_command_test_reliability_dbot_score = [
    ('online', (3, 'The URL is active (online) and currently serving a payload')),
    ('offline', (2, 'The URL is inadctive (offline) and serving no payload')),
    ('unknown', (0, 'The URL status could not be determined')),
]


@pytest.mark.parametrize('status,excepted_output', url_command_test_reliability_dbot_score)
def test_url_reliability_dbot_score(status: str, excepted_output: Tuple[int, str]):
    """

    Given:
        - A URL status.

    When:
        - Calling calculate_dbot_score() method.

    Then:
        - Make sure the DBot Score is calculated correctly.

    """
    from URLHaus import url_calculate_score

    output = url_calculate_score(status)
    for i in range(len(excepted_output)):
        assert output[i] == excepted_output[i]


url_command_test_create_payloads = [
    ({'payloads': [{'virustotal': {'percent': 1.23, 'link': 'test_link'},
                    'filename': 'test_file',
                    'file_type': 'test_type',
                    'response_md5': 'test_md5',
                    'response_sha256': 'test_sha256'}]},
     [{
         'Name': 'test_file',
         'Type': 'test_type',
         'MD5': 'test_md5',
         'SHA256': 'test_sha256',
         'VT': {
             'Result': 1.23,
             'Link': 'test_link'
         }
     }]), ({'payloads': []}, []),
    ({}, [])
]


@pytest.mark.parametrize('test_data,excepted_output', url_command_test_create_payloads)
def test_url_create_payloads(test_data: dict, excepted_output: List[dict]):
    """

    Given:
        - A URL information including payloads which contain files info.

    When:
        - Calling url_create_payloads() method.

    Then:
        - Make sure the payload lists is created correctly.

    """
    from URLHaus import url_create_payloads
    assert url_create_payloads(url_information=test_data) == excepted_output


url_command_test_create_blacklists = [
    ({'blacklists': {'test_name_0': 'test_status',
                     'test_name_1': 'test_status'}},
     [{'Name': 'test_name_0',
       'Status': 'test_status'},
      {'Name': 'test_name_1',
       'Status': 'test_status'}
      ]), ({'blacklists': {}}, []),
    ({}, [])
]


@pytest.mark.parametrize('test_data,excepted_output', url_command_test_create_blacklists)
def test_url_create_blacklists(test_data: dict, excepted_output: List[dict]):
    """

    Given:
        - A URL information including blacklists which contain name,status.

    When:
        - Calling url_create_blacklist() method.

    Then:
        - Make sure the blacklist is created correctly.

    """
    from URLHaus import url_create_blacklist
    assert url_create_blacklist(url_information=test_data) == excepted_output


url_command_test_create_relationships = [
    ('127.0.0.1', 'IP', True, 1),
    ('127.0.0.1', 'IP', False, 1),
    ('127.0.0.1', 'IP', True, 22),
    ('127.0.0.1', 'IP', False, 22),
    ('127.0.0.1', 'IP', True, 1000),
    ('127.0.0.1', 'IP', False, 1000),
    ('test_domain.com', 'Domain', True, 1),
    ('test_domain.com', 'Domain', False, 1),
    ('test_domain.com', 'Domain', True, 22),
    ('test_domain.com', 'Domain', False, 22),
    ('test_domain.com', 'Domain', True, 1000),
    ('test_domain.com', 'Domain', False, 1000),
]


@pytest.mark.parametrize('host,host_type,create_relationships,max_num_relationships',
                         url_command_test_create_relationships)
def test_url_command_create_relationships(host: str, host_type: str, create_relationships: bool,
                                          max_num_relationships: int):
    """

    Given:
        - A URL host, file list, Create relationship table(T/F), max number of relationships(Limited to 1000).

    When:
        - Calling url_create_relationships() method.

    Then:
        - Make sure the relationships list is created correctly.

    """
    from URLHaus import url_create_relationships

    files = [{
        'Name': f'test_file{i}',
        'Type': f'test_type{i}',
        'MD5': f'test_md5{i}',
        'SHA256': f'test_sha256{i}',
        'VT': {
            'Result': float(i),
            'Link': f'test_link{i}'
        }
    } for i in range(10000)]
    uri = 'test_uri'
    excepted_output = []
    if create_relationships:
        excepted_output = [{
            'Relationship': 'related-to' if host_type == 'IP' else 'hosted-on',
            'EntityA': uri,
            'EntityAType': 'URL',
            'EntityB': host,
            'EntityBType': host_type,
        }]
        excepted_output.extend([{
            'Relationship': 'related-to',
            'EntityA': uri,
            'EntityAType': 'URL',
            'EntityB': files[i].get('SHA256'),
            'EntityBType': 'File',
        } for i in range(max_num_relationships - 1)])
    results = url_create_relationships(uri, host, files, create_relationships, max_num_relationships)
    assert len(results) == len(excepted_output)
    for i in range(len(results)):
        assert results[i].to_context() == excepted_output[i]


domain_command_test = [
    ('ok', 'spammer_domain', 'spammer'),
    ('ok', 'phishing_domain', 'phishing'),
    ('ok', 'botnet_cc_domain', 'botnet_cc'),
    ('ok', 'abused_legit_spam', 'abused_legit_spam'),
    ('ok', 'abused_legit_malware', 'abused_legit_malware'),
    ('ok', 'abused_legit_phishing', 'abused_legit_phishing'),
    ('ok', 'not listed', ''),
    ('no_results', 'not listed', ''),
    ('invalid_host', 'spammer_domain', 'spammer')
]


@pytest.mark.parametrize('query_status,spamhaus_dbl,expected_tag', domain_command_test)
def test_domain_command(requests_mock, mocker, query_status: str, spamhaus_dbl: str, expected_tag: str):
    """
        Given
        - A Domain.

        When
        - Calling run_domain_command() method.

        Then
        - Validate that the Tags were created correctly.
        - Validate that the relationships were created correctly.

    """
    from URLHaus import run_domain_command

    domain_to_check = "test.com"
    mock_response = util_load_json('test_data/domain_command.json')
    mock_response['query_status'] = query_status
    mock_response['blacklists']['spamhaus_dbl'] = spamhaus_dbl
    requests_mock.post('http://test.com/api/v1/host/',
                       json=mock_response)
    results = run_domain_command(domain_to_check, params)

    Domain = results.indicator
    if Domain:
        assert Domain.domain == domain_to_check
        if expected_tag:
            assert Domain.tags[0] == expected_tag if query_status == 'ok' else not Domain.tags
        assert len(Domain.relationships) == 1 if query_status == 'ok' else not Domain.relationships


domain_command_test_reliability_dbot_score = [
    ({'spamhaus_dbl': 'spammer_domain', 'surbl': 'test'},
     (Common.DBotScore.BAD, 'The queried Domain is a known spammer domain')),
    ({'spamhaus_dbl': 'phishing_domain', 'surbl': 'test'},
     (Common.DBotScore.BAD, 'The queried Domain is a known phishing domain')),
    ({'spamhaus_dbl': 'botnet_cc_domain', 'surbl': 'test'},
     (Common.DBotScore.BAD, 'The queried Domain is a known botnet C&C domain')),
    ({'spamhaus_dbl': 'test', 'surbl': 'listed'},
     (Common.DBotScore.BAD, 'The queried Domain is listed on SURBL')),
    ({'spamhaus_dbl': 'not listed', 'surbl': 'test'},
     (Common.DBotScore.NONE, 'The queried Domain is not listed on Spamhaus DBL')),
    ({'spamhaus_dbl': 'test', 'surbl': 'not listed'},
     (Common.DBotScore.NONE, 'The queried Domain is not listed on SURBL')),
    ({'spamhaus_dbl': 'test', 'surbl': 'test'},
     (Common.DBotScore.GOOD, 'There is no information about Domain in the blacklist')),
    ({'spamhaus_dbl': 'botnet_cc_domain', 'surbl': 'not listed'},
     (Common.DBotScore.BAD, 'The queried Domain is a known botnet C&C domain')),
    ({'spamhaus_dbl': 'not listed', 'surbl': 'listed'},
     (Common.DBotScore.BAD, 'The queried Domain is listed on SURBL')),
    ({'surbl': 'not listed'},
     (Common.DBotScore.NONE, 'The queried Domain is not listed on SURBL')),
    ({'surbl': 'listed'},
     (Common.DBotScore.BAD, 'The queried Domain is listed on SURBL')),
    ({'spamhaus_dbl': 'spammer_domain'},
     (Common.DBotScore.BAD, 'The queried Domain is a known spammer domain')),
    ({'spamhaus_dbl': 'not listed'},
     (Common.DBotScore.NONE, 'The queried Domain is not listed on Spamhaus DBL')),
    ({},
     (Common.DBotScore.GOOD, 'There is no information about Domain in the blacklist')),
]


@pytest.mark.parametrize('blacklist,excepted_output', domain_command_test_reliability_dbot_score)
def test_domain_reliability_dbot_score(blacklist: dict, excepted_output: Tuple[int, str]):
    """

    Given:
        - A Domain blacklist from URLhaus database.

    When:
        - Calling calculate_dbot_score() method.

    Then:
        - Make sure the DBot Score is calculated correctly.

    """
    from URLHaus import domain_calculate_score

    output = domain_calculate_score(blacklist)
    for i in range(len(excepted_output)):
        assert output[i] == excepted_output[i]


domain_command_test_create_relationships = [
    (True, 1),
    (False, 1),
    (True, 22),
    (False, 22),
    (True, 1000),
    (False, 1000),
    (True, 1),
    (False, 1),
    (True, 22),
    (False, 22),
    (True, 1000),
    (False, 1000),
]


@pytest.mark.parametrize('create_relationships,max_num_relationships',
                         domain_command_test_create_relationships)
def test_domain_command_test_create_relationships(create_relationships: bool, max_num_relationships: int):
    """

    Given:
        - A Domain, urls list, Create relationship table(T/F), max number of relationships(Limited to 1000).

    When:
        - Calling domain_create_relationships() method.

    Then:
        - Make sure the relationships list is created correctly.

    """
    from URLHaus import domain_create_relationships

    urls = [{
        'url': f'test_url{i}',
    } for i in range(10000)]  # Large amounts of urls
    domain = "test_domain"
    excepted_output = []
    if create_relationships:
        excepted_output.extend([{
            'Relationship': 'hosts',
            'EntityA': domain,
            'EntityAType': 'Domain',
            'EntityB': urls[i].get('url'),
            'EntityBType': 'URL',
        } for i in range(max_num_relationships)])
    results = domain_create_relationships(urls, domain, create_relationships, max_num_relationships)
    assert len(results) == len(excepted_output)
    for i in range(len(results)):
        assert results[i].to_context() == excepted_output[i]


domain_add_tags = [
    ('spammer_domain', ['spammer']),
    ('phishing_domain', ['phishing']),
    ('botnet_cc_domain', ['botnet_cc']),
    ('listed', []),
    ('not listed', []),
    ('', []),
    (None, []),
]


@pytest.mark.parametrize('blacklist_status,excepted_output',
                         domain_add_tags)
def test_domain_add_tags(blacklist_status: str, excepted_output: List[str]):
    """

    Given:
        - A Blacklist status, tags.

    When:
        - Calling domain_add_tags() method.

    Then:
        - Make sure tags are added correctly.

    """
    from URLHaus import domain_add_tags

    tags = []
    domain_add_tags(blacklist_status, tags)
    assert tags == excepted_output


file_command_test = [
    ('ok', 'test_ssdeep_1', 'test_ssdeep_1'),
    ('ok', 'test_ssdeep_2', 'test_ssdeep_2'),
    ('no_results', 'test_ssdeep_1', ''),
    ('invalid_md5', 'test_ssdeep_1', ''),
    ('invalid_sha256', 'test_ssdeep_1', '')
]


@pytest.mark.parametrize('query_status,ssdeep,expected_ssdeep', file_command_test)
def test_file_command(mocker, requests_mock, query_status: str, ssdeep: str, expected_ssdeep: str):
    """
        Given
        - A file.

        When
        - Calling file_command() method.

        Then
        - Validate that the Tags were created.
        - Validate that the relationships were created.

    """
    from URLHaus import run_file_command

    file_to_check = 'a' * 32
    mock_response = util_load_json('test_data/file_command.json')
    mock_response['query_status'] = query_status
    mock_response['ssdeep'] = ssdeep
    requests_mock.post('http://test.com/api/v1/payload/',
                       json=mock_response)
    results = run_file_command(file_to_check, params)

    File = '' if not results.outputs else results.outputs.get('File', '')
    if File:
        assert 'SHA256' in File
        if expected_ssdeep:
            assert File['SSDeep'] == expected_ssdeep if query_status == 'ok' else 'SSDeep' not in File
        assert len(File['Relationships']) == 1 if query_status == 'ok' else 'Relationships' not in File


def test_file_reliability_dbot_score():
    """

    Given:
        - A file.

    When:
        - calling calculate_dbot_score() method.

    Then:
        - Make sure the DBot Score is calculated correctly.
    """
    from URLHaus import file_calculate_score
    dbot_score = file_calculate_score()[0]
    assert dbot_score == Common.DBotScore.BAD


file_command_test_create_relationships = [
    (True, 1, 'test_signature'),
    (True, 22, 'test_signature'),
    (False, 22, 'test_signature'),
    (True, 1000, 'test_signature'),
    (False, 1000, 'test_signature'),
    (False, 22, ''),
    (True, 1000, ''),
    (False, 1000, ''),
]


@pytest.mark.parametrize('create_relationships,max_num_relationships,sig',
                         file_command_test_create_relationships)
def test_file_create_relationships(create_relationships: bool, max_num_relationships: int, sig: str):
    """

    Given:
        - Create relationship table(T/F), max number of relationships(Limited to 1000), file signature.

    When:
        - Calling file_create_relationships() method.

    Then:
        - Make sure the relationships list is created correctly.

    """
    from URLHaus import file_create_relationships
    urls = [{
        'url': f'test_url{i}',
    } for i in range(10000)]  # Large amounts of urls
    file = '123123123123123123123'
    excepted_output = []
    if create_relationships:
        if sig:
            excepted_output = [{
                'Relationship': 'indicator-of',
                'EntityA': file,
                'EntityAType': 'File',
                'EntityB': sig,
                'EntityBType': 'Malware',
            }]
        excepted_output.extend([{
            'Relationship': 'related-to',
            'EntityA': file,
            'EntityAType': 'File',
            'EntityB': urls[i].get('url'),
            'EntityBType': 'URL',
        } for i in range(max_num_relationships - len(excepted_output))])
    results = file_create_relationships(file=file, urls=urls, sig=sig, create_relationships=create_relationships,
                                        max_num_of_relationships=max_num_relationships)
    assert len(results) == len(excepted_output)
    for i in range(len(results)):
        assert results[i].to_context() == excepted_output[i]


def test_unsupported_file_return_error(mocker):
    from URLHaus import run_file_command
    params = {
        'should_error': True
    }
    hash = '11111111'
    mock_return_error = mocker.patch('URLHaus.return_error', side_effect=Exception())
    with pytest.raises(Exception):
        run_file_command(hash, params)
    mock_return_error.assert_called_once_with('Only accepting MD5 (32 bytes) or SHA256 (64 bytes) hash types')


def test_unsupported_file_return_warning(mocker):
    from URLHaus import run_file_command
    params = {
        'should_error': False
    }
    hash = '11111111'
    mock_return_warning = mocker.patch('URLHaus.return_warning', side_effect=Exception())
    with pytest.raises(Exception):
        run_file_command(hash, params)
    mock_return_warning.assert_called_once_with('Only accepting MD5 (32 bytes) or SHA256 (64 bytes) hash types', exit=True)

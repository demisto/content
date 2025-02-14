import json

import pytest
from GoogleThreatIntelligence import (
    ScoreCalculator,
    encode_url_to_base64,
    epoch_to_timestamp,
    get_working_id,
    raise_if_hash_not_valid,
    raise_if_ip_not_valid,
    create_relationships,
    get_whois
)

from CommonServerPython import argToList, DemistoException
import demistomock as demisto

INTEGRATION_NAME = 'GoogleThreatIntelligence'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


class TestScoreCalculator:
    """Tests the ScoreCalculator class"""
    score_calculator: ScoreCalculator

    @classmethod
    def setup_class(cls):
        cls.score_calculator = ScoreCalculator(
            {
                'preferredVendors': 'vt1, v2, vt3',
                'preferredVendorsThreshold': 2,
                'fileThreshold': 1,
                'ipThreshold': 1,
                'urlThreshold': 1,
                'domainThreshold': 1,
                'fileSuspiciousThreshold': 0,
                'ipSuspiciousThreshold': 0,
                'urlSuspiciousThreshold': 0,
                'domainSuspiciousThreshold': 0,
                'crowdsourced_yara_rules_enabled': True,
                'yaraRulesThreshold': 1,
                'SigmaIDSThreshold': 1,
                'domain_popularity_ranking': 1,
                'relationship_threshold': 1,
                'relationship_suspicious_threshold': 0,
                'gti_malicious': True,
                'gti_suspicious': True,
            }
        )

    def test_there_are_logs(self):
        with open('./test_data/file.json') as f:
            self.score_calculator.file_score('given hash', json.load(f))
        assert self.score_calculator.logs
        self.score_calculator.logs = []

    @pytest.mark.parametrize('malicious, suspicious, threshold, result', [
        (0, 5, 5, True),
        (10, 0, 5, True),
        (0, 0, 2, False)
    ])
    def test_is_suspicious_by_threshold(self, malicious: int, suspicious: int, threshold: int, result: bool):
        analysis_results = {
            'malicious': malicious,
            'suspicious': suspicious
        }
        assert self.score_calculator.is_suspicious_by_threshold(analysis_results, threshold) is result

    @pytest.mark.parametrize('malicious, threshold, result', [
        (5, 5, True),
        (10, 5, True),
        (0, 2, False)
    ])
    def test_is_malicious_by_threshold(self, malicious: int, threshold: int, result: bool):
        analysis_results = {
            'malicious': malicious
        }
        assert self.score_calculator.is_malicious_by_threshold(analysis_results, threshold) is result

    @pytest.mark.parametrize('ranks, result', [
        ({'vendor1': {'rank': 10000}}, False),
        ({'vendor1': {'rank': 3000}, 'vendor2': {'rank': 7000}}, True),
        ({'vendor1': {'rank': 0}}, True),
        ({'vendor1': {'rank': 300}, 'vendor2': {'rank': 300}}, True),
        ({}, None)
    ])
    def test_is_good_by_popularity_ranks(self, ranks: dict[str, dict], result: bool):
        self.score_calculator.domain_popularity_ranking = 5000
        assert self.score_calculator.is_good_by_popularity_ranks(ranks) is result

    @pytest.mark.parametrize('yara_rules_found, result', [
        (1, False),
        (3, True),
        (2, True)
    ])
    def test_is_suspicious_by_rules_yara(self, yara_rules_found: int, result: bool):
        # enable indicators process and set to 2
        self.score_calculator.crowdsourced_yara_rules_enabled = True
        self.score_calculator.crowdsourced_yara_rules_threshold = 2
        # process
        response = {'data': {
            'crowdsourced_yara_results': [1] * yara_rules_found
        }}
        assert self.score_calculator.is_suspicious_by_rules(response) is result

    @pytest.mark.parametrize('high, critical, result', [
        (2, 0, True),
        (0, 2, True),
        (1, 1, True),
        (0, 0, False),
    ])
    def test_is_suspicious_by_rules_sigma(self, high: int, critical: int, result: bool):
        # enable indicators process and set to 2
        self.score_calculator.crowdsourced_yara_rules_enabled = True
        self.score_calculator.sigma_ids_threshold = 2
        response = {'data': {'sigma_analysis_stats': {'high': high, 'critical': critical}}}
        # process
        assert self.score_calculator.is_suspicious_by_rules(response) is result

    @pytest.mark.parametrize('threshold', (1, 2))
    def test_is_preferred_vendors_pass_malicious(self, threshold: int):
        # setup
        self.score_calculator.trusted_vendors_threshold = threshold
        self.score_calculator.trusted_vendors = ['v1', 'v2']
        # process
        analysis_results = {'v1': {'category': 'malicious'}, 'v2': {'category': 'malicious'}}
        assert self.score_calculator.is_preferred_vendors_pass_malicious(analysis_results)

    def test_is_preferred_vendors_pass_malicious_below_threshold(self):
        # setup
        self.score_calculator.trusted_vendors_threshold = 3
        self.score_calculator.trusted_vendors = ['v1', 'v2']
        # process
        analysis_results = {'v1': {'category': 'malicious'}, 'v2': {'category': 'malicious'}}
        assert not self.score_calculator.is_preferred_vendors_pass_malicious(analysis_results)

    def test_is_malicious_by_gti(self):
        assert self.score_calculator.is_malicious_by_gti({'verdict': {'value': 'VERDICT_MALICIOUS'}}) is True
        assert self.score_calculator.is_malicious_by_gti({'verdict': {'value': 'VERDICT_SUSPICIOUS'}}) is False
        assert self.score_calculator.is_malicious_by_gti({}) is False
        self.score_calculator.gti_malicious = False
        assert self.score_calculator.is_malicious_by_gti({'verdict': {'value': 'VERDICT_MALICIOUS'}}) is False

    def test_is_suspicious_by_gti(self):
        assert self.score_calculator.is_suspicious_by_gti({'verdict': {'value': 'VERDICT_MALICIOUS'}}) is False
        assert self.score_calculator.is_suspicious_by_gti({'verdict': {'value': 'VERDICT_SUSPICIOUS'}}) is True
        assert self.score_calculator.is_suspicious_by_gti({}) is False
        self.score_calculator.gti_suspicious = False
        assert self.score_calculator.is_suspicious_by_gti({'verdict': {'value': 'VERDICT_SUSPICIOUS'}}) is False


class TestHelpers:
    def test_encode_url_to_base64(self):
        assert encode_url_to_base64('https://example.com') == 'aHR0cHM6Ly9leGFtcGxlLmNvbQ'

    def test_raise_if_hash_not_valid_valid_input(self):
        raise_if_hash_not_valid('7e641f6b9706d860baf09fe418b6cc87')

    def test_raise_if_hash_not_valid_invalid_input(self):
        with pytest.raises(ValueError, match='not of type'):
            raise_if_hash_not_valid('not a valid hash')

    def test_raise_if_ip_not_valid_valid_input(self):
        raise_if_ip_not_valid('8.8.8.8')

    def test_raise_if_ip_not_valid_invalid_input(self):
        with pytest.raises(ValueError, match='is not valid'):
            raise_if_ip_not_valid('not ip at all')

    @pytest.mark.parametrize('epoch_time, output', [
        (0, '1970-01-01 00:00:00Z'),
        (999113584, '2001-08-29 19:33:04Z'),
        ('a string', None)
    ])
    def test_epoch_to_timestamp(self, epoch_time: int, output: str):
        assert epoch_to_timestamp(epoch_time) == output

    def test_get_working_id(self):
        assert get_working_id('314huoh432ou', '') == '314huoh432ou'

    def test_get_working_id_no_entry(self):
        with pytest.raises(DemistoException):
            assert get_working_id('1451', '')


def test_create_relationships():
    """
    Given:
    - The IP response from the API.

    When:
    - create relationships function.

    Then:
    - Validate that the relationships were created as expected.
    """
    expected_name = ['communicates-with', 'communicates-with', 'related-to', 'related-to']
    with open('./test_data/relationships.json') as f:
        relationships = create_relationships(entity_a='Test', entity_a_type='IP', relationships_response=json.load(f),
                                             reliability='B - Usually reliable')
    relation_entry = [relation.to_entry() for relation in relationships]

    for relation, expected_relation_name in zip(relation_entry, expected_name):
        assert relation.get('name') == expected_relation_name
        assert relation.get('entityA') == 'Test'
        assert relation.get('entityBType') == 'File'


def test_get_whois_unexpected_value():
    """
    Given:
    - Whois string.

    When:
    - Whois string returned is a reserved Whois string returned by GoogleThreatIntelligence services.

    Then:
    - Validate empty dict is returned
    """
    assert get_whois('g. [Organization] Reserved Domain Name\nl. [Organization Type] Reserved Domain Name') == {}


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


DEFAULT_PARAMS = {
    'credentials': {'password': 'somepassword'},
    'domain_relationships': '* cname records',
    'ip_relationships': '* cname records',
    'url_relationships': '* cname records',
    'preferredVendors': 'vt1, v2, vt3',
    'preferredVendorsThreshold': 2,
    'fileThreshold': 1,
    'ipThreshold': 1,
    'urlThreshold': 1,
    'domainThreshold': 1,
    'fileSuspiciousThreshold': 0,
    'ipSuspiciousThreshold': 0,
    'urlSuspiciousThreshold': 0,
    'domainSuspiciousThreshold': 0,
    'crowdsourced_yara_rules_enabled': True,
    'yaraRulesThreshold': 1,
    'SigmaIDSThreshold': 1,
    'domain_popularity_ranking': 1,
    'relationship_threshold': 1,
    'relationship_suspicious_threshold': 0,
    'feedReliability': 'A - Completely reliable',
    'insecure': 'false',
    'proxy': 'false',
    'gti_malicious': True,
    'gti_suspicious': True,
}


def test_file_command(mocker, requests_mock):
    """
    Given:
    - A valid file hash

    When:
    - Running the !file command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import file_command, ScoreCalculator, Client
    import CommonServerPython

    file_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    file_relationships = (','.join(argToList(params.get('file_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    mock_response = util_load_json('test_data/file.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/files/{file_hash}?relationships={file_relationships}',
                      json=mock_response)

    for extended_data in [True, False]:
        file_hash = '0000000000000000000000000000000000000000000000000000000000000000'
        mocker.patch.object(demisto, 'args', return_value={'file': file_hash, 'extended_data': extended_data})

        if extended_data:
            expected_results = util_load_json('test_data/file_extended_results.json')
        else:
            expected_results = util_load_json('test_data/file_results.json')

        # Run command and collect result array
        results = file_command(
            client=client, score_calculator=mocked_score_calculator,
            args=demisto.args(), relationships=file_relationships)

        assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
        assert results[0].execution_metrics is None
        assert results[0].outputs == expected_results
        assert results[0].indicator.dbot_score.score == 3


def test_not_found_file_command(mocker, requests_mock):
    """
    Given:
    - A not found file hash

    When:
    - Running the !file command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import file_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    file_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    mocker.patch.object(demisto, 'args', return_value={'file': file_hash, 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    file_relationships = (','.join(argToList(params.get('file_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/files/{file_hash}?relationships={file_relationships}',
                      json=mock_response)

    results = file_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=file_relationships)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == f'File "{file_hash}" was not found in GoogleThreatIntelligence.'
    assert results[0].indicator.dbot_score.score == 0


def test_domain_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing domain (testing.com)

    When:
    - Running the !domain command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import domain_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'domain': 'testing.com', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    domain_relationships = (','.join(argToList(params.get('domain_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    # Load assertions and mocked request data
    mock_response = util_load_json('test_data/domain.json')
    expected_results = util_load_json('test_data/domain_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/domains/testing.com?relationships={domain_relationships}',
                      json=mock_response)

    # Run command and collect result array
    results = domain_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=domain_relationships)

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].outputs == expected_results
    assert results[0].indicator.dbot_score.score == 3


def test_not_found_domain_command(mocker, requests_mock):
    """
    Given:
    - A not found domain (testing.com)

    When:
    - Running the !domain command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import domain_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'domain': 'testing.com', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    domain_relationships = (','.join(argToList(params.get('domain_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/domains/testing.com?relationships={domain_relationships}',
                      json=mock_response)

    results = domain_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=domain_relationships)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == 'Domain "testing.com" was not found in GoogleThreatIntelligence.'
    assert results[0].indicator.dbot_score.score == 0


def test_ip_command(mocker, requests_mock):
    """
    Given:
    - A valid (and private) ip (192.168.0.1)

    When:
    - Running the !ip command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    # Load assertions and mocked request data
    mock_response = util_load_json('test_data/ip.json')
    expected_results = util_load_json('test_data/ip_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/ip_addresses/192.168.0.1?relationships={ip_relationships}',
                      json=mock_response)

    # Run command and collect result array
    results = ip_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=ip_relationships,
        disable_private_ip_lookup=False)

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].outputs == expected_results
    assert results[0].indicator.dbot_score.score == 3


def test_ip_command_private_ip_lookup(mocker):
    """
    Given:
    - A valid (and private) ip (192.168.0.1) and enabling private ip lookup

    When:
    - Running the !ip command

    Then:
    - Display "Reputation lookups disabled" message to user
    """
    from GoogleThreatIntelligence import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    # Run command but disabling private IP enrichment
    results = ip_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=ip_relationships,
        disable_private_ip_lookup=True)

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].readable_output == ('IP "192.168.0.1" was not enriched. '
                                          'Reputation lookups have been disabled for private IP addresses.')
    assert results[0].indicator.dbot_score.score == 0


def test_ip_command_override_private_lookup(mocker, requests_mock):
    """
    Given:
    - A valid (and private) ip (192.168.0.1) and enabling private ip lookup

    When:
    - Running the !ip command

    Then:
    - Display "Reputation lookups disabled" message to user
    """
    from GoogleThreatIntelligence import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false',
                                                       'override_private_lookup': 'true'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    # Load assertions and mocked request data
    mock_response = util_load_json('test_data/ip.json')
    expected_results = util_load_json('test_data/ip_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/ip_addresses/192.168.0.1?relationships={ip_relationships}',
                      json=mock_response)

    # Run command but enabling private IP enrichment after disabling it
    results = ip_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=ip_relationships,
        disable_private_ip_lookup=True)

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].outputs == expected_results
    assert results[0].indicator.dbot_score.score == 3


def test_not_found_ip_command(mocker, requests_mock):
    """
    Given:
    - A not found ip (192.168.0.1)

    When:
    - Running the !ip command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/ip_addresses/192.168.0.1?relationships={ip_relationships}',
                      json=mock_response)

    results = ip_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=ip_relationships,
        disable_private_ip_lookup=False)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == 'IP "192.168.0.1" was not found in GoogleThreatIntelligence.'
    assert results[0].indicator.dbot_score.score == 0


def test_url_command(mocker, requests_mock):
    """
    Given:
    - A valid testing url (https://vt_is_awesome.com/uts)

    When:
    - Running the !url command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import url_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'url': 'https://vt_is_awesome.com/uts', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    testing_url = 'https://vt_is_awesome.com/uts'
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    url_relationships = (','.join(argToList(params.get('url_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    # Load assertions and mocked request data
    mock_response = util_load_json('test_data/url.json')
    expected_results = util_load_json('test_data/url_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/urls/{encode_url_to_base64(testing_url)}'
                      f'?relationships={url_relationships}', json=mock_response)

    # Run command and collect result array
    results = url_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=url_relationships)

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].outputs == expected_results
    assert results[0].indicator.dbot_score.score == 3


def test_not_found_url_command(mocker, requests_mock):
    """
    Given:
    - A not found url (https://vt_is_awesome.com/uts)

    When:
    - Running the !url command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import url_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'url': 'https://vt_is_awesome.com/uts', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    testing_url = 'https://vt_is_awesome.com/uts'
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    url_relationships = (','.join(argToList(params.get('url_relationships')))).replace('* ', '').replace(' ', '_')
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/urls/{encode_url_to_base64(testing_url)}'
                      f'?relationships={url_relationships}', json=mock_response)

    results = url_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=url_relationships)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == f'URL "{testing_url}" was not found in GoogleThreatIntelligence.'
    assert results[0].indicator.dbot_score.score == 0


def test_private_file_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing private file

    When:
    - Running the !vt-privatescanning-file command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import private_file_command, Client
    import CommonServerPython
    # Setup Mocks
    sha256 = 'Example_sha256_with_64_characters_000000000000000000000000000000'
    mocker.patch.object(demisto, 'args', return_value={'file': sha256})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    client = Client(params=params)

    # Load assertions and mocked request data
    mock_response = util_load_json('test_data/private_file.json')
    expected_results = util_load_json('test_data/private_file_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/private/files/{sha256}',
                      json=mock_response)

    # Run command and collect result array
    results = private_file_command(client=client, args=demisto.args())

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].outputs == expected_results


def test_not_found_private_file_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing private file

    When:
    - Running the !vt-privatescanning-file command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import private_file_command, Client
    import CommonServerPython
    # Setup Mocks
    sha256 = 'Example_sha256_with_64_characters_000000000000000000000000000000'
    mocker.patch.object(demisto, 'args', return_value={'file': sha256})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/private/files/{sha256}',
                      json=mock_response)

    results = private_file_command(client=client, args=demisto.args())

    assert results[0].execution_metrics is None
    assert results[0].readable_output == f'File "{sha256}" was not found in GoogleThreatIntelligence.'
    assert results[0].indicator.dbot_score.score == 0


def test_private_url_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing private URL

    When:
    - Running the !gti-privatescanning-url command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import private_url_command, Client
    import CommonServerPython
    # Setup Mocks
    url = 'https://www.example.com'
    mocker.patch.object(demisto, 'args', return_value={'url': url})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    client = Client(params=params)

    # Load assertions and mocked request data
    mock_response = util_load_json('test_data/private_url.json')
    expected_results = util_load_json('test_data/private_url_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/private/urls/{encode_url_to_base64(url)}',
                      json=mock_response)

    # Run command and collect result array
    results = private_url_command(client=client, args=demisto.args())

    assert results[1].execution_metrics == [{'APICallsCount': 1, 'Type': 'Successful'}]
    assert results[0].execution_metrics is None
    assert results[0].outputs == expected_results


def test_not_found_private_url_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing private file

    When:
    - Running the !gti-privatescanning-url command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import private_url_command, Client
    import CommonServerPython
    # Setup Mocks
    url = 'https://www.example.com'
    mocker.patch.object(demisto, 'args', return_value={'url': url})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/private/urls/{encode_url_to_base64(url)}',
                      json=mock_response)

    results = private_url_command(client=client, args=demisto.args())

    assert results[0].execution_metrics is None
    assert results[0].readable_output == f'URL "{url}" was not found in GoogleThreatIntelligence.'
    assert results[0].indicator.dbot_score.score == 0


def test_not_found_file_sandbox_report_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing hash

    When:
    - Running the !vt-file-sandbox-report command

    Then:
    - Display "Not found" message to user
    """
    from GoogleThreatIntelligence import file_sandbox_report_command, Client
    import CommonServerPython
    # Setup Mocks
    sha256 = 'Example_sha256_with_64_characters_000000000000000000000000000000'
    mocker.patch.object(demisto, 'args', return_value={'file': sha256, 'limit': '10'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/files/{sha256}/behaviours',
                      json=mock_response)

    results = file_sandbox_report_command(client=client, args=demisto.args())

    assert results[0].execution_metrics is None
    assert results[0].readable_output == f'File "{sha256}" was not found in GoogleThreatIntelligence.'


def test_gti_assessment_command(mocker, requests_mock):
    """
    Given:
    - A valid or not found IoC

    When:
    - Running the !gti-assessment-get command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import get_assessment_command, encode_url_to_base64, ScoreCalculator, Client
    import CommonServerPython

    for resource, resource_type, endpoint in [
        ('0000000000000000000000000000000000000000000000000000000000000000', 'file', 'files'),
        ('8.8.8.8', 'ip', 'ip_addresses'),
        ('www.example.com', 'domain', 'domains'),
        ('https://www.example.com', 'url', 'urls'),
    ]:
        error_resource_type = resource_type.upper() if resource_type in ['url', 'ip'] else resource_type.capitalize()
        for mock_response, expected_results in [
            (
                util_load_json(f'test_data/{resource_type}.json'),
                util_load_json(f'test_data/{resource_type}_assessment_results.json')
            ),
            (
                {'error': {'code': 'NotFoundError'}},
                f'{error_resource_type} "{resource}" was not found in GoogleThreatIntelligence.'
            )
        ]:
            mocker.patch.object(demisto, 'args', return_value={'resource': resource, 'resource_type': resource_type})
            mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
            mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

            # Assign arguments
            params = demisto.params()
            mocked_score_calculator = ScoreCalculator(params=params)
            client = Client(params=params)

            # Load assertions and mocked request data
            endpoint_resource = encode_url_to_base64(resource) if resource_type == 'url' else resource
            requests_mock.get(f'https://www.virustotal.com/api/v3/{endpoint}/{endpoint_resource}?relationships=',
                              json=mock_response)

            # Run command and collect result array
            results = get_assessment_command(client=client, score_calculator=mocked_score_calculator, args=demisto.args())

            assert results.execution_metrics is None
            if 'error' in mock_response:
                assert results.readable_output == expected_results
                assert results.indicator.dbot_score.score == 0
            else:
                assert results.outputs == expected_results
                assert results.indicator.dbot_score.score == 3


def test_gti_comments_command(mocker, requests_mock):
    """
    Given:
    - A valid IoC

    When:
    - Running the !gti-comments-get command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import get_comments_command, encode_url_to_base64, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': [{
            'attributes': {
                'date': 0,
                'text': 'Hello',
                'votes': {
                    'positive': 10,
                    'negative': 5,
                    'abuse': 1,
                }
            }
        }]
    }

    for resource, resource_type, endpoint in [
        ('0000000000000000000000000000000000000000000000000000000000000000', 'file', 'files'),
        ('8.8.8.8', 'ip', 'ip_addresses'),
        ('www.example.com', 'domain', 'domains'),
        ('https://www.example.com', 'url', 'urls'),
    ]:
        mocker.patch.object(demisto, 'args', return_value={
            'resource': resource,
            'resource_type': resource_type,
            'limit': 10,
        })

        endpoint_resource = encode_url_to_base64(resource) if resource_type == 'url' else resource
        requests_mock.get(f'https://www.virustotal.com/api/v3/{endpoint}/{endpoint_resource}/comments',
                          json=mock_response)

        results = get_comments_command(client=client, args=demisto.args())

        assert results.execution_metrics is None
        assert results.outputs == {'indicator': resource, 'comments': mock_response['data']}


def test_gti_add_comments_command(mocker, requests_mock):
    """
    Given:
    - A valid IoC and comment

    When:
    - Running the !gti-comments-add command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import add_comments_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': {
            'attributes': {
                'date': 0,
                'text': 'Hello',
                'votes': {
                    'positive': 10,
                    'negative': 5,
                    'abuse': 1,
                }
            }
        }
    }

    for resource, resource_type, endpoint in [
        ('0000000000000000000000000000000000000000000000000000000000000000', 'file', 'files'),
        ('8.8.8.8', 'ip', 'ip_addresses'),
        ('www.example.com', 'domain', 'domains'),
        ('https://www.example.com', 'url', 'urls'),
    ]:
        mocker.patch.object(demisto, 'args', return_value={
            'resource': resource,
            'resource_type': resource_type,
            'comment': 'Hello',
        })

        endpoint_resource = encode_url_to_base64(resource) if resource_type == 'url' else resource
        requests_mock.post(f'https://www.virustotal.com/api/v3/{endpoint}/{endpoint_resource}/comments',
                           json=mock_response)

        results = add_comments_command(client=client, args=demisto.args())

        assert results.execution_metrics is None
        assert results.outputs == mock_response['data']


def test_gti_comments_by_id_command(mocker, requests_mock):
    """
    Given:
    - A valid IoC

    When:
    - Running the !gti-comments-get-by-id command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import get_comments_by_id_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': {
            'attributes': {
                'date': 0,
                'text': 'Hello',
                'votes': {
                    'positive': 10,
                    'negative': 5,
                    'abuse': 1,
                }
            }
        }
    }

    mocker.patch.object(demisto, 'args', return_value={'id': 'random_id'})
    requests_mock.get('https://www.virustotal.com/api/v3/comments/random_id',
                      json=mock_response)

    results = get_comments_by_id_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == mock_response['data']


def test_gti_passive_dns(mocker, requests_mock):
    """
    Given:
    - A valid IP address (8.8.8.8)

    When:
    - Running the !gti-passive-dns-data command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import passive_dns_data, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = util_load_json('test_data/passive_dns_ip.json')
    expected_response = util_load_json('test_data/passive_dns_ip_results.json')

    mocker.patch.object(demisto, 'args', return_value={'id': '8.8.8.8', 'limit': 10})
    requests_mock.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8/resolutions?limit=10',
                      json=mock_response)

    results = passive_dns_data(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == expected_response


def test_gti_analysis_get(mocker, requests_mock):
    """
    Given:
    - A valid analysis ID

    When:
    - Running the !gti-analysis-get command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import get_analysis_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': {
            'attributes': {
                'status': 'completed',
            }
        }
    }

    mocker.patch.object(demisto, 'args', return_value={'id': 'random_id'})
    requests_mock.get('https://www.virustotal.com/api/v3/analyses/random_id',
                      json=mock_response)

    results = get_analysis_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == {'id': 'random_id', **mock_response}


def test_pending_gti_private_analysis_get(mocker, requests_mock):
    """
    Given:
    - A valid analysis ID

    When:
    - Running the !gti-privatescanning-analysis-get command (pending)

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import private_get_analysis_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': {
            'attributes': {
                'status': 'pending',
            }
        }
    }
    expected_response = mock_response.copy()
    expected_response['id'] = 'random_id'

    mocker.patch.object(demisto, 'args', return_value={'id': 'random_id'})
    requests_mock.get('https://www.virustotal.com/api/v3/private/analyses/random_id',
                      json=mock_response)

    results = private_get_analysis_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == expected_response


def test_completed_gti_private_analysis_get(mocker, requests_mock):
    """
    Given:
    - A valid analysis ID

    When:
    - Running the !gti-privatescanning-analysis-get command (completed)

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import private_get_analysis_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_analysis_response = {
        'data': {
            'attributes': {
                'status': 'completed',
            }
        }
    }
    mock_item_response = {
        'data': {
            'attributes': {
                # File attributes
                'sha256': 'random_sha256',
                'threat_severity': {
                    'threat_severity_level': 'SEVERITY_LOW',
                    'threat_severity_data': {
                        'popular_threat_category': 'random_category',
                    },
                },
                'threat_verdict': 'VERDICT_UNDETECTED',
                # URL attributes
                'url': 'random_url',
                'title': 'random_title',
                'last_http_response_content_sha256': 'random_content_sha256',
                'last_analysis_stats': {
                    'malicious': 1,
                    'undetected': 4,
                }
            }
        }
    }
    expected_response = mock_analysis_response.copy()
    expected_response['id'] = 'random_id'
    expected_response['data']['attributes'].update({
        'sha256': 'random_sha256',
        'threat_severity_level': 'LOW',
        'popular_threat_category': 'random_category',
        'threat_verdict': 'UNDETECTED',
        'url': 'random_url',
        'title': 'random_title',
        'last_http_response_content_sha256': 'random_content_sha256',
        'positives': '1/5',
    })

    mocker.patch.object(demisto, 'args', return_value={'id': 'random_id'})
    requests_mock.get('https://www.virustotal.com/api/v3/private/analyses/random_id',
                      json=mock_analysis_response)
    requests_mock.get('https://www.virustotal.com/api/v3/private/analyses/random_id/item',
                      json=mock_item_response)

    results = private_get_analysis_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == expected_response


def test_url_scan_command(mocker, requests_mock):
    """
    Given:
    - A valid URL

    When:
    - Running the !url-scan command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import scan_url_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    url = 'https://www.example.com'
    mock_response = {
        'data': {
            'id': 'random_id',
            'url': url,
        }
    }

    mocker.patch.object(demisto, 'args', return_value={'url': url})
    requests_mock.post('https://www.virustotal.com/api/v3/urls',
                       json=mock_response)

    results = scan_url_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == {
        'GoogleThreatIntelligence.Submission(val.id && val.id === obj.id)': mock_response['data'],
        'vtScanID': 'random_id',
    }


def test_private_url_scan_command(mocker, requests_mock):
    """
    Given:
    - A valid URL

    When:
    - Running the !gti-privatescanning-url-scan command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import private_scan_url_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    url = 'https://www.example.com'
    mock_response = {
        'data': {
            'id': 'random_id',
            'url': url,
        }
    }

    mocker.patch.object(demisto, 'args', return_value={'url': url})
    requests_mock.post('https://www.virustotal.com/api/v3/private/urls',
                       json=mock_response)

    results = private_scan_url_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == {
        'GoogleThreatIntelligence.Submission(val.id && val.id === obj.id)': mock_response['data'],
        'vtScanID': 'random_id',
    }


def test_file_sigma_analysis_command(mocker, requests_mock):
    """
    Given:
    - A valid file hash

    When:
    - Running the !gti-file-sigma-analysis command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from GoogleThreatIntelligence import file_sigma_analysis_command, Client
    import CommonServerPython

    file_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    params = demisto.params()
    client = Client(params=params)

    mock_response = util_load_json('test_data/file.json')
    expected_results = util_load_json('test_data/file_extended_results.json')
    requests_mock.get(f'https://www.virustotal.com/api/v3/files/{file_hash}?relationships=',
                      json=mock_response)

    for only_stats in [True, False]:
        mocker.patch.object(demisto, 'args', return_value={'file': file_hash, 'only_stats': only_stats})

        results = file_sigma_analysis_command(client=client, args=demisto.args())

        assert results.execution_metrics is None
        assert results.outputs == expected_results


def test_search_command(mocker, requests_mock):
    """
    Given:
    - A valid query

    When:
    - Running the !gti-search command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import search_command, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': [{
            'id': 'random_id',
            'attributes': {},
        }]
    }

    mocker.patch.object(demisto, 'args', return_value={'query': 'random', 'limit': 2})
    requests_mock.get('https://www.virustotal.com/api/v3/search?query=random&limit=2',
                      json=mock_response)

    results = search_command(client=client, args=demisto.args())

    assert results.execution_metrics is None
    assert results.outputs == mock_response['data']


def test_get_upload_url(mocker, requests_mock):
    """
    Given:
    - A valid query

    When:
    - Running the !gti-file-scan-upload-url command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import get_upload_url, Client
    import CommonServerPython

    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)
    params = demisto.params()
    client = Client(params=params)

    mock_response = {
        'data': 'https://www.upload_url.com',
    }

    requests_mock.get('https://www.virustotal.com/api/v3/files/upload_url',
                      json=mock_response)

    results = get_upload_url(client=client)

    assert results.execution_metrics is None
    assert results.outputs == {
        'GoogleThreatIntelligence.FileUploadURL': 'https://www.upload_url.com',
        'vtUploadURL': 'https://www.upload_url.com',
    }


def test_gti_curated_collections_commands(mocker, requests_mock):
    """
    Given:
    - A valid IoC

    When:
    - Running the !gti-curated-campaigns-get command
    - Running the !gti-curated-malware-families-get command
    - Running the !gti-curated-threat-actors-get command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligence import (
        get_curated_campaigns_command,
        get_curated_malware_families_command,
        get_curated_threat_actors_command,
        Client
    )
    import CommonServerPython

    data_json = {
        'data': [
            {
                'id': 'collection-1',
                'attributes': {
                    'name': 'Name 1',
                    'description': 'Description 1',
                    'last_modification_date': 1718719985,
                    'targeted_regions': ['UK', 'FR'],
                    'targeted_industries': ['Industry 1', 'Industry 2'],
                }
            },
            {
                'id': 'collection-2',
                'attributes': {
                    'name': 'Name 2',
                    'description': 'Description 2',
                    'last_modification_date': 1718720000,
                    'targeted_regions': ['FR'],
                    'targeted_industries': [],
                }
            }
        ],
    }

    for func, collection_type in [
        (get_curated_campaigns_command, 'campaign'),
        (get_curated_malware_families_command, 'malware-family'),
        (get_curated_threat_actors_command, 'threat-actor'),
    ]:
        for resource, resource_type, endpoint in [
            ('0000000000000000000000000000000000000000000000000000000000000000', 'file', 'files'),
            ('8.8.8.8', 'ip', 'ip_addresses'),
            ('www.example.com', 'domain', 'domains'),
            ('https://www.example.com', 'url', 'urls'),
        ]:
            mocker.patch.object(demisto, 'args', return_value={'resource': resource, 'resource_type': resource_type})
            mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
            mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

            # Assign arguments
            params = demisto.params()
            client = Client(params=params)

            # Load assertions and mocked request data
            endpoint_resource = encode_url_to_base64(resource) if resource_type == 'url' else resource
            filter_query = 'owner%3AMandiant%20'
            if collection_type == 'malware-family':
                filter_query += '%28collection_type%3Amalware-family%20OR%20collection_type%3Asoftware-tookit%29'
            else:
                filter_query += f'collection_type%3A{collection_type}'
            requests_mock.get(f'https://www.virustotal.com/api/v3/{endpoint}/{endpoint_resource}/collections'
                              f'?filter={filter_query}', json=data_json)

            # Run command and collect result array
            results = func(client=client, args=demisto.args())

            assert results.execution_metrics is None
            assert results.outputs == {
                'id': resource,
                'collections': data_json['data'],
            }

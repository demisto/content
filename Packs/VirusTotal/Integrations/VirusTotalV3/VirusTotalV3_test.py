import json

import pytest
from VirusTotalV3 import (ScoreCalculator, encode_to_base64,
                          encode_url_to_base64, epoch_to_timestamp,
                          get_working_id, raise_if_hash_not_valid,
                          raise_if_ip_not_valid, create_relationships, get_whois)

from CommonServerPython import argToList, DemistoException
import demistomock as demisto

INTEGRATION_NAME = 'VirusTotal'


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
                'relationship_suspicious_threshold': 0
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

    def test_encode_to_base64(self):
        assert encode_to_base64('c59bffd0571b8c341c7b4be63bf0e3cd',
                                1613568775) == 'YzU5YmZmZDA1NzFiOGMzNDFjN2I0YmU2M2JmMGUzY2Q6MTYxMzU2ODc3NQ=='

    def test_get_working_id(self):
        assert get_working_id('314huoh432ou', '') == '314huoh432ou'

    def test_get_working_id_no_entry(self):
        with pytest.raises(DemistoException):
            assert get_working_id('1451', '')


def test_create_relationships():
    """
    Given:
    - The IP response from the api.

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
    - Whois string returned is a reserved Whois string returned by VirusTotal services.

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
    'is_premium_api': 'false',
    'feedReliability': 'A - Completely reliable',
    'insecure': 'false',
    'proxy': 'false'
}


def test_domain_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing domain (testing.com)

    When:
    - Running the !domain command

    Then:
    - Validate the command results are valid and contains metric data
    """
    from VirusTotalV3 import domain_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'domain': 'testing.com', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    domain_relationships = (','.join(argToList(params.get('domain_relationships')))).replace('* ', '').replace(" ", "_")
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


def test_not_found_domain_command(mocker, requests_mock):
    """
    Given:
    - A not found domain (testing.com)

    When:
    - Running the !domain command

    Then:
    - Display "Not found" message to user
    """
    from VirusTotalV3 import domain_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'domain': 'testing.com', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    domain_relationships = (','.join(argToList(params.get('domain_relationships')))).replace('* ', '').replace(" ", "_")
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/domains/testing.com?relationships={domain_relationships}',
                      json=mock_response)

    results = domain_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=domain_relationships)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == 'Domain "testing.com" was not found in VirusTotal.'
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
    from VirusTotalV3 import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(" ", "_")
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


def test_ip_command_private_ip_lookup(mocker):
    """
    Given:
    - A valid (and private) ip (192.168.0.1) and enabling private ip lookup

    When:
    - Running the !ip command

    Then:
    - Display "Reputation lookups disabled" message to user
    """
    from VirusTotalV3 import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(" ", "_")
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


def test_ip_command_override_private_lookup(mocker, requests_mock):
    """
    Given:
    - A valid (and private) ip (192.168.0.1) and enabling private ip lookup

    When:
    - Running the !ip command

    Then:
    - Display "Reputation lookups disabled" message to user
    """
    from VirusTotalV3 import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false',
                                                       'override_private_lookup': 'true'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(" ", "_")
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


def test_not_found_ip_command(mocker, requests_mock):
    """
    Given:
    - A not found ip (192.168.0.1)

    When:
    - Running the !ip command

    Then:
    - Display "Not found" message to user
    """
    from VirusTotalV3 import ip_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'ip': '192.168.0.1', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    ip_relationships = (','.join(argToList(params.get('ip_relationships')))).replace('* ', '').replace(" ", "_")
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/ip_addresses/192.168.0.1?relationships={ip_relationships}',
                      json=mock_response)

    results = ip_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=ip_relationships,
        disable_private_ip_lookup=False)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == 'IP "192.168.0.1" was not found in VirusTotal.'
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
    from VirusTotalV3 import url_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'url': 'https://vt_is_awesome.com/uts', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    testing_url = 'https://vt_is_awesome.com/uts'
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    url_relationships = (','.join(argToList(params.get('url_relationships')))).replace('* ', '').replace(" ", "_")
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


def test_not_found_url_command(mocker, requests_mock):
    """
    Given:
    - A not found url (https://vt_is_awesome.com/uts)

    When:
    - Running the !url command

    Then:
    - Display "Not found" message to user
    """
    from VirusTotalV3 import url_command, ScoreCalculator, Client
    import CommonServerPython
    # Setup Mocks
    mocker.patch.object(demisto, 'args', return_value={'url': 'https://vt_is_awesome.com/uts', 'extended_data': 'false'})
    mocker.patch.object(demisto, 'params', return_value=DEFAULT_PARAMS)
    mocker.patch.object(CommonServerPython, 'is_demisto_version_ge', return_value=True)

    # Assign arguments
    testing_url = 'https://vt_is_awesome.com/uts'
    params = demisto.params()
    mocked_score_calculator = ScoreCalculator(params=params)
    url_relationships = (','.join(argToList(params.get('url_relationships')))).replace('* ', '').replace(" ", "_")
    client = Client(params=params)

    mock_response = {'error': {'code': 'NotFoundError'}}
    requests_mock.get(f'https://www.virustotal.com/api/v3/urls/{encode_url_to_base64(testing_url)}'
                      f'?relationships={url_relationships}', json=mock_response)

    results = url_command(
        client=client, score_calculator=mocked_score_calculator,
        args=demisto.args(), relationships=url_relationships)

    assert results[0].execution_metrics is None
    assert results[0].readable_output == f'URL "{testing_url}" was not found in VirusTotal.'
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
    from VirusTotalV3 import private_file_command, Client
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
    from VirusTotalV3 import private_file_command, Client
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
    assert results[0].readable_output == f'File "{sha256}" was not found in VirusTotal.'
    assert results[0].indicator.dbot_score.score == 0


def test_private_url_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing private URL
    When:
    - Running the !vt-privatescanning-url command
    Then:
    - Validate the command results are valid and contains metric data
    """
    from VirusTotalV3 import private_url_command, Client
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
    - A valid Testing private URL
    When:
    - Running the !vt-privatescanning-url command
    Then:
    - Display "Not found" message to user
    """
    from VirusTotalV3 import private_url_command, Client
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
    assert results[0].readable_output == f'URL "{url}" was not found in VirusTotal.'
    assert results[0].indicator.dbot_score.score == 0


def test_private_url_scan_command(mocker, requests_mock):
    """
    Given:
    - A valid URL
    When:
    - Running the !vt-privatescanning-url-scan command
    Then:
    - Validate the command results are valid
    """
    from VirusTotalV3 import private_scan_url_command, Client
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
        'VirusTotal.Submission(val.id && val.id === obj.id)': mock_response['data'],
        'vtScanID': 'random_id',
    }


def test_not_found_file_sandbox_report_command(mocker, requests_mock):
    """
    Given:
    - A valid Testing hash

    When:
    - Running the !vt-file-sandbox-report command

    Then:
    - Display "Not found" message to user
    """
    from VirusTotalV3 import file_sandbox_report_command, Client
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
    assert results[0].readable_output == f'File "{sha256}" was not found in VirusTotal.'

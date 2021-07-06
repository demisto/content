import json
from typing import Dict

import pytest
from VirusTotalV3 import (ScoreCalculator, encode_to_base64,
                          encode_url_to_base64, epoch_to_timestamp,
                          get_working_id, raise_if_hash_not_valid,
                          raise_if_ip_not_valid, create_relationships)

from CommonServerPython import DemistoException


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
                'crowdsourced_yara_rules_enabled': True,
                'yaraRulesThreshold': 1,
                'SigmaIDSThreshold': 1,
                'domain_popularity_ranking': 1,
                'relationship_threshold': 1
            }
        )

    def test_there_are_logs(self):
        with open('./TestData/file.json') as f:
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
        ({'vendor1': {'rank': 10000}}, True),
        ({'vendor1': {'rank': 3000}, 'vendor2': {'rank': 7000}}, True),
        ({'vendor1': {'rank': 0}}, False),
        ({'vendor1': {'rank': 300}, 'vendor2': {'rank': 300}}, False),
        ({}, None)
    ])
    def test_is_good_by_popularity_ranks(self, ranks: Dict[str, dict], result: bool):
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
    with open('./TestData/relationships.json') as f:
        relationships = create_relationships(entity_a='Test', entity_a_type='IP',
                                            relationships_response=json.load(f),
                                            reliability='B - Usually reliable')
    relation_entry = [relation.to_entry() for relation in relationships]

    for relation, expected_relation_name in zip(relation_entry, expected_name):
        assert relation.get('name') == expected_relation_name
        assert relation.get('entityA') == 'Test'
        assert relation.get('entityBType') == 'File'

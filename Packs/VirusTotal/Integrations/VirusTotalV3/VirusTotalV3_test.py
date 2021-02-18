import json
from unittest.mock import patch

import pytest

from VirusTotalV3 import remove_links, encode_url_to_base64, raise_if_hash_not_valid, \
    raise_if_ip_not_valid, bang_domain, Client, bang_file, ScoreCalculator


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
                'domain_popularity_ranking': 1
            }
        )

    def test_file(self):
        self.score_calculator.file_score('given hash', json.load(open('./TestData/file.json')))
        print('\n'.join(self.score_calculator.logs))


class TestReputation:
    @patch.object(Client, 'domain')
    def test_domain(self, client):
        client.domain = lambda item: json.load(open('./TestData/domain.json'))
        bang_domain(client, args={'domain': 'domain'})

    @patch.object(Client, 'file')
    def test_file(self, client):
        client.file = lambda item: json.load(open('./TestData/file.json'))
        bang_file(client, args={'file': 'a1b6400a21ddee090e93d8882ffa629963132785bfa41b0abbea199d278121e9'})


class TestHelpers:
    @pytest.mark.parametrize('lists_with_links', (
            [],
            [{'links': 'a link'}],
            [{'links': 'a link'}, {'links': 'a link'}]
    ))
    def test_remove_links(self, lists_with_links):
        assert not any('links' in item for item in remove_links(lists_with_links))

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

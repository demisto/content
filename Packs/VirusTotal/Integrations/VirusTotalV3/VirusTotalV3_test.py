import json

import pytest

from VirusTotalV3 import encode_url_to_base64, raise_if_hash_not_valid, \
    raise_if_ip_not_valid, ScoreCalculator, epoch_to_timestamp


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
                'relashionship_threshold': 1
            }
        )

    def test_file(self, capfd):
        with capfd.disabled():
            self.score_calculator.file_score('given hash', json.load(open('./TestData/file.json')))
            print('\n'.join(self.score_calculator.logs))


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

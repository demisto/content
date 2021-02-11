import pytest

from VirusTotalV3 import ScoreCalculator, remove_links, encode_url_to_base64, raise_if_hash_not_valid, \
    raise_if_ip_not_valid


class TestScoreCalculator:
    """Tests the ScoreCalculator class"""

    def test_(self):
        pass


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

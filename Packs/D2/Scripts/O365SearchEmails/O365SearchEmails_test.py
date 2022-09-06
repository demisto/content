import pytest

from Packs.D2.Scripts.O365SearchEmails.O365SearchEmails import get_search_results_from_entry


@pytest.mark.parametrize('contents, expected', [
    ('Search results: {Hello}', {'Type': 1, 'ContentsFormat': 'text', 'Contents': 'Hello'}),
    ('No match', None)])
def test_get_search_results_from_entry(contents, expected):
    assert expected == get_search_results_from_entry({'Contents' : contents})
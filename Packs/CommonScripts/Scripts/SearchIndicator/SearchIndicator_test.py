import demistomock as demisto
from SearchIndicator import search_indicators


def test_main(mocker):
    mocker.patch.object(demisto, 'results', return_value={})
    mocker.patch.object(demisto, 'executeCommand',
                        return_value=[{'Contents': [{'CustomFields': {'field': 'score'}}]}])
    assert search_indicators({'add_fields_to_context': 'a,b,c'}) == (
    '### Indicators Found\n|id|indicator_type|value|score|a|b|c|verdict|\n|---|---|---|---|---|---|---|---|\n| n/a | n/a | n/a | n/a | n/a | n/a | n/a | None |\n',  # noqa
    [{'id': 'n/a', 'indicator_type': 'n/a', 'value': 'n/a', 'score': 'n/a', 'a': 'n/a', 'b': 'n/a', 'c': 'n/a',  # noqa
      'verdict': 'None'}])

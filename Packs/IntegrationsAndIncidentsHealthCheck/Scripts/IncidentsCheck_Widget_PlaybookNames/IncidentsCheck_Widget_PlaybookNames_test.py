import pytest
import demistomock as demisto
from IncidentsCheck_Widget_PlaybookNames import main, random


@pytest.mark.parametrize('list_, expected', [
    ([{'Contents': 'AutoFocusPolling,Account Enrichment - Generic v2.1'}],
     ('[{"data": [1], "name": "AutoFocusPolling", "color": "#3e8"}, {"data": [1], '
      '"name": "Account Enrichment - Generic v2.1", "color": "#3e8"}]')),
    ([{'Contents': ''}], '[{"data": [0], "name": "N\\\\A", "color": "#00CD33"}]'),
    ([{}], '[{"data": [0], "name": "N\\\\A", "color": "#00CD33"}]'),
])
def test_script(mocker, list_, expected):
    mocker.patch.object(random, 'randint', return_value=1000)
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected

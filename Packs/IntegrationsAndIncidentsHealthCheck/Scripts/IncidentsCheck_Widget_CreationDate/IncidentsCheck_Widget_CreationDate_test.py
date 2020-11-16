import pytest
import demistomock as demisto
from IncidentsCheck_Widget_CreationDate import main, random


@pytest.mark.parametrize('list_, expected', [
    ([{
        'Contents': '2020-09-29 16:48:30.261438285Z,2020-09-29 14:02:45.82647067Z,2020-09-29 14:02:45.82647067Z,'
                    '2020-09-30 15:44:06.930751906Z'}],
     ('[{"data": [3], "name": "2020-09-29", "color": "#3e8"}, {"data": [1], "name": "2020-09-30", "color": "#3e8"}]')),
    ([{'Contents': ''}], '[{"data": [0], "name": "2020-01-01", "color": "#00CD33"}]'),
    ([{}], '[{"data": [0], "name": "2020-01-01", "color": "#00CD33"}]'),
])
def test_script(mocker, list_, expected):
    mocker.patch.object(random, 'randint', return_value=1000)
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected

import pytest
import demistomock as demisto
from IncidentsCheck_Widget_NumberFailingIncidents import main


@pytest.mark.parametrize('list_, expected', [
    ([{'Contents': '7,3,3,48'}], 4),
    ([{'Contents': ''}], 0),
    ([{}], 0)
])
def test_script(mocker, list_, expected):
    mocker.patch.object(demisto, 'executeCommand', return_value=list_)
    mocker.patch.object(demisto, 'results')

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected

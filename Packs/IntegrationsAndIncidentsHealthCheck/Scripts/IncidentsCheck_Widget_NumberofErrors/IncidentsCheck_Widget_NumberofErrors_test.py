import pytest
import demistomock as demisto
from IncidentsCheck_Widget_NumberofErrors import main


@pytest.mark.parametrize(
    "list_, expected", [([{"Contents": "4@7,5@7,44@3,45@3,46@3,47@3,85@48,86@48"}], 8), ([{"Contents": ""}], 0), ([{}], 0)]
)
def test_script(mocker, list_, expected):
    mocker.patch.object(demisto, "executeCommand", return_value=list_)
    mocker.patch.object(demisto, "results")

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected

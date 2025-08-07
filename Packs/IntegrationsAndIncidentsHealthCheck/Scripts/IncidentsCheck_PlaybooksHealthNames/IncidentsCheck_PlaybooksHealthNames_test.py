import pytest
import demistomock as demisto
from IncidentsCheck_PlaybooksHealthNames import main, random
from test_data.constants import (
    INCIDENT_RESULT,
    INCIDENT_RESULT_NO_FAILED_COMMANDS,
    INCIDENT_RESULT_EXPECTED,
    INCIDENT_RESULT_NO_FAILED_COMMANDS_EXPECTED,
)


@pytest.mark.parametrize(
    "incidents_result, expected",
    [
        (INCIDENT_RESULT, INCIDENT_RESULT_EXPECTED),
        (INCIDENT_RESULT_NO_FAILED_COMMANDS, INCIDENT_RESULT_NO_FAILED_COMMANDS_EXPECTED),
    ],
)
def test_script(mocker, incidents_result, expected):
    mocker.patch.object(random, "randint", return_value=1000)
    mocker.patch.object(demisto, "incidents", return_value=incidents_result)
    mocker.patch.object(demisto, "results")

    main()

    contents = demisto.results.call_args[0][0].get("Contents")
    assert contents == expected

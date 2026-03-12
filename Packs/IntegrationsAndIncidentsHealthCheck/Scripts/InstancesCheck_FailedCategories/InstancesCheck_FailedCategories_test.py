import pytest
import demistomock as demisto
from InstancesCheck_FailedCategories import main, random
from test_data.constants import (
    INCIDENTS_RESULTS,
    INCIDENTS_RESULTS_EXPECTED,
    INCIDENTS_RESULTS_NO_FAILED,
    INCIDENTS_RESULTS_NO_FAILED_EXPECTED,
)


@pytest.mark.parametrize(
    "list_, expected",
    [(INCIDENTS_RESULTS, INCIDENTS_RESULTS_EXPECTED), (INCIDENTS_RESULTS_NO_FAILED, INCIDENTS_RESULTS_NO_FAILED_EXPECTED)],
)
def test_script(mocker, list_, expected):
    mocker.patch.object(random, "randint", return_value=1000)
    mocker.patch.object(demisto, "incidents", return_value=list_)
    mocker.patch.object(demisto, "results")

    main()

    contents = demisto.results.call_args[0][0]
    assert contents == expected

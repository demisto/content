import pytest
import demistomock as demisto
import TimeStampToDateV2
from TimeStampToDateV2 import main


@pytest.mark.parametrize(
    "date,format,expected_result", [
        (1585657181, "%Y-%m-%dT%H:%M:%S.%f%z", '2020-03-31T12:19:41.000000+0000'),
        (1585657181, "%Y-%m-%dT%H:%M:%S%z", '2020-03-31T12:19:41+0000'),
        (1585657181, None, '2020-03-31T12:19:41+00:00'),
    ])
def test_epoch_to_date(mocker, date, format, expected_result):
    """
    Test happy_path
    """
    mocker.patch.object(demisto, 'args', return_value={'value': date, 'format': format})
    mocker.patch.object(TimeStampToDateV2, 'return_results')

    main()

    command_results = TimeStampToDateV2.return_results.call_args[0][0]
    assert command_results.outputs == expected_result


def test_wrong_epoch_value(mocker):
    """
    Given - wrong value for timestamp
    When - trying to convert to the date
    Then - validate the return_error was called
    """
    mocker.patch.object(demisto, 'args', return_value={'value': 'wrong_val', 'format': "%Y-%m-%dT%H:%M:%S%z"})
    mocker.patch.object(TimeStampToDateV2, 'return_error')

    main()

    error_results = TimeStampToDateV2.return_error.call_args[0][0]
    assert 'Failed to execute TimeStampToDateV2' in error_results

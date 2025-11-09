import pytest
import demistomock as demisto
from BeforeRelativeDate import check_date, main

TEST_INPUTS = [
    ("2025-09-12T12:00:00", "1 day ago", True, "Before date - No TZ"),
    ("2025-09-12T12:00:00", "19 years ago", False, "Not before date - No TZ"),
    ("1999-09-12T12:00:00z", "19 years ago", True, "Before date - Zulu"),
    ("2100-09-12T12:00:00", "19 years ago", False, "Not before - No TZ"),
]


@pytest.mark.parametrize("left, right, expected_result, test_title", TEST_INPUTS)
def test_check_date(left, right, expected_result, test_title):
    assert check_date(left, right) == expected_result, test_title


def test_results(mocker):
    import BeforeRelativeDate

    mocker.patch.object(demisto, "args", return_value={"left": "2025-09-12T12:00:00", "right": "1 day ago"})
    mocker.patch("BeforeRelativeDate.check_date", return_value=True)
    mocker.patch.object(BeforeRelativeDate, "return_results")
    main()

    call = BeforeRelativeDate.return_results.call_args_list
    command_results = call[0].args[0]

    assert command_results.outputs


def test_error_results(mocker):
    import BeforeRelativeDate

    mocker.patch.object(demisto, "args", return_value={"value": "", "right": "1 day ago"})
    mocker.patch("BeforeRelativeDate.check_date", return_value=True)
    mocker.patch.object(BeforeRelativeDate, "return_error")
    main()
    call = BeforeRelativeDate.return_error.call_args_list
    command_results = call[0]

    assert "Error Occured" in command_results.kwargs["message"]
    assert "A required input is missing or malformed." in command_results.kwargs["error"]

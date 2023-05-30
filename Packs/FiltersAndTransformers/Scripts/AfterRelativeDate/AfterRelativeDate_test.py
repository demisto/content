from AfterRelativeDate import main
import demistomock as demisto


def test_date_match(mocker):
    """
    Given a date and relative date, when the date is sooner than the specified date, return bool true.
    """

    args_value = {
        "left": "2020-10-12T22:17:17",
        "right": "30 years ago"
    }
    mocker.patch.object(demisto, "args", return_value=args_value)
    mocker.patch.object(demisto, "results")
    main()

    demisto.results.assert_called_with(True)


def test_date_match_non_iso(mocker):
    """
    Given a date in NON-ISO compatible format, and relative date, when the date is sooner than the specified date,
    return bool true.
    """
    args_value = {
        "left": "2020-10-12",
        "right": "30 years ago"
    }
    mocker.patch.object(demisto, "args", return_value=args_value)
    mocker.patch.object(demisto, "results")
    main()

    demisto.results.assert_called_with(True)


def test_date_no_match(mocker):
    """
    Given a date and relative date, when the date is older than the relative date, return false.
    """
    args_value = {
        "left": "2000-01-01T00:00:00",
        "right": "1 day ago"
    }
    mocker.patch.object(demisto, "args", return_value=args_value)
    mocker.patch.object(demisto, "results")
    main()

    demisto.results.assert_called_with(False)

from RelativeDateCheck import main
import demistomock as demisto


def test_date_match(mocker):
    # Check that the passed date is earlier than the relative
    # Yes, if this code is around in 30 years time the date will need updating or it'll assert incorrectly.
    args_value = {
        "left": "2020-10-12T22:17:17",
        "right": "30 years ago"
    }
    mocker.patch.object(demisto, "args", return_value=args_value)
    mocker.patch.object(demisto, "results")
    main()

    demisto.results.assert_called_with(True)

def test_date_match_nonISO(mocker):
    # Try other date formats
    args_value = {
        "left": "2020-10-12",
        "right": "30 years ago"
    }
    mocker.patch.object(demisto, "args", return_value=args_value)
    mocker.patch.object(demisto, "results")
    main()

    demisto.results.assert_called_with(True)


def test_date_no_match(mocker):
    # Check that the passed date is later than the relative
    args_value = {
        "left": "2000-01-01T00:00:00",
        "right": "1 day ago"
    }
    mocker.patch.object(demisto, "args", return_value=args_value)
    mocker.patch.object(demisto, "results")
    main()

    demisto.results.assert_called_with(False)

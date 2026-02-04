from CommonServerPython import *  # noqa: F401
from DataminrPulseCVSSColor import main, demisto


def test_main_with_valid_cvss_score_data(mocker):
    """
    Test the main function with valid cvss score.
    """

    context = {
        "args": {"indicator": {"CustomFields": {"cvssscore": "7.1"}}},
    }

    mocker.patch.object(demisto, "callingContext", context)

    mock_return = mocker.patch("DataminrPulseCVSSColor.return_results")

    main()

    assert mock_return.call_args.args[0].readable_output == "# <-:->{{color:#E1211E}}(**7.1**)"


def test_main_with_no_cvss_score_data(mocker):
    """
    Test the main function with no cvss score data.
    """
    context: dict = {
        "args": {"indicator": {"CustomFields": {}}},
    }

    mocker.patch.object(demisto, "callingContext", context)

    mock_return = mocker.patch("DataminrPulseCVSSColor.return_results")

    main()

    assert mock_return.call_args.args[0].readable_output == "# <-:->{{color:#CDCED6}}(**N/A**)"

from CommonServerPython import *  # noqa: F401
from DataminrPulseEPSSScore import main, demisto


def test_main_with_valid_eppss_score_data(mocker):
    """
    Test the main function with valid epss score.
    """

    context = {
        "args": {"indicator": {"CustomFields": {"dataminrpulseepssscore": "7.1%"}}},
    }

    mocker.patch.object(demisto, "callingContext", context)

    mock_return = mocker.patch("DataminrPulseEPSSScore.return_results")

    main()

    assert mock_return.call_args.args[0].readable_output == "# <-:->**7.1%**"


def test_main_with_no_epss_score_data(mocker):
    """
    Test the main function with no epss score data.
    """
    context = {
        "args": {"indicator": {"CustomFields": {}}},
    }

    mocker.patch.object(demisto, "callingContext", context)

    mock_return = mocker.patch("DataminrPulseEPSSScore.return_results")

    main()

    assert mock_return.call_args.args[0].readable_output == "# <-:->**N/A**"

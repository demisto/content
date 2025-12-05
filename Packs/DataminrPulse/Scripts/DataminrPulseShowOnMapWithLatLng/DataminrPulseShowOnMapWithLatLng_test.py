from CommonServerPython import *  # noqa: F401
from DataminrPulseShowOnMapWithLatLng import main, demisto


def test_main_with_valid_coordinates(mocker):
    """
    Test the main function with valid coordinates.
    """
    incident = {"CustomFields": {"dataminrpulseeventlocationcoordinates": "[1.2, 3.4]"}}
    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseShowOnMapWithLatLng.return_results")

    main()

    assert mock_return.call_args.args[0]["Type"] == entryTypes["map"]
    assert mock_return.call_args.args[0]["ContentsFormat"] == formats["json"]
    assert mock_return.call_args.args[0]["Contents"]["lat"] == 1.2
    assert mock_return.call_args.args[0]["Contents"]["lng"] == 3.4


def test_main_with_invalid_coordinates(mocker):
    """
    Test the main function with invalid coordinates.
    """
    incident = {"CustomFields": {"dataminrpulseeventlocationcoordinates": "[1.2 3.4]"}}
    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseShowOnMapWithLatLng.return_results")

    main()

    assert mock_return.call_args.args[0] == "Invalid coordinates format."


def test_main_with_no_coordinates(mocker):
    """
    Test the main function with no coordinates.
    """
    mocker.patch.object(demisto, "incident", return_value={})

    mock_return = mocker.patch("DataminrPulseShowOnMapWithLatLng.return_results")

    main()

    assert mock_return.call_args.args[0] == "No coordinates found."

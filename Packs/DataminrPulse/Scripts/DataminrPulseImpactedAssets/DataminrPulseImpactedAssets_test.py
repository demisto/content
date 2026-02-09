from CommonServerPython import *  # noqa: F401
from DataminrPulseImpactedAssets import main, demisto
import json
import os


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_txt(path):
    """Load a text file to python dictionary."""
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_main_with_valid_impacted_assets_data(mocker):
    """
    Test the main function with valid impacted assets data.
    """
    impacted_assets_data = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/impacted_assets_data.json")
    )

    incident: dict = {
        "CustomFields": {
            "dataminrpulseimpactedassetstext": json.dumps(impacted_assets_data),
            "dataminrpulseexpandalerturl": "Dummy_URL",
        }
    }

    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseImpactedAssets.return_results")

    main()

    impacted_assets_html = util_load_txt(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/expected_impacted_assets_data.txt")
    )

    expected_content = f'<div style="padding:10px; line-height:1.2; font-size:14px;">{impacted_assets_html}</div>'

    assert mock_return.call_args.args[0]["Type"] == EntryType.NOTE
    assert mock_return.call_args.args[0]["ContentsFormat"] == EntryFormat.HTML
    assert mock_return.call_args.args[0]["Contents"] == expected_content


def test_main_with_no_impacted_assets_data(mocker):
    """
    Test the main function with no impacted assets data.
    """
    incident: dict = {"CustomFields": {}}
    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseImpactedAssets.return_results")

    main()

    assert mock_return.call_args.args[0]["Type"] == EntryType.NOTE
    assert mock_return.call_args.args[0]["ContentsFormat"] == EntryFormat.HTML
    assert mock_return.call_args.args[0]["Contents"] == "<p>N/A</p>"


def test_main_with_invalid_impacted_assets_data(mocker):
    """
    Test the main function with invalid impacted assets data.
    """
    incident: dict = {
        "CustomFields": {
            "dataminrpulseimpactedassetstext": json.dumps("{"),
            "dataminrpulseexpandalerturl": "Dummy_URL",
        }
    }
    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseImpactedAssets.return_error")

    main()

    error_message = "Failed to render data: Invalid format for impacted assets data."

    assert mock_return.call_args.args[0] == error_message

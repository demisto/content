from CommonServerPython import *  # noqa: F401
from DataminrPulseIntelAgents import main, demisto, PANEL_NAME
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


def test_main_with_valid_intel_agents_data_in_light_mode(mocker):
    """
    Test the main function with valid intel agents data in light mode.
    """
    intel_agents_data = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/intel_agents_data.json")
    )

    incident: dict = {
        "CustomFields": {
            "dataminrpulseintelagentssummary": json.dumps(intel_agents_data),
            "dataminrpulseexpandalerturl": "Dummy_URL",
        }
    }
    theme = {"context": {"User": {"theme": "light"}}}

    mocker.patch.object(demisto, "incident", return_value=incident)
    mocker.patch.object(demisto, "callingContext", theme)

    mock_return = mocker.patch("DataminrPulseIntelAgents.return_results")

    main()

    intel_agents = util_load_txt(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/expected_intel_agents_data.txt")
    )

    expected_content = (
        '<div style="background:#E9FBF9; color:#000000; border:2px solid #016558; border-radius:5px; padding:10px; '
        'margin-top:10px; line-height:1.2; font-size:14px;">'
        f'<h4 style="color:#016558;">{PANEL_NAME}</h4>'  # noqa: E231,E702
        f"{intel_agents}</div>"  # type: ignore
    )

    assert mock_return.call_args.args[0]["Type"] == EntryType.NOTE
    assert mock_return.call_args.args[0]["ContentsFormat"] == EntryFormat.HTML
    assert mock_return.call_args.args[0]["Contents"] == expected_content


def test_main_with_valid_intel_agents_data_in_dark_mode(mocker):
    """
    Test the main function with valid intel agents data in dark mode.
    """
    intel_agents_data = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/intel_agents_data.json")
    )

    incident: dict = {
        "CustomFields": {
            "dataminrpulseintelagentssummary": json.dumps(intel_agents_data),
            "dataminrpulseexpandalerturl": "Dummy_URL",
        }
    }
    theme = {"context": {"User": {"theme": "dark"}}}

    mocker.patch.object(demisto, "incident", return_value=incident)
    mocker.patch.object(demisto, "callingContext", theme)

    mock_return = mocker.patch("DataminrPulseIntelAgents.return_results")

    main()

    intel_agents = util_load_txt(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/expected_intel_agents_data.txt")
    )

    expected_content = (
        '<div style="background:#082223; color:#FFFFFF; border:2px solid #53DFCD; border-radius:5px; padding:10px; '
        'margin-top:10px; line-height:1.2; font-size:14px;">'
        f'<h4 style="color:#53DFCD;">{PANEL_NAME}</h4>'  # noqa: E231,E702
        f"{intel_agents}</div>"  # type: ignore
    )

    assert mock_return.call_args.args[0]["Type"] == EntryType.NOTE
    assert mock_return.call_args.args[0]["ContentsFormat"] == EntryFormat.HTML
    assert mock_return.call_args.args[0]["Contents"] == expected_content


def test_main_with_no_intel_agents_data(mocker):
    """
    Test the main function with no intel agents data.
    """
    incident: dict = {"CustomFields": {}}
    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseIntelAgents.return_results")

    main()

    assert mock_return.call_args.args[0]["Type"] == EntryType.NOTE
    assert mock_return.call_args.args[0]["ContentsFormat"] == EntryFormat.HTML
    assert mock_return.call_args.args[0]["Contents"] == (
        f'<h4 style="margin:10px 0;">{PANEL_NAME}</h4><p>N/A</p>'  # noqa: E231,E702
    )


def test_main_with_invalid_intel_agents_data(mocker):
    """
    Test the main function with invalid intel agents data.
    """
    incident: dict = {
        "CustomFields": {
            "dataminrpulseintelagentssummary": "{",
            "dataminrpulseexpandalerturl": "Dummy_URL",
        }
    }
    mocker.patch.object(demisto, "incident", return_value=incident)

    mock_return = mocker.patch("DataminrPulseIntelAgents.return_error")

    main()

    error_message = 'Failed to render data: Failed to parse "Dataminr Pulse Intel Agents Summary" JSON string.'

    assert mock_return.call_args.args[0] == error_message

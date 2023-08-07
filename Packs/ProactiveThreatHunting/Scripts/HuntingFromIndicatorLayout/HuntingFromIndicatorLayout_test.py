from HuntingFromIndicatorLayout import hunting_from_indicator_layout  # Replace 'your_script_file' with the actual filename
from demisto_sdk.commands.common.tools import CommandResults

def test_hunting_from_indicator_layout(mocker):
    mock_execute_command.return_value = [
        {
            'Type': 1,
            'Contents': 'success',
            'ContentsFormat': 'json',
            'HumanReadable': 'Proactive Threat Hunting Incident Created: Threat Hunting Session - some_sdo_value',
            'EntryContext': {}
        }
    ]

    sdo_value = "some_sdo_value"
    expected_output = CommandResults(
        readable_output=f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo_value}"
    )

    # Call the function to be tested
    result = hunting_from_indicator_layout(sdo_value)

    # Assertions
    self.assertEqual(result, expected_output)
    mock_execute_command.assert_called_once_with(
        "createNewIncident",
        {
            "name": f"Threat Hunting Session - {sdo_value}",
            "sdoname": f"{sdo_value}",
            "type": "Proactive Threat Hunting"
        }
    )
import unittest
from unittest.mock import patch
from HuntingFromIndicatorLayout import hunting_from_indicator_layout
from demisto_sdk.commands.common.tools import CommandResults


class TestHuntingFromIndicatorLayout(unittest.TestCase):

    @patch('demisto.executeCommand')
    def test_hunting_session_creation_success(self, mock_execute_command):
        # Mock the demisto.executeCommand response
        mock_execute_command.return_value = [
            {
                'Type': 1,
                'Contents': 'success',
                'ContentsFormat': 'json',
                'HumanReadable': 'Proactive Threat Hunting Incident Created: Threat Hunting Session - sdo_value',
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

    @patch('demisto.executeCommand')
    def test_hunting_session_creation_failure(self, mock_execute_command):
        # Mock the demisto.executeCommand response when an exception occurs
        mock_execute_command.side_effect = Exception("Some error message")

        sdo_value = "some_sdo_value"

        # Call the function to be tested and expect a DemistoException to be raised
        with self.assertRaises(DemistoException) as context:
            hunting_from_indicator_layout(sdo_value)

        # Assertions
        self.assertIn("Failed to create hunting session:", str(context.exception))
        mock_execute_command.assert_called_once_with(
            "createNewIncident",
            {
                "name": f"Threat Hunting Session - {sdo_value}",
                "sdoname": f"{sdo_value}",
                "type": "Proactive Threat Hunting"
            }
        )


if __name__ == '__main__':
    unittest.main()
